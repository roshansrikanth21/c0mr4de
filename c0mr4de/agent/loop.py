"""The ReAct-style agent loop: generate -> execute any tool calls ->
feed results back -> repeat until the model stops calling tools or the
step cap is hit. Backend-agnostic - swap Ollama for Anthropic in config
and nothing here changes."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from c0mr4de import stats
from c0mr4de.agent.backends import Backend
from c0mr4de.agent.prompts import SYSTEM_PROMPT
from c0mr4de.tools.base import ToolRegistry
from c0mr4de.tools.playbook import consult_knowledge


def _trim_history(messages: list[dict], keep_full: int = 4, old_cap: int = 240) -> list[dict]:
    """Keep the request under free-tier TPM limits (Groq free = 8000 TPM) by
    shrinking the CONTENT of older messages while keeping every message in
    place - removing messages would break the assistant->tool_result pairing
    the API requires. The most recent `keep_full` messages stay untouched so
    the model still has full detail on what it's currently doing."""
    n = len(messages)
    if n <= keep_full:
        return messages
    trimmed = []
    for i, m in enumerate(messages):
        if i >= n - keep_full or not isinstance(m.get("content"), str) or len(m["content"]) <= old_cap:
            trimmed.append(m)
        else:
            shrunk = dict(m)
            shrunk["content"] = m["content"][:old_cap] + " ...[trimmed for context budget]"
            trimmed.append(shrunk)
    return trimmed


_PLAN_SIGNALS = ("```", "let's", "we will", "we should", "next step", "step 1", "i will", "import ")

# Tools that constitute actually TESTING an input (not just discovery). Concluding
# "nothing found" without any of these is the "gave up shallow" failure a live run
# exposed - crawling alone is not testing, so it must not satisfy the gate.
# verify_finding / test_all_params are the real confirm/test tools, so they count.
_EFFORT_TOOLS = ("test_injection", "test_all_params", "verify_finding", "sqlmap", "tamper_jwt",
                 "fuzz_param", "oob_poll", "nuclei_scan")
_NEGATIVE_SIGNALS = ("no vuln", "no exploitable", "no exploit", "nothing found", "no findings",
                     "not vulnerable", "no obvious", "found nothing", "no issues", "no direct impact",
                     "no sqli", "no xss", "clean", "did not reveal", "no injection")
# Claiming a vuln (positive) also needs backing by a real test/confirmation, not prose.
_VULN_CLAIM = ("vulnerable", "sql injection", "sqli", "xss", "idor", "ssrf", "rce", "exploitable",
               "injection point", "auth bypass", "open redirect")


def _is_negative_conclusion(text: str) -> bool:
    low = (text or "").lower()
    return any(sig in low for sig in _NEGATIVE_SIGNALS)


def _claims_finding(text: str) -> bool:
    """The model asserts a vuln without it being a negative statement - that claim
    must be backed by a verify_finding/test tool, not accepted on prose alone."""
    if _is_negative_conclusion(text):
        return False
    low = (text or "").lower()
    return any(s in low for s in _VULN_CLAIM)


def _looks_like_unexecuted_plan(text: str, tools_used: bool) -> bool:
    """Heuristic: did the model describe/code an action instead of calling a
    tool? True when the text reads like a plan or contains code. If no tool
    has run yet, be more eager to nudge (an all-text first turn on an action
    task is almost always narration)."""
    if not text:
        return False
    low = text.lower()
    if any(sig in low for sig in _PLAN_SIGNALS):
        return True
    # Long, action-implying text with nothing executed yet also warrants a push.
    return not tools_used and len(text) > 400


@dataclass
class StepLog:
    step: int
    assistant_text: str
    tool_calls: list[str] = field(default_factory=list)
    tool_results: list[str] = field(default_factory=list)


class AgentLoop:
    def __init__(self, backend: Backend, tools: ToolRegistry, max_steps: int = 25, verbose: bool = True,
                 on_event=None, should_stop=None, system_prompt: str | None = None, supervise: bool = True,
                 trim_tools: bool = True):
        self.backend = backend
        self.tools = tools
        self.max_steps = max_steps
        self.verbose = verbose
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        self.log: list[StepLog] = []
        # on_event(kind, data): fired for live UIs. kinds: "thought", "tool_call",
        # "tool_result", "final", "supervisor". Optional - None means no streaming.
        self.on_event = on_event or (lambda kind, data: None)
        # should_stop(): return True to cancel the run (operator hit Stop).
        self.should_stop = should_stop or (lambda: False)
        # Independent watcher (foreman-inspired): catches loop/stuck/thrash and
        # steers or stops. Conservative + capped; disable with supervise=False.
        from c0mr4de.agent.supervisor import Supervisor
        self.supervisor = Supervisor() if supervise else None
        # Send only relevant tool schemas per step (not all ~42) to stay under
        # free-tier TPM. The full registry stays executable regardless.
        self.trim_tools = trim_tools

    def run(self, task: str) -> str:
        # Auto-inject relevant playbook/vault knowledge up front rather than
        # relying on the model to remember to call consult_knowledge itself -
        # live testing showed a 7B model will happily skip that step even when
        # explicitly told to use it. This guarantees the grounding is present
        # regardless of the backend's tool-use discipline. Wrapped defensively:
        # RAG needs the local embedder (Ollama) up, but a missing embedder must
        # NOT crash the whole run - the model can still consult_knowledge later
        # if/when it comes back, and cloud-only users may not run Ollama at all.
        try:
            knowledge = consult_knowledge(task)
        except Exception as exc:  # noqa: BLE001
            knowledge = f"(knowledge base unavailable this run: {exc})"
        knowledge = knowledge[:1400]  # cap so the first turn stays under free-tier TPM limits
        from c0mr4de import scope
        roe = scope.brief()
        primed_task = (
            (f"{roe}\n\n" if roe else "")
            + f"{task}\n\n"
            f"--- Relevant knowledge auto-retrieved for this task (already consulted, no need to call "
            f"consult_knowledge again for this exact question - call it again only if you need something "
            f"more specific as you go) ---\n{knowledge}"
        )
        messages: list[dict] = [{"role": "user", "content": primed_task}]
        all_schemas = self.tools.schemas()

        def _schemas_for_step() -> list[dict]:
            if not self.trim_tools:
                return all_schemas
            from c0mr4de.agent.toolselect import select_schemas
            used = {c.split("(")[0] for s in self.log for c in s.tool_calls}
            recent = " ".join((s.assistant_text or "") for s in self.log[-2:])
            return select_schemas(self.tools, task, recent, used)

        nudges_left = 3
        tools_used = False
        wrapup_sent = False
        gate_used = False
        empty_retries = 2
        confirmed_hits: list[str] = []   # deterministic tool confirmations - ground truth, not prose

        def _effort_spent() -> bool:
            return any(any(t in c for t in _EFFORT_TOOLS) for s in self.log for c in s.tool_calls)

        for step in range(1, self.max_steps + 1):
            if self.should_stop():
                self.on_event("final", {"text": "Run stopped by operator."})
                return "Run stopped by operator."
            # Near the step cap, tell the model to wrap up and report, so a run
            # never just dies at the limit with nothing written (the m1rage run
            # hit the cap mid-recon and produced no report).
            if not wrapup_sent and step >= self.max_steps - 3:
                wrapup_sent = True
                messages.append({
                    "role": "user",
                    "content": (
                        "You are at the step limit. STOP exploring. Now write up what you have: call "
                        "write_report with every finding so far (or state plainly that you found nothing), "
                        "then give a final summary. Do not start new probes."
                    ),
                })
            _t0 = time.time()
            response = self.backend.generate(self.system_prompt, _trim_history(messages), tools=_schemas_for_step())
            _served = getattr(self.backend, "_last_used", self.backend).name
            stats.record(_served, response.usage.get("input_tokens", 0),
                         response.usage.get("output_tokens", 0), time.time() - _t0)
            step_log = StepLog(step=step, assistant_text=response.text)

            if self.verbose and response.text:
                print(f"\n[step {step}] {self.backend.name} thinks:\n{response.text}\n")
            if response.text:
                self.on_event("thought", {"step": step, "text": response.text})

            if not response.tool_calls:
                # An EMPTY reply (no text, no tool calls) is almost always a free-tier
                # rate-limit/TPM hit (Groq returns empty at the 8000 TPM ceiling), not a
                # real conclusion. Don't silently end - trim harder and retry a couple times.
                if not (response.text or "").strip():
                    if empty_retries > 0:
                        empty_retries -= 1
                        if self.verbose:
                            print("  !! empty reply (likely TPM/rate-limit) - trimming context and retrying")
                        self.on_event("supervisor", {"action": "retry", "text": "empty reply - retrying"})
                        # aggressively shrink history so the next request fits the token budget
                        messages = _trim_history(messages, keep_full=2, old_cap=120)
                        messages.append({"role": "user", "content":
                                         "Continue: call the next tool (or write_report if you have enough)."})
                        self.log.append(step_log)
                        continue
                    self.log.append(step_log)
                    msg = ("Run ended on repeated empty replies - likely the free-tier token/min ceiling. "
                           "Re-run with fewer tools, a paid/higher-TPM key, or a shorter task.")
                    self.on_event("final", {"text": msg})
                    return msg
                # Weak models often narrate a plan (or write code) instead of
                # actually calling tools, then stop. If that looks like what
                # happened, push back once rather than accepting it as done.
                if nudges_left > 0 and _looks_like_unexecuted_plan(response.text, tools_used):
                    nudges_left -= 1
                    if self.verbose:
                        print("  !! model narrated instead of acting - nudging to execute the tools")
                    messages.append({"role": "assistant", "content": response.text})
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "You described steps but did not actually call any tools - writing code "
                                "in a code block does NOT run it. Execute the plan now by calling the real "
                                "tools (decode_jwt, tamper_jwt, http_request, write_report, ...). Do not "
                                "write Python; issue the tool calls."
                            ),
                        }
                    )
                    self.log.append(step_log)
                    continue
                # Completion gate: a verdict - "nothing found" OR a vuln CLAIM - must be backed
                # by a real test/verify tool, not prose. Fires once, not near the step cap.
                if (not gate_used and not wrapup_sent and not _effort_spent()
                        and (_is_negative_conclusion(response.text) or _claims_finding(response.text))):
                    gate_used = True
                    if self.verbose:
                        print("  ~~ completion gate: concluding without a real test - pushing to verify")
                    self.on_event("supervisor", {"action": "gate", "text": "completion gate: test/verify before concluding"})
                    messages.append({"role": "assistant", "content": response.text})
                    messages.append({"role": "user", "content": (
                        "Do NOT conclude on prose - you have not run a real test. Call crawl_site to find "
                        "params, then test_injection on them, and CONFIRM anything you suspect with "
                        "verify_finding (it returns a deterministic CONFIRMED / UNCONFIRMED). State a verdict "
                        "ONLY after verify_finding has run; a claim without it does not count.")})
                    self.log.append(step_log)
                    continue
                # Reconcile prose vs evidence: the model's narration is NOT ground truth. If a tool
                # deterministically CONFIRMED something, the tool wins - a negative conclusion is
                # overridden, and a positive one is annotated with the proof so it is never lost.
                # This is the exact failure a live run exposed (model said "nothing found" while
                # verify_finding returned CONFIRMED on the same request).
                if confirmed_hits:
                    proof = "\n".join(f"- {h}" for h in confirmed_hits)
                    if _is_negative_conclusion(response.text):
                        final = ("The model concluded negatively, but tool evidence overrides narration. "
                                 "DETERMINISTICALLY CONFIRMED this run:\n" + proof)
                    else:
                        final = (response.text or "").rstrip() + "\n\nCONFIRMED (tool-verified ground truth):\n" + proof
                    self.log.append(step_log)
                    self.on_event("final", {"text": final})
                    return final
                self.log.append(step_log)
                self.on_event("final", {"text": response.text})
                return response.text

            tools_used = True

            tool_results: list[tuple] = []
            for call in response.tool_calls:
                tool = self.tools.get(call.name)
                if tool is None:
                    result = f"ERROR: unknown tool '{call.name}'"
                else:
                    if self.verbose:
                        print(f"  -> calling {call.name}({call.arguments})")
                    self.on_event("tool_call", {"name": call.name, "arguments": call.arguments})
                    result = tool.run(**call.arguments)
                    # Cap a single tool result so a big dump (e.g. crawl_site's endpoint
                    # list) can't blow the free-tier token/min budget and cause empty replies.
                    if len(result) > 2600:
                        result = result[:2600] + "\n...[truncated to protect the token budget - narrow the query or read specifics]"
                    if self.verbose:
                        preview = result if len(result) < 500 else result[:500] + "... (truncated)"
                        print(f"  <- {preview}")
                    self.on_event("tool_result", {"name": call.name, "result": result})
                    if "[CONFIRMED]" in result:   # the verifier's ground-truth marker
                        confirmed_hits.append(f"{call.name}: {result.splitlines()[0][:220]}")
                step_log.tool_calls.append(f"{call.name}({call.arguments})")
                step_log.tool_results.append(result)
                tool_results.append((call, result))

            self.log.append(step_log)
            messages.extend(self.backend.format_turn(response, tool_results))

            # Independent supervision: catch loops/stuck/thrash and steer or stop.
            if self.supervisor:
                verdict = self.supervisor.review(self.log)
                if verdict:
                    action, msg = verdict
                    if self.verbose:
                        print(f"  ~~ {msg}")
                    self.on_event("supervisor", {"action": action, "text": msg})
                    messages.append({"role": "user", "content": msg})
                    if action == "stop" and not wrapup_sent:
                        wrapup_sent = True  # its message already tells the model to report

        return (
            f"Stopped after {self.max_steps} steps without a final answer. "
            f"Raise max_steps if this task genuinely needs more, or check the log for a loop."
        )
