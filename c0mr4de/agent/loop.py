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
                 on_event=None, should_stop=None, system_prompt: str | None = None):
        self.backend = backend
        self.tools = tools
        self.max_steps = max_steps
        self.verbose = verbose
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        self.log: list[StepLog] = []
        # on_event(kind, data): fired for live UIs. kinds: "thought", "tool_call",
        # "tool_result", "final". Optional - None means no streaming.
        self.on_event = on_event or (lambda kind, data: None)
        # should_stop(): return True to cancel the run (operator hit Stop).
        self.should_stop = should_stop or (lambda: False)

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
        primed_task = (
            f"{task}\n\n"
            f"--- Relevant knowledge auto-retrieved for this task (already consulted, no need to call "
            f"consult_knowledge again for this exact question - call it again only if you need something "
            f"more specific as you go) ---\n{knowledge}"
        )
        messages: list[dict] = [{"role": "user", "content": primed_task}]
        tool_schemas = self.tools.schemas()

        nudges_left = 3
        tools_used = False
        wrapup_sent = False

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
            response = self.backend.generate(self.system_prompt, _trim_history(messages), tools=tool_schemas)
            _served = getattr(self.backend, "_last_used", self.backend).name
            stats.record(_served, response.usage.get("input_tokens", 0),
                         response.usage.get("output_tokens", 0), time.time() - _t0)
            step_log = StepLog(step=step, assistant_text=response.text)

            if self.verbose and response.text:
                print(f"\n[step {step}] {self.backend.name} thinks:\n{response.text}\n")
            if response.text:
                self.on_event("thought", {"step": step, "text": response.text})

            if not response.tool_calls:
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
                    if self.verbose:
                        preview = result if len(result) < 500 else result[:500] + "... (truncated)"
                        print(f"  <- {preview}")
                    self.on_event("tool_result", {"name": call.name, "result": result})
                step_log.tool_calls.append(f"{call.name}({call.arguments})")
                step_log.tool_results.append(result)
                tool_results.append((call, result))

            self.log.append(step_log)
            messages.extend(self.backend.format_turn(response, tool_results))

        return (
            f"Stopped after {self.max_steps} steps without a final answer. "
            f"Raise max_steps if this task genuinely needs more, or check the log for a loop."
        )
