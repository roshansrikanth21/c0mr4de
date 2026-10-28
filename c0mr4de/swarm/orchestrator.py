"""Hivemind coordinator.

Runs a phase DAG against a target: specialists WITHIN a phase run in PARALLEL
(threads), PHASES run in SEQUENCE. A thread-safe blackboard is the only shared
state - specialists never talk to each other, they read/write typed, de-duplicated
entries. The flow is: recon (runtime + source, parallel) -> exploit (one specialist
per vuln class, parallel) -> VALIDATE (the deterministic verifier is the gate) ->
report (from CONFIRMED findings only). Each specialist gets its own backend so the
threads do not share a client; on a single local model they serialize at the model,
which is fine.

Emits events tagged with the active specialist, so the UI/CLI shows who is working.
Back-compat: `Swarm` is an alias for `Hivemind`."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from c0mr4de.agent.backends import build_backend
from c0mr4de.agent.loop import AgentLoop
from c0mr4de.swarm.agents import PHASES, RUNTIME_RECON
from c0mr4de.swarm.blackboard import Blackboard

_FINDING_MARKERS = ("BENCH{", "flag{", "FLAG{", "MIRAGE{", "premium unlocked",
                    "successfully solved", "<<<", '"role": "admin"', '"role":"admin"')
# Deterministic-confirmation notes that test_injection's engine (_analyze, shared with the
# verifier) emits - the same hard signals the verifier confirms on.
_TI_CONFIRM = ("db error on a single-quote", "materially different", "(time-based) confirmed",
               "xss confirmed")


def _looks_like_finding(text: str) -> bool:
    return any(m.lower() in (text or "").lower() for m in _FINDING_MARKERS)


def _active_backend_cfg() -> dict:
    """Resolve the backend for the HIVEMIND (the heavy path). If the operator set a
    `heavy_model` preset in config.yaml, use it - that's the capable brain (e.g. a
    rotating NIM-DeepSeek -> local chain) reserved for real engagements. Otherwise
    fall back to the same resolution the web UI uses (runtime.json switch, then
    active_model, then the legacy single block). Each specialist builds its OWN client."""
    repo = Path(__file__).resolve().parent.parent.parent
    cfg = yaml.safe_load((repo / "config" / "config.yaml").read_text())
    models = cfg.get("models") or {}
    heavy = cfg.get("heavy_model")
    if heavy and heavy in models:
        return models[heavy]
    try:
        st = json.loads((repo / "config" / "runtime.json").read_text())
        if isinstance(st.get("active_backend"), dict):
            return st["active_backend"]
    except Exception:  # noqa: BLE001
        pass
    name = cfg.get("active_model")
    if name and name in models:
        return models[name]
    return cfg["backend"]


class Hivemind:
    def __init__(self, backend=None, max_steps: int = 14, on_event=None, should_stop=None, make_backend=None,
                 max_feedback: int = 8):
        self.backend = backend                 # kept for the "backend name" event; specialists get fresh ones
        self.max_steps = max_steps
        self.on_event = on_event or (lambda kind, data: None)
        self.should_stop = should_stop or (lambda: False)
        self._make_backend = make_backend      # test seam: () -> backend
        # The mutual recon<->exploit flow is CONVERGENCE-driven: it keeps iterating while each
        # round still produces new gaps/findings and STOPS on its own when nothing new appears.
        # max_feedback is only a high SAFETY backstop against pathological flapping (0 disables
        # feedback entirely) - in practice the loop terminates by convergence, not by this cap.
        self.max_feedback = max_feedback

    def _new_backend(self):
        if self._make_backend:
            return self._make_backend()
        return build_backend(_active_backend_cfg())

    def _concurrency(self) -> int:
        """How many specialists in a phase may run at once. A local Ollama model
        serves one model on one device - concurrent 7B requests thrash and can
        wedge the box, so local runs go SEQUENTIAL. A hosted OpenAI-compatible API
        (GLM/DeepSeek/etc.) handles real concurrency, so there we fan out."""
        if self._make_backend:
            return 6
        try:
            return 1 if _active_backend_cfg().get("type") == "ollama" else 6
        except Exception:  # noqa: BLE001
            return 1

    def run(self, target: str, objective: str) -> Blackboard:
        from c0mr4de.tools import cache
        cache.clear()   # per-engagement cache: specialists share recon results, no cross-run staleness
        bb = Blackboard(target=target, objective=objective)
        recon, exploit, validate, report = PHASES
        self._phase(recon, bb, objective, target)
        self._deterministic_sweep(bb, target)   # code-driven detection - never depends on the model
        self._correlate(bb)                      # tie source findings to live endpoints (Shannon-style)
        if self.should_stop():
            return bb
        # Mutual collaboration loop: recon's output feeds exploitation, exploitation's output
        # (gaps + new findings) feeds recon, and so on - the bidirectional "one agent's input is
        # the other's output, and vice versa" flow. It runs until the shared blackboard STOPS
        # changing (convergence), with max_feedback as a safety cap. Terminated by convergence,
        # NOT an unbounded A<->B cycle (which would deadlock).
        rounds = 0
        while not self.should_stop():
            self._phase(exploit, bb, objective, target)
            fresh = bb.new_gaps()                 # gaps the exploit specialists fed back to recon
            # Converged when exploitation raised no new gaps for recon to fill; otherwise recon
            # consumes those gaps, re-surfaces, and exploitation runs again - the bidirectional
            # loop continues until it converges (no new gaps) or the safety cap is reached.
            if not fresh or rounds >= self.max_feedback:
                break
            rounds += 1
            self.on_event("feedback", {"round": rounds, "gaps": [g["text"] for g in fresh]})
            self._phase([RUNTIME_RECON], bb, objective, target, extra=bb.gaps_brief(fresh))
            self._deterministic_sweep(bb, target)   # re-sweep any newly surfaced endpoints
            self._correlate(bb)                      # re-correlate against the newly surfaced endpoints
        if not self.should_stop():
            self._phase(validate, bb, objective, target)
            self._phase(report, bb, objective, target)
        return bb

    def _correlate(self, bb) -> None:
        """Tie source-audit findings to live runtime endpoints (Shannon's edge): a
        SAST sink that recon confirmed is reachable is the highest-value lead. Pure,
        code-driven, best-effort - posts correlated LEADS the exploit specialists see
        first. Never breaks a run."""
        if self.should_stop():
            return
        try:
            from c0mr4de.swarm.correlate import correlate_blackboard
            hits = correlate_blackboard(bb)
            if hits:
                self.on_event("correlate", {"count": len(hits),
                                            "leads": [h["text"][:160] for h in hits[:4]],
                                            "counts": bb.counts()})
        except Exception:  # noqa: BLE001
            pass

    def _deterministic_sweep(self, bb, target: str) -> None:
        """Run test_all_params in CODE (not via the model) so the hivemind confirms the
        obvious injectable vulns even when a weak local model fails to drive the tools.
        This is c0mr4de's determinism-first thesis applied to the swarm: the baseline
        detection + confirmation is guaranteed; the model-driven specialists add
        judgment, chaining and coverage on top. Best-effort - never breaks a run."""
        if self.should_stop():
            return
        try:
            from c0mr4de.tools import build_default_registry
            tool = build_default_registry().get("test_all_params")
            if tool is None:
                return
            self.on_event("phase", {"name": "sweep", "specialists": ["deterministic-sweep"],
                                    "parallel": False, "counts": bb.counts()})
            self.on_event("agent_start", {"agent": "deterministic-sweep", "domain": "code-driven detection"})
            result = tool.run(url=target)
            self.on_event("tool_result", {"agent": "deterministic-sweep", "name": "test_all_params",
                                          "result": result})
            low = result.lower()
            if "likely-vulnerable" in low:
                for line in result.splitlines():
                    ll = line.lower()
                    if any(m in ll for m in _TI_CONFIRM):
                        bb.confirm("deterministic-sweep", line.strip()[:300])
                    elif line.strip().startswith("[") and ("sqli" in ll or "xss" in ll):
                        bb.lead("deterministic-sweep", line.strip()[:220])
            self.on_event("agent_done", {"agent": "deterministic-sweep", "counts": bb.counts()})
        except Exception:  # noqa: BLE001
            pass

    def _phase(self, group, bb, objective, target, extra: str = "") -> None:
        if not group or self.should_stop():
            return
        parallel = min(len(group), self._concurrency()) > 1
        self.on_event("phase", {"name": group[0].phase, "specialists": [p.name for p in group],
                                "parallel": parallel, "counts": bb.counts()})
        self._run_phase(group, bb, objective, target, extra)

    def _run_phase(self, group, bb, objective, target, extra: str = "") -> None:
        workers = min(len(group), self._concurrency())
        if workers <= 1:
            for p in group:                       # local backend: sequential (avoid thrashing one model)
                if self.should_stop():
                    break
                self._run_specialist(p, bb, objective, target, extra)
            return
        with ThreadPoolExecutor(max_workers=workers) as ex:   # hosted backend: real parallelism
            futs = [ex.submit(self._run_specialist, p, bb, objective, target, extra) for p in group]
            for f in futs:
                f.result()   # surface exceptions; each specialist already guards its own tools

    def _run_specialist(self, profile, bb, objective, target, extra: str = "") -> None:
        if self.should_stop():
            return
        self.on_event("agent_start", {"agent": profile.name, "domain": profile.domain})
        captured: list[dict] = []

        def on_ev(kind, data, _agent=profile.name):
            self.on_event(kind, {**data, "agent": _agent})
            if kind == "tool_result":
                captured.append(data)

        task = (f"{objective}\n\nTarget: {target}\n\n"
                f"--- shared hivemind memory (structured; do not duplicate work) ---\n{bb.brief()}")
        if extra:
            task += f"\n\n{extra}"
        primer = profile.domain_primer()   # deterministic domain grounding (no embedder, no model decision)
        if primer:
            task += f"\n\n{primer}"
        try:
            loop = AgentLoop(backend=self._new_backend(), tools=profile.registry(), max_steps=self.max_steps,
                             verbose=False, on_event=on_ev, should_stop=self.should_stop,
                             system_prompt=profile.system)
            summary = loop.run(task)
        except Exception as exc:  # noqa: BLE001 - one specialist dying must not kill the phase
            summary = f"(specialist {profile.name} errored: {exc})"
        self._capture(bb, profile, captured, summary)
        self.on_event("agent_done", {"agent": profile.name, "summary": summary, "counts": bb.counts()})

    def _capture(self, bb, profile, captured, summary) -> None:
        """Route a specialist's outputs into the structured blackboard from TOOL
        EVIDENCE, not model prose. A verify_finding CONFIRMED (the verifier's
        ground-truth marker) is the ONLY thing that reaches `confirmed`; narration
        is never posted as a lead (a live run showed specialists posting
        'I apologize for the confusion...' as findings)."""
        post = {"surface": bb.surface_item, "leads": bb.lead,
                "confirmed": bb.confirm, "notes": bb.note}.get(profile.posts, bb.note)
        posted_confirm = False
        for data in captured:
            name, result = data.get("name"), data.get("result", "")
            low = result.lower()
            if "[confirmed]" in low:                                   # verifier ground truth
                bb.confirm(profile.name, result.splitlines()[0][:300])
                posted_confirm = True   # a tool confirmation exists; don't also post the prose summary
            elif name == "verify_finding" and ("[unconfirmed]" in low or "[inconclusive]" in low):
                bb.lead(profile.name, result.splitlines()[0][:220])
            elif name == "note_gap" and "gap noted" in low:           # feedback to recon
                bb.gap(profile.name, result.split(":", 1)[-1].strip()[:220])
            elif name in ("test_injection", "test_all_params") and "likely-vulnerable" in low:
                # test_injection runs the SAME deterministic engine as the verifier (_analyze), so
                # an error-based / boolean / time / executed signal IS a confirmation - count it,
                # rather than waiting for the model to re-call verify_finding with precise args.
                if any(m in low for m in _TI_CONFIRM):
                    line = next((ln for ln in result.splitlines()
                                 if any(m in ln.lower() for m in _TI_CONFIRM)), result.splitlines()[0])
                    bb.confirm(profile.name, line.strip()[:300])
                    posted_confirm = True
                else:
                    bb.lead(profile.name, result[:300])
            elif _looks_like_finding(result):
                post(profile.name, result[:400])
        # The summary is prose, not evidence. Keep only: a reconciled CONFIRMED (the
        # hardened loop appends tool-verified proof) when the tool result was not already
        # captured above, recon's surface synthesis, and the report note. Exploit/validate
        # narration is dropped.
        if summary and summary.strip():
            if ("[CONFIRMED]" in summary or "CONFIRMED (tool-verified" in summary):
                if not posted_confirm:   # don't double-count a finding already captured from its tool result
                    bb.confirm(profile.name, summary.strip()[:600])
            elif profile.phase == "recon":
                bb.surface_item(profile.name, summary.strip()[:500])
            elif profile.phase == "report":
                bb.note(profile.name, summary.strip()[:300])


# Back-compat alias - older callers/tests import Swarm.
Swarm = Hivemind


def _load_cfg():   # kept for back-compat with any importer
    return _active_backend_cfg()
