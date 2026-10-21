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
from c0mr4de.swarm.agents import PHASES
from c0mr4de.swarm.blackboard import Blackboard

_FINDING_MARKERS = ("BENCH{", "flag{", "FLAG{", "MIRAGE{", "premium unlocked",
                    "successfully solved", "<<<", '"role": "admin"', '"role":"admin"')


def _looks_like_finding(text: str) -> bool:
    return any(m.lower() in (text or "").lower() for m in _FINDING_MARKERS)


def _active_backend_cfg() -> dict:
    """Resolve the backend the same way the web UI does (runtime.json model switch,
    then config preset, then the legacy single block) so the hivemind uses the model
    the operator selected - and so each parallel specialist builds its OWN client."""
    repo = Path(__file__).resolve().parent.parent.parent
    cfg = yaml.safe_load((repo / "config" / "config.yaml").read_text())
    try:
        st = json.loads((repo / "config" / "runtime.json").read_text())
        if isinstance(st.get("active_backend"), dict):
            return st["active_backend"]
    except Exception:  # noqa: BLE001
        pass
    name, models = cfg.get("active_model"), cfg.get("models") or {}
    if name and name in models:
        return models[name]
    return cfg["backend"]


class Hivemind:
    def __init__(self, backend=None, max_steps: int = 14, on_event=None, should_stop=None, make_backend=None):
        self.backend = backend                 # kept for the "backend name" event; specialists get fresh ones
        self.max_steps = max_steps
        self.on_event = on_event or (lambda kind, data: None)
        self.should_stop = should_stop or (lambda: False)
        self._make_backend = make_backend      # test seam: () -> backend

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
        bb = Blackboard(target=target, objective=objective)
        for group in PHASES:
            if self.should_stop():
                break
            phase = group[0].phase if group else ""
            parallel = min(len(group), self._concurrency()) > 1
            self.on_event("phase", {"name": phase, "specialists": [p.name for p in group],
                                    "parallel": parallel, "counts": bb.counts()})
            self._run_phase(group, bb, objective, target)
        return bb

    def _run_phase(self, group, bb, objective, target) -> None:
        workers = min(len(group), self._concurrency())
        if workers <= 1:
            for p in group:                       # local backend: sequential (avoid thrashing one model)
                if self.should_stop():
                    break
                self._run_specialist(p, bb, objective, target)
            return
        with ThreadPoolExecutor(max_workers=workers) as ex:   # hosted backend: real parallelism
            futs = [ex.submit(self._run_specialist, p, bb, objective, target) for p in group]
            for f in futs:
                f.result()   # surface exceptions; each specialist already guards its own tools

    def _run_specialist(self, profile, bb, objective, target) -> None:
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
        for data in captured:
            name, result = data.get("name"), data.get("result", "")
            low = result.lower()
            if "[confirmed]" in low:                                   # verifier ground truth
                bb.confirm(profile.name, result.splitlines()[0][:300])
            elif name == "verify_finding" and ("[unconfirmed]" in low or "[inconclusive]" in low):
                bb.lead(profile.name, result.splitlines()[0][:220])
            elif name in ("test_injection", "test_all_params") and "likely-vulnerable" in low:
                bb.lead(profile.name, result[:300])
            elif _looks_like_finding(result):
                post(profile.name, result[:400])
        # The summary is prose, not evidence. Keep only: a reconciled CONFIRMED (the
        # hardened loop appends tool-verified proof), recon's surface synthesis, and the
        # report note. Exploit/validate narration is dropped.
        if summary and summary.strip():
            if "[CONFIRMED]" in summary or "CONFIRMED (tool-verified" in summary:
                bb.confirm(profile.name, summary.strip()[:600])
            elif profile.phase == "recon":
                bb.surface_item(profile.name, summary.strip()[:500])
            elif profile.phase == "report":
                bb.note(profile.name, summary.strip()[:300])


# Back-compat alias - older callers/tests import Swarm.
Swarm = Hivemind


def _load_cfg():   # kept for back-compat with any importer
    return _active_backend_cfg()
