"""Swarm orchestrator - runs the specialist pipeline (recon -> exploit ->
report) against a target, sharing a blackboard between them. Each phase is a
scoped AgentLoop; its findings and summary are posted to the blackboard so
the next specialist builds on them instead of starting over.

Emits events (via on_event) tagged with the active agent, so the UI/CLI can
show which specialist is working."""
from __future__ import annotations

from c0mr4de.agent.backends import build_backend
from c0mr4de.agent.loop import AgentLoop
from c0mr4de.swarm.agents import PIPELINE
from c0mr4de.swarm.blackboard import Blackboard

_FINDING_MARKERS = ("BENCH{", "flag{", "FLAG{", "MIRAGE{", "premium unlocked",
                    "successfully solved", "<<<", '"role": "admin"', '"role":"admin"')


def _looks_like_finding(text: str) -> bool:
    return any(m.lower() in (text or "").lower() for m in _FINDING_MARKERS)


class Swarm:
    def __init__(self, backend=None, max_steps: int = 16, on_event=None, should_stop=None):
        self.backend = backend
        self.max_steps = max_steps
        self.on_event = on_event or (lambda kind, data: None)
        self.should_stop = should_stop or (lambda: False)

    def run(self, target: str, objective: str) -> Blackboard:
        bb = Blackboard(target=target, objective=objective)
        backend = self.backend or build_backend(_load_cfg())

        for profile in PIPELINE:
            if self.should_stop():
                break
            self.on_event("agent_start", {"agent": profile.name})

            captured: list[str] = []

            def on_ev(kind, data, _agent=profile.name, _cap=captured):
                # tag every event with which specialist produced it
                self.on_event(kind, {**data, "agent": _agent})
                if kind == "tool_result" and _looks_like_finding(data.get("result", "")):
                    _cap.append(data["result"])

            task = (
                f"{objective}\n\nTarget: {target}\n\n"
                f"--- shared intel from the swarm so far ---\n{bb.brief()}"
            )
            loop = AgentLoop(backend=backend, tools=profile.registry(), max_steps=self.max_steps,
                             verbose=False, on_event=on_ev, should_stop=self.should_stop,
                             system_prompt=profile.system)
            summary = loop.run(task)

            # post this specialist's results to the shared blackboard
            for c in captured:
                bb.finding(profile.name, c)
            if profile.name == "recon":
                bb.note("recon", summary)
            elif summary and summary.strip():
                bb.note(profile.name, summary)
            self.on_event("agent_done", {"agent": profile.name, "summary": summary})

        return bb


def _load_cfg():
    from pathlib import Path

    import yaml

    repo = Path(__file__).resolve().parent.parent.parent
    return yaml.safe_load((repo / "config" / "config.yaml").read_text())["backend"]
