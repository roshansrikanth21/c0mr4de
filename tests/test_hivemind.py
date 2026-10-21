"""Hivemind coordinator + blackboard. Asserts the structure that makes it a
hivemind and not a free-for-all: a thread-safe de-duplicated blackboard, phases
run in sequence while specialists within a phase run (and all complete), and ONLY
a verifier-CONFIRMED result reaches the `confirmed` bucket that the report uses."""
import c0mr4de.swarm.orchestrator as orch
from c0mr4de.swarm.blackboard import Blackboard


def test_blackboard_dedup_and_structured_brief():
    bb = Blackboard("t", "obj")
    assert bb.surface_item("runtime-recon", "endpoint /login found")
    assert not bb.surface_item("runtime-recon", "endpoint /login found")   # duplicate rejected
    assert bb.lead("injection", "maybe sqli on id")
    assert bb.confirm("validator", "[CONFIRMED] sqli on id")
    brief = bb.brief()
    assert "ATTACK SURFACE" in brief and "CONFIRMED" in brief and "UNVERIFIED leads" in brief
    assert bb.counts() == {"surface": 1, "leads": 1, "confirmed": 1, "gaps": 0}


def test_hivemind_phases_parallelism_and_verifier_gate(monkeypatch):
    class FakeLoop:
        def __init__(self, backend=None, tools=None, max_steps=0, verbose=False,
                     on_event=None, should_stop=None, system_prompt=""):
            self.on_event = on_event or (lambda *a, **k: None)
            self.sys = system_prompt

        def run(self, task):
            if "INJECTION specialist" in self.sys:
                # a real deterministic confirmation - the ONLY thing allowed into `confirmed`
                self.on_event("tool_result", {"name": "verify_finding",
                                              "result": "[CONFIRMED] claim: sqli  technique: sqli"})
                return "found and confirmed sqli on id"
            if "CLIENT-SIDE" in self.sys:
                # an UNVERIFIED lead must NOT become a confirmed finding
                self.on_event("tool_result", {"name": "verify_finding",
                                              "result": "[UNCONFIRMED] claim: xss - reflected only"})
                return "xss reflected but not executed"
            if "RUNTIME RECON" in self.sys:
                return "surface: /login, /api, id param"
            return "done"

    monkeypatch.setattr(orch, "AgentLoop", FakeLoop)
    events = []
    hm = orch.Hivemind(on_event=lambda k, d: events.append((k, d)), make_backend=lambda: object())
    bb = hm.run("http://t", "pwn it")

    # the verifier-confirmed sqli reached `confirmed`; the unconfirmed xss did NOT
    assert bb.counts()["confirmed"] == 1
    assert any("sqli" in c["text"].lower() for c in bb.confirmed)
    assert not any("xss" in c["text"].lower() for c in bb.confirmed)

    # phases fired in order
    assert [d["name"] for k, d in events if k == "phase"] == ["recon", "exploit", "validate", "report"]
    # every exploit specialist (parallel) actually ran, plus recon/validate/report
    starts = {d["agent"] for k, d in events if k == "agent_start"}
    assert {"runtime-recon", "code-audit", "injection", "client-side", "access-control", "auth",
            "validator", "reporter"} <= starts


def test_swarm_is_alias_for_hivemind():
    assert orch.Swarm is orch.Hivemind
