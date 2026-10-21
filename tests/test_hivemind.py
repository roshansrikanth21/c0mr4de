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


def test_test_injection_deterministic_signal_counts_as_confirmed(monkeypatch):
    # test_injection runs the verifier's own engine (_analyze); an error-based DB-error
    # signal IS a confirmation, so a weak model that calls test_injection (but can't
    # construct a precise verify_finding call) still yields a CONFIRMED finding.
    class FakeLoop:
        def __init__(self, **k):
            self.on_event = k.get("on_event") or (lambda *a, **kw: None)
            self.sys = k.get("system_prompt", "")

        def run(self, task):
            if "INJECTION specialist" in self.sys:
                self.on_event("tool_result", {"name": "test_injection",
                    "result": "likely-vulnerable:\n  [/item?id] SQLi: DB error on a single-quote payload (error-based)"})
                return "tested the id param"
            return "done"

    monkeypatch.setattr(orch, "AgentLoop", FakeLoop)
    bb = orch.Hivemind(on_event=lambda k, d: None, make_backend=lambda: object(), max_feedback=0).run("http://t", "x")
    assert bb.counts()["confirmed"] >= 1
    assert any("db error" in c["text"].lower() for c in bb.confirmed)


def test_bounded_feedback_loop(monkeypatch):
    # an exploit specialist posts a gap once -> ONE focused recon round -> exploit again.
    state = {"gap_posted": False}

    class FakeLoop:
        def __init__(self, **k):
            self.on_event = k.get("on_event") or (lambda *a, **kw: None)
            self.sys = k.get("system_prompt", "")

        def run(self, task):
            if "INJECTION specialist" in self.sys and not state["gap_posted"]:
                state["gap_posted"] = True
                self.on_event("tool_result", {"name": "note_gap",
                                              "result": "GAP NOTED (recon requested): enumerate /admin endpoints"})
                return "blocked - need recon on admin"
            return "done"

    monkeypatch.setattr(orch, "AgentLoop", FakeLoop)
    events = []
    hm = orch.Hivemind(on_event=lambda k, d: events.append((k, d)), make_backend=lambda: object(), max_feedback=1)
    hm.run("http://t", "pwn it")
    feedback = [d for k, d in events if k == "feedback"]
    assert len(feedback) == 1 and "admin" in feedback[0]["gaps"][0]           # the gap fed recon
    recon_starts = [d for k, d in events if k == "agent_start" and d["agent"] == "runtime-recon"]
    assert len(recon_starts) == 2                                             # initial + one feedback round (bounded)


def test_feedback_disabled_with_max_feedback_zero(monkeypatch):
    class GapLoop:
        def __init__(self, **k):
            self.on_event = k.get("on_event") or (lambda *a, **kw: None)
            self.sys = k.get("system_prompt", "")

        def run(self, task):
            if "INJECTION specialist" in self.sys:
                self.on_event("tool_result", {"name": "note_gap", "result": "GAP NOTED (recon requested): x"})
            return "done"

    monkeypatch.setattr(orch, "AgentLoop", GapLoop)
    events = []
    orch.Hivemind(on_event=lambda k, d: events.append((k, d)), make_backend=lambda: object(),
                  max_feedback=0).run("http://t", "x")
    assert not any(k == "feedback" for k, d in events)                       # no feedback round when disabled


def test_specialists_run_in_parallel(monkeypatch):
    import time

    import c0mr4de.swarm.agents as agmod
    from c0mr4de.tools.base import ToolRegistry
    # isolate the parallelism measurement from per-specialist registry-build overhead
    monkeypatch.setattr(agmod, "build_default_registry", lambda *a, **k: ToolRegistry())

    class SleepLoop:
        def __init__(self, **k):
            self.on_event = k.get("on_event") or (lambda *a, **kw: None)

        def run(self, task):
            time.sleep(0.4)
            return "done"

    monkeypatch.setattr(orch, "AgentLoop", SleepLoop)
    hm = orch.Hivemind(on_event=lambda k, d: None, make_backend=lambda: object(), max_feedback=0)
    t = time.time()
    hm.run("http://t", "x")
    dt = time.time() - t
    # 8 specialists x 0.4s = 3.2s if sequential. recon (2) and exploit (4) run in parallel, so the
    # total collapses toward ~1.6s (recon .4 + exploit .4 + validate .4 + report .4). Under 2.5s
    # proves the phases genuinely fan out rather than running one specialist at a time.
    assert dt < 2.5
