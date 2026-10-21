"""Agent-loop hardening: the model's prose is not ground truth. A deterministic
tool CONFIRMED must override a negative conclusion and must be surfaced on a
positive one, and a verdict reached without any real test is pushed to verify.
This is the exact failure a live run exposed (the 7B said 'No injection points
confirmed' while verify_finding returned CONFIRMED on the same request)."""
import pytest

import c0mr4de.agent.loop as loopmod
from c0mr4de.agent.backends import LLMResponse, ToolCall
from c0mr4de.agent.loop import AgentLoop
from c0mr4de.tools.base import Tool, ToolRegistry


class FakeBackend:
    name = "fake"

    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.i = 0

    def generate(self, system, messages, tools):
        r = self.scripted[min(self.i, len(self.scripted) - 1)]
        self.i += 1
        return r

    def format_turn(self, response, tool_results):
        msgs = [{"role": "assistant", "content": response.text or "(tool call)"}]
        for call, res in tool_results:
            msgs.append({"role": "user", "content": f"[{call.name}] {res}"})
        return msgs


def _reg(verify_result="[CONFIRMED] claim: sqli  technique: sqli"):
    r = ToolRegistry()
    r.register(Tool(name="verify_finding", description="v",
                    parameters={"type": "object", "properties": {}}, fn=lambda **k: verify_result))
    r.register(Tool(name="test_injection", description="t",
                    parameters={"type": "object", "properties": {}}, fn=lambda **k: "likely-vulnerable: [id] SQLi"))
    return r


@pytest.fixture(autouse=True)
def _no_rag(monkeypatch):
    monkeypatch.setattr(loopmod, "consult_knowledge", lambda *a, **k: "")


def _loop(scripted, on_event=None):
    return AgentLoop(backend=FakeBackend(scripted), tools=_reg(), max_steps=6, verbose=False,
                     supervise=False, trim_tools=False, on_event=on_event)


def test_tool_confirmation_overrides_negative_prose():
    scripted = [
        LLMResponse("", [ToolCall("1", "verify_finding", {})]),             # tool -> CONFIRMED
        LLMResponse("No injection points confirmed. Nothing was found.", []),  # model lies
    ]
    out = _loop(scripted).run("test http://t/item?id=1 for sqli")
    assert "overrides" in out.lower() and "CONFIRMED" in out and "sqli" in out.lower()


def test_confirmation_annotates_positive_conclusion():
    scripted = [
        LLMResponse("", [ToolCall("1", "verify_finding", {})]),
        LLMResponse("The id parameter is injectable.", []),
    ]
    out = _loop(scripted).run("test it")
    assert "CONFIRMED (tool-verified ground truth)" in out


def test_gate_fires_on_verdict_without_testing():
    events = []
    scripted = [
        LLMResponse("I found no vulnerabilities.", []),   # negative verdict, no tool -> gate
        LLMResponse("Still nothing.", []),
    ]
    _loop(scripted, on_event=lambda k, d: events.append((k, d))).run("test http://t for vulns")
    assert any(k == "supervisor" and d.get("action") == "gate" for k, d in events)


def test_gate_fires_on_unbacked_positive_claim():
    events = []
    scripted = [
        LLMResponse("The target is vulnerable to SQL injection.", []),   # claim, no test -> gate
        LLMResponse("Confirmed vulnerable.", []),
    ]
    _loop(scripted, on_event=lambda k, d: events.append((k, d))).run("test it")
    assert any(k == "supervisor" and d.get("action") == "gate" for k, d in events)
