"""Core unit tests - pure logic, no network / no LLM / no Docker. Run with
`python -m pytest tests/` or `python tests/test_core.py`.

Locks in the behaviour that actually broke in real runs: the rotating
failover cursor bug, JWT tamper/decode, context trimming, the text
tool-call fallback parser, and stack fingerprinting."""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from c0mr4de.agent.backends import (  # noqa: E402
    Backend, LLMResponse, RotatingBackend, _extract_fallback_tool_call, _is_rate_limit,
)
from c0mr4de.agent.loop import _trim_history, _looks_like_unexecuted_plan, StepLog  # noqa: E402
from c0mr4de.agent.supervisor import Supervisor  # noqa: E402
from c0mr4de.tools.web import decode_jwt, tamper_jwt  # noqa: E402
from c0mr4de.engagement import _fingerprint_stack  # noqa: E402


# --- fakes ---
class _Ok(Backend):
    name = "ok"
    def __init__(self): self.calls = 0
    def generate(self, *a, **k):
        self.calls += 1
        return LLMResponse(text="served")

class _RateLimited(Backend):
    name = "limited"
    def __init__(self): self.calls = 0
    def generate(self, *a, **k):
        self.calls += 1
        raise Exception("Error code: 429 - rate_limit_exceeded tokens per day (TPD)")


def test_rotating_fails_over_past_rate_limited_member():
    # THE regression test: a 429'd first member must not be retried; the loop
    # must reach the second member. (Old bug: cursor mutated mid-loop -> retried.)
    limited, ok = _RateLimited(), _Ok()
    r = RotatingBackend([limited, ok])
    resp = r.generate("s", [{"role": "user", "content": "hi"}])
    assert resp.text == "served"
    assert ok.calls == 1
    assert r._last_used is ok


def test_rotating_all_fail_raises():
    a, b = _RateLimited(), _RateLimited()
    r = RotatingBackend([a, b])
    try:
        r.generate("s", [{"role": "user", "content": "x"}])
        assert False, "should have raised"
    except RuntimeError as e:
        assert "all backends failed" in str(e)


def test_is_rate_limit():
    assert _is_rate_limit(Exception("Error code: 429"))
    assert _is_rate_limit(Exception("tokens per day (TPD) quota"))
    assert not _is_rate_limit(Exception("connection refused"))


def test_extract_fallback_tool_call():
    text = 'Sure, let me do that. {"name": "decode_jwt", "arguments": {"token": "abc.def.ghi"}} done'
    tc = _extract_fallback_tool_call(text)
    assert tc is not None and tc.name == "decode_jwt"
    assert tc.arguments["token"] == "abc.def.ghi"
    assert _extract_fallback_tool_call("no tool call here") is None


def _mk_jwt(payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.sig"


def test_decode_jwt():
    out = decode_jwt(_mk_jwt({"acs": "Un Paid", "user": "guest"}))
    assert "Un Paid" in out and "guest" in out


def test_tamper_jwt_keeps_signature_changes_field():
    tok = _mk_jwt({"acs": "Un Paid"})
    out = tamper_jwt(tok, "acs", "Active")
    tampered = [l for l in out.splitlines() if l.count(".") == 2][0].strip()
    payload = json.loads(base64.urlsafe_b64decode(
        tampered.split(".")[1] + "=" * (-len(tampered.split(".")[1]) % 4)))
    assert payload["acs"] == "Active"
    assert tampered.split(".")[2] == tok.split(".")[2]  # signature unchanged


def test_trim_history_shrinks_old_keeps_recent():
    msgs = [{"role": "user", "content": "X" * 1000} for _ in range(10)]
    trimmed = _trim_history(msgs, keep_full=4, old_cap=100)
    assert len(trimmed) == 10  # no messages removed (pairing intact)
    assert len(trimmed[0]["content"]) < 200  # old shrunk
    assert len(trimmed[-1]["content"]) == 1000  # recent kept full


def test_looks_like_unexecuted_plan():
    assert _looks_like_unexecuted_plan("```python\nrequests.get(x)\n```", tools_used=False)
    assert _looks_like_unexecuted_plan("Step 1: do this. Next step: that.", tools_used=False)
    assert not _looks_like_unexecuted_plan("Done.", tools_used=True)


def test_fingerprint_stack():
    assert "Next.js" in _fingerprint_stack("has Next-Action header and _next/static")
    assert "Juice Shop" in _fingerprint_stack("GET /rest/products returned")
    assert _fingerprint_stack("totally generic text") == []


def test_supervisor_catches_loop_and_stuck():
    # identical tool call two steps running -> steer (loop)
    s = Supervisor()
    log = [StepLog(1, "", ['http_request({"url":"x"})'], ["200"]),
           StepLog(2, "", ['http_request({"url":"x"})'], ["200"])]
    v = s.review(log)
    assert v and v[0] == "steer"
    # distinct tools but all erroring two steps running -> steer (stuck)
    s = Supervisor()
    log = [StepLog(1, "", ["probe(...)"], ["httpx not available"]),
           StepLog(2, "", ["naabu(...)"], ["naabu not available"])]
    v = s.review(log)
    assert v and v[0] == "steer"
    # healthy progress -> no intervention
    s = Supervisor()
    log = [StepLog(1, "", ["crawl(...)"], ["found 12 endpoints"]),
           StepLog(2, "", ["probe(...)"], ["200 ok"])]
    assert s.review(log) is None
    # capped: never intervenes more than max_interventions times
    s = Supervisor(max_interventions=1)
    dup = [StepLog(1, "", ["x()"], ["ok"]), StepLog(2, "", ["x()"], ["ok"])]
    assert s.review(dup) is not None and s.review(dup) is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
