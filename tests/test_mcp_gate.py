"""MCP safety-gate tests. The gate is the whole security value of exposing an
offensive toolset over MCP, so these assert: passive tools pass freely, active tools
are scope-fail-closed, out-of-scope is always refused, approvals are single-use and
must match the exact call, and an armed window allows in-scope actions but never
out-of-scope ones."""
import c0mr4de.mcp.gate as g
from c0mr4de import scope


def _reset():
    scope.clear_scope()
    g.disarm()
    if g._DIR.exists():
        for p in g._DIR.glob("*.json"):
            p.unlink()


def test_active_vs_passive():
    assert not g.is_active("consult_knowledge")
    assert not g.is_active("cve_lookup")
    assert g.is_active("test_injection")
    assert g.is_active("http_request")
    assert g.is_active("some_new_unlisted_tool")   # fail-safe: unknown = active


def test_passive_always_allowed_even_out_of_scope():
    _reset()
    scope.set_scope(out_of_scope=["evil.com"])
    ok, _ = g.guard("consult_knowledge", {"query": "x"}, None)
    assert ok


def test_active_out_of_scope_always_blocked():
    _reset()
    scope.set_scope(in_scope=["target.com"], out_of_scope=["bank.com"])
    ok, why = g.guard("test_injection", {"url": "http://bank.com/x"}, None)
    assert not ok and "OUT of scope" in why


def test_active_fail_closed_on_unknown_host():
    _reset()
    scope.set_scope(in_scope=["target.com"])             # scope set, other hosts unknown
    ok, why = g.guard("nuclei_scan", {"target": "http://random.io"}, None)
    assert not ok and "fail-closed" in why


def test_active_in_scope_requires_approval_then_runs_once():
    _reset()
    scope.set_scope(in_scope=["target.com"])
    args = {"url": "http://target.com/item?id=1"}
    ok, why = g.guard("test_injection", args, None)      # no approval -> pending
    assert not ok and "approval" in why.lower()
    aid = [r["id"] for r in g.list_pending()][0]
    # cannot consume before approval
    ok, _ = g.guard("test_injection", args, aid)
    assert not ok
    # operator approves
    done, _ = g.approve(aid)
    assert done
    ok, _ = g.guard("test_injection", args, aid)         # now runs
    assert ok
    ok, why = g.guard("test_injection", args, aid)       # single-use: second time fails
    assert not ok and "used" in why.lower()


def test_approval_must_match_exact_call():
    _reset()
    scope.set_scope(in_scope=["target.com"])
    g.guard("test_injection", {"url": "http://target.com/a"}, None)
    aid = [r["id"] for r in g.list_pending()][0]
    g.approve(aid)
    # reuse the approval for a DIFFERENT url -> rejected
    ok, why = g.guard("test_injection", {"url": "http://target.com/b"}, aid)
    assert not ok and "match" in why.lower()


def test_armed_window_allows_in_scope_but_not_out():
    _reset()
    scope.set_scope(in_scope=["target.com"], out_of_scope=["bank.com"])
    g.arm(5)
    assert g.is_armed()
    ok, why = g.guard("test_injection", {"url": "http://target.com/x"}, None)
    assert ok and "armed" in why.lower()
    ok, _ = g.guard("test_injection", {"url": "http://bank.com/x"}, None)   # out-of-scope still blocked
    assert not ok
    g.disarm()
    assert not g.is_armed()


def test_disarm_restores_per_action_approval():
    _reset()
    scope.set_scope(in_scope=["target.com"])
    g.arm(5); g.disarm()
    ok, _ = g.guard("test_injection", {"url": "http://target.com/x"}, None)
    assert not ok   # back to requiring approval
    _reset()
