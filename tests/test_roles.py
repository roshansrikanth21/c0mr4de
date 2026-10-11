"""Per-chat role scoping: a role must restrict the agent to its own tools plus
the always-on set, leave 'general' untouched, and produce a sane capability
digest. These guard the Hermes-style role feature wired into the web UI."""
from c0mr4de import roles
from c0mr4de.tools.base import Tool, ToolRegistry


def _reg(*names):
    r = ToolRegistry()
    for n in names:
        r.register(Tool(name=n, description=n, parameters={"type": "object", "properties": {}},
                        fn=lambda **k: "ok"))
    return r


def test_general_role_returns_registry_unchanged():
    reg = _reg("http_request", "nuclei_scan", "audit_source")
    out = roles.filter_registry(reg, "general")
    assert out is reg
    assert set(out.names()) == {"http_request", "nuclei_scan", "audit_source"}


def test_role_scopes_to_allowed_plus_always_on():
    # recon allows http_request/probe/nuclei_scan; bug-bounty-only test_injection
    # must be dropped; write_report is always-on so it survives any role.
    reg = _reg("http_request", "probe", "test_injection", "write_report", "nuclei_scan")
    names = set(roles.filter_registry(reg, "recon").names())
    assert {"http_request", "probe", "nuclei_scan"} <= names   # recon's own tools
    assert "write_report" in names                             # always-on
    assert "test_injection" not in names                       # not in recon's set


def test_role_skips_tools_not_registered():
    # a role names many tools; filtering keeps only the ones actually present.
    reg = _reg("http_request", "write_report")
    out = set(roles.filter_registry(reg, "bug_bounty").names())
    assert out <= {"http_request", "write_report"}
    assert "http_request" in out


def test_role_focus_present_for_specialist_empty_for_general():
    assert roles.role_focus("general") == ""
    assert "bug-bounty" in roles.role_focus("bug_bounty").lower()


def test_role_digest_shape_counts_only_present_tools():
    reg = _reg("http_request", "write_report", "nuclei_scan")
    d = roles.role_digest("recon", reg)
    assert d["name"] == "recon" and d["label"]
    assert {"http_request", "nuclei_scan", "write_report"} <= set(d["tools"])
    assert d["tool_count"] == len(d["tools"])


def test_unknown_role_falls_back_to_general():
    reg = _reg("http_request")
    assert roles.get_role("nope")["label"] == roles.ROLES["general"]["label"]
    assert roles.filter_registry(reg, "nope") is reg
