"""Plugin Mode tests. The one thing this module does that reaches outside
c0mr4de's own files is writing to a THIRD-PARTY app's config, so these assert,
against temp fixture files (never real app configs): the per-client JSON shapes
are correct (Claude's split command/args vs OpenCode's single command array +
nested mcp.servers key), merging never drops pre-existing content, a backup is
taken before any write, and describe() never echoes an existing file's content
back (only a diff-sized entry snippet) - the privacy property that matters most."""
import json

import c0mr4de.pluginmode as P


def test_claude_entry_shape_is_command_plus_args():
    e = P._claude_entry("target.com", "", "IDOR")
    assert e["command"] == P._command_list("target.com", "", "IDOR")[0]
    assert e["args"][0:2] == ["-m", "c0mr4de.cli"]
    assert "--in-scope" in e["args"] and "target.com" in e["args"]


def test_opencode_entry_shape_is_single_command_array_with_type_and_cwd():
    e = P._opencode_entry("target.com", "", "")
    assert e["type"] == "local"
    assert isinstance(e["command"], list)
    assert e["command"][0] == P._command_list()[0]          # interpreter is element 0, not a separate field
    assert "args" not in e                                   # no split command/args like Claude's shape
    assert e["cwd"] == str(P.REPO)


def test_describe_unknown_target():
    assert "error" in P.describe("not-a-real-target")


def test_describe_fresh_file_includes_full_preview(tmp_path, monkeypatch):
    fresh = tmp_path / "opencode.json"
    monkeypatch.setitem(P.TARGETS["opencode"], "project_path", lambda: fresh)
    d = P.describe("opencode", in_scope="t.com")
    assert d["exists"] is False and d["already_wired"] is False
    assert d["full_file_preview"] is not None
    parsed = json.loads(d["full_file_preview"])
    assert "c0mr4de" in parsed["mcp"]["servers"]
    assert d["cli_hint"].startswith("opencode mcp add c0mr4de -- ")


def test_describe_existing_file_never_echoes_its_content(tmp_path, monkeypatch):
    """The privacy-critical property: an existing config's content (which may
    hold other tools' secrets) must never appear anywhere in describe()'s
    return value - not in full_file_preview (must be None) and not leaked via
    entry_snippet (which only ever contains OUR OWN entry)."""
    existing = tmp_path / "claude_desktop_config.json"
    existing.write_text(json.dumps({
        "mcpServers": {"other-tool": {"command": "npx", "args": ["-y", "SUPER-SECRET-OTHER-TOOL"]}},
        "someAccountId": "SUPER-SECRET-ACCOUNT-ID-12345",
    }), encoding="utf-8")
    monkeypatch.setitem(P.TARGETS["claude-desktop"], "windows_path", lambda: existing)
    monkeypatch.setattr(P.sys, "platform", "win32")
    d = P.describe("claude-desktop")
    assert d["exists"] is True
    assert d["full_file_preview"] is None                    # the whole point of the fix
    blob = json.dumps(d)
    assert "SUPER-SECRET-OTHER-TOOL" not in blob
    assert "SUPER-SECRET-ACCOUNT-ID-12345" not in blob
    assert "c0mr4de" in d["entry_snippet"]                   # the snippet still has OUR entry


def test_describe_detects_already_wired(tmp_path, monkeypatch):
    existing = tmp_path / "claude_desktop_config.json"
    existing.write_text(json.dumps({"mcpServers": {"c0mr4de": {"command": "old", "args": []}}}), encoding="utf-8")
    monkeypatch.setitem(P.TARGETS["claude-desktop"], "windows_path", lambda: existing)
    monkeypatch.setattr(P.sys, "platform", "win32")
    d = P.describe("claude-desktop")
    assert d["already_wired"] is True


def test_write_config_preserves_everything_else_and_backs_up(tmp_path, monkeypatch):
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({
        "mcpServers": {"other-tool": {"command": "npx", "args": ["-y", "other"]}},
        "unrelatedTopLevelKey": {"nested": True},
    }), encoding="utf-8")
    monkeypatch.setitem(P.TARGETS["claude-desktop"], "windows_path", lambda: target)
    monkeypatch.setattr(P.sys, "platform", "win32")

    r = P.write_config("claude-desktop", in_scope="t.com")
    assert r["ok"] is True
    out = json.loads(target.read_text(encoding="utf-8"))
    assert "other-tool" in out["mcpServers"]                 # untouched
    assert out["unrelatedTopLevelKey"] == {"nested": True}   # untouched
    assert "c0mr4de" in out["mcpServers"]                    # added

    backup = __import__("pathlib").Path(r["backup"])
    assert backup.is_file()
    original = json.loads(backup.read_text(encoding="utf-8"))
    assert "c0mr4de" not in original["mcpServers"]           # backup is the PRE-write state


def test_write_config_creates_fresh_file_when_absent(tmp_path, monkeypatch):
    target = tmp_path / "sub" / "opencode.json"
    monkeypatch.setitem(P.TARGETS["opencode"], "project_path", lambda: target)
    r = P.write_config("opencode", focus="SSRF")
    assert r["ok"] is True and r["backup"] is None
    out = json.loads(target.read_text(encoding="utf-8"))
    assert "c0mr4de" in out["mcp"]["servers"]
    assert "--focus" in out["mcp"]["servers"]["c0mr4de"]["command"]


def test_write_config_rejects_invalid_existing_json(tmp_path, monkeypatch):
    target = tmp_path / "claude_desktop_config.json"
    target.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setitem(P.TARGETS["claude-desktop"], "windows_path", lambda: target)
    monkeypatch.setattr(P.sys, "platform", "win32")
    r = P.write_config("claude-desktop")
    assert "error" in r
    assert target.read_text(encoding="utf-8") == "{not valid json"   # untouched on failure


def test_status_shape():
    s = P.status()
    assert "mcp_sdk_installed" in s and "tool_count" in s and s["tool_count"] > 0
    assert len(s["targets"]) == len(P.TARGETS)
