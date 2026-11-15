"""Plugin Mode - connect c0mr4de's MCP server (verified tools + RAG + Intel Map +
CVE-intel + payloads) to an external agent brain: Claude Desktop, Claude Code
(this CLI's own project-scoped .mcp.json), or OpenCode. The MCP server itself
(c0mr4de/mcp/server.py, `c0mr4de mcp`) already exposes everything - this module
just generates the exact config snippet each client expects, and can merge it
into that client's real config file for you.

Schemas verified live against each project's current docs (2026-11) rather than
assumed - Claude Code/Desktop and OpenCode use genuinely different shapes:
  Claude (both):  {"mcpServers": {name: {"command": str, "args": [...], "env": {}}}}
  OpenCode:       {"mcp": {"servers": {name: {"type": "local", "command": [...],
                   "cwd": str, "environment": {}}}}}  - command is ONE array here,
                   not split command+args, and a higher-precedence config file
                   replaces the whole entry on a name collision (no field merge).

Writing to a THIRD-PARTY app's config is the one thing this module does that
reaches outside c0mr4de's own files. It always backs up the original first, and
it only ever adds/overwrites a single "c0mr4de" entry under that client's server
map - it never touches any other key already in the file.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _command_list(in_scope: str = "", out_scope: str = "", focus: str = "") -> list[str]:
    """[interpreter, -m, c0mr4de.cli, mcp, ...flags] - sys.executable is this
    machine's ACTUAL interpreter (absolute path), so it resolves even when the
    launching app's own PATH doesn't include python/py."""
    cmd = [sys.executable, "-m", "c0mr4de.cli", "mcp"]
    if in_scope:
        cmd += ["--in-scope", in_scope]
    if out_scope:
        cmd += ["--out-scope", out_scope]
    if focus:
        cmd += ["--focus", focus]
    return cmd


def _claude_entry(in_scope: str, out_scope: str, focus: str) -> dict:
    cmd = _command_list(in_scope, out_scope, focus)
    return {"command": cmd[0], "args": cmd[1:]}


def _opencode_entry(in_scope: str, out_scope: str, focus: str) -> dict:
    return {"type": "local", "command": _command_list(in_scope, out_scope, focus), "cwd": str(REPO)}


# Each target: where its config lives, how its JSON nests ("path" into the
# config dict to the server map, as a tuple of keys), how to build its server
# entry, and a CLI one-liner shortcut (most of these tools have one).
TARGETS: dict[str, dict] = {
    "claude-desktop": {
        "name": "Claude Desktop",
        "key_path": ("mcpServers",),
        "entry": _claude_entry,
        "blurb": "Anthropic's desktop app. One global config; available in every chat once you restart it.",
        "docs": "https://code.claude.com/docs/en/mcp",
        "note": "Edit via Settings > Developer > Edit Config, or let c0mr4de merge it below. Restart the app after.",
        "cli_hint": None,
        "windows_path": lambda: Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        "mac_path": lambda: Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        "linux_path": lambda: Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
    },
    "claude-code": {
        "name": "Claude Code",
        "key_path": ("mcpServers",),
        "entry": _claude_entry,
        "blurb": "This CLI's own project-scoped .mcp.json, shared via git with anyone working in this repo.",
        "docs": "https://code.claude.com/docs/en/mcp",
        "note": "Project-scoped servers need one-time approval the next time you launch `claude` here.",
        "cli_hint": lambda c: "claude mcp add --scope project c0mr4de -- " + " ".join(f'"{a}"' for a in c),
        "project_path": lambda: REPO / ".mcp.json",
    },
    "opencode": {
        "name": "OpenCode",
        "key_path": ("mcp", "servers"),
        "entry": _opencode_entry,
        "blurb": "The open terminal agent (GLM/DeepSeek etc.). Project-level config, overrides the global one.",
        "docs": "https://opencode.ai/docs/mcp-servers/",
        "note": "A higher-precedence OpenCode config (global vs project) REPLACES this whole entry on name "
                "collision, not merge - if you've already got a global 'c0mr4de' entry, edit that one instead.",
        "cli_hint": lambda c: "opencode mcp add c0mr4de -- " + " ".join(f'"{a}"' for a in c),
        "project_path": lambda: REPO / "opencode.json",
    },
}


def _os_path(t: dict) -> Path | None:
    if "project_path" in t:
        return t["project_path"]()
    if sys.platform.startswith("win"):
        return t.get("windows_path", lambda: None)()
    if sys.platform == "darwin":
        return t.get("mac_path", lambda: None)()
    return t.get("linux_path", lambda: None)()


def _get_in(d: dict, keys: tuple[str, ...]) -> dict:
    for k in keys:
        d = d.setdefault(k, {}) if isinstance(d, dict) else {}
    return d


def describe(target_id: str, in_scope: str = "", out_scope: str = "", focus: str = "") -> dict:
    """Everything the UI needs for one target: config path, whether it already
    exists (and already has a c0mr4de entry), a one-line CLI shortcut where that
    client has one, and a paste-ready snippet.

    PRIVACY: if the target's config file already exists, its content is NEVER
    read into the returned snippet - only whether it exists and already has a
    c0mr4de entry. A real Claude Desktop config carries other servers' secrets
    and account preferences; this must never echo them back over the API, into
    logs, or into a screen share. `full_file_preview` (the whole file, safe to
    show because it's 100% c0mr4de's own content) is populated ONLY when the
    file does not exist yet. When it does exist, the UI shows `entry_snippet`
    (just the new "c0mr4de" block) for a manual merge, or the Write button."""
    t = TARGETS.get(target_id)
    if t is None:
        return {"error": f"unknown target '{target_id}'"}
    path = _os_path(t)
    exists = bool(path and path.is_file())
    already_wired = False
    if exists:
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            already_wired = "c0mr4de" in _get_in(existing, t["key_path"])
        except Exception:  # noqa: BLE001
            pass
    entry = t["entry"](in_scope, out_scope, focus)
    entry_snippet = json.dumps({"c0mr4de": entry}, indent=2)
    full_file_preview = None
    if not exists:
        fresh: dict = {}
        _get_in(fresh, t["key_path"])["c0mr4de"] = entry
        full_file_preview = json.dumps(fresh, indent=2)
    cmd = _command_list(in_scope, out_scope, focus)
    return {
        "id": target_id, "name": t["name"], "blurb": t["blurb"], "docs": t["docs"], "note": t["note"],
        "config_path": str(path) if path else None, "exists": exists, "already_wired": already_wired,
        "key_path": " > ".join(t["key_path"]),
        "entry_snippet": entry_snippet, "full_file_preview": full_file_preview,
        "cli_hint": t["cli_hint"](cmd) if t["cli_hint"] else None,
    }


def status(in_scope: str = "", out_scope: str = "", focus: str = "") -> dict:
    try:
        import mcp  # noqa: F401
        mcp_ok = True
    except Exception:  # noqa: BLE001
        mcp_ok = False
    from c0mr4de.tools import build_default_registry
    n_tools = len(build_default_registry()._tools)
    from c0mr4de import scope
    from c0mr4de.mcp import gate
    return {
        "mcp_sdk_installed": mcp_ok, "tool_count": n_tools,
        "scope_brief": scope.brief(), "armed": gate.is_armed(),
        "pending_approvals": len(gate.list_pending()),
        "targets": [describe(tid, in_scope, out_scope, focus) for tid in TARGETS],
    }


def write_config(target_id: str, in_scope: str = "", out_scope: str = "", focus: str = "") -> dict:
    """Merge the c0mr4de entry into TARGET's real config file, backing up
    whatever was there first. Only the "c0mr4de" entry under that client's own
    server map is touched - every other key in the file is preserved as-is."""
    t = TARGETS.get(target_id)
    if t is None:
        return {"error": f"unknown target '{target_id}'"}
    path = _os_path(t)
    if path is None:
        return {"error": f"no config path known for '{target_id}' on this OS"}
    existing: dict = {}
    backup = None
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return {"error": f"existing config at {path} is not valid JSON ({exc}) - fix or remove it first"}
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_suffix(path.suffix + f".bak-{stamp}")
        backup.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    _get_in(existing, t["key_path"])["c0mr4de"] = t["entry"](in_scope, out_scope, focus)
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return {"ok": True, "path": str(path), "backup": str(backup) if backup else None}
