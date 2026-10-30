"""The MCP safety gate: tool classification, scope egress, and operator approval.

Pure, file-backed, and framework-free so it is fully unit-testable without an MCP
runtime. The server (server.py) calls `guard()` before dispatching any tool, and the
CLI calls `approve()/arm()/list_pending()` on the operator's side. State lives in
WORKSPACE/mcp-approvals so the server process and the CLI share it.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from c0mr4de import scope
from c0mr4de.tools.files import WORKSPACE

_DIR = WORKSPACE / "mcp-approvals"
_ARMED = _DIR / "_armed.json"
_LOG = _DIR / "_audit.log"
PENDING_TTL = 600     # a pending request the operator hasn't approved expires after 10 min
APPROVED_TTL = 300    # once approved, the single-use token is valid for 5 min

# PASSIVE = reads local/third-party data or does local-only transforms: no attack
# traffic to the target, no state change. Everything NOT listed here is treated as
# ACTIVE (fail-safe: a new/unknown tool is gated by default).
PASSIVE: set[str] = {
    "consult_knowledge", "recall_related", "search_writeups", "fetch_writeup",
    "read_file", "list_workspace", "read_worklog", "worklog", "add_osint_note",
    "decode_jwt", "make_poc", "cve_lookup", "cve_for_surface", "payloads",
    "whois_lookup", "crt_sh", "urlscan_search", "virustotal_lookup", "abuseipdb_check",
    "greynoise_check", "otx_indicator", "shodan_host", "google_dork", "username_search",
    "email_osint", "env_report", "attack_surface_report", "render_osint_graph",
    "write_report", "import_scan", "burp_import",
}
# arg keys that carry a target host/URL, checked against scope for active tools
_TARGET_KEYS = ("url", "target", "base_url", "domain", "host", "ip", "url_with_fuzz", "endpoint")


def is_active(tool: str) -> bool:
    return tool not in PASSIVE


# ---- scope egress (fail-closed for active tools) --------------------------------
def scope_block(args: dict) -> str | None:
    """Return a block reason if any target host in args is out-of-scope (or, when a
    scope is set, not in-scope). None = allowed."""
    hosts = []
    for k in _TARGET_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            hosts.append(v)
    for h in hosts:
        verdict = scope.check(h)
        if verdict == "out":
            return f"BLOCKED: '{scope._host(h)}' is explicitly OUT of scope. Refusing."
        if verdict == "unknown":
            return (f"BLOCKED (fail-closed): '{scope._host(h)}' is not in the operator's scope. "
                    f"The operator must add it to scope first - the AI cannot widen scope.")
    return None


# ---- approval store -------------------------------------------------------------
def _ensure() -> None:
    _DIR.mkdir(parents=True, exist_ok=True)


def _args_hash(tool: str, args: dict) -> str:
    blob = tool + "|" + json.dumps(args or {}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _rec_path(approval_id: str) -> Path:
    # keep it a plain token, no path traversal
    safe = "".join(c for c in approval_id if c.isalnum())
    return _DIR / f"{safe}.json"


def _audit(line: str) -> None:
    try:
        _ensure()
        with _LOG.open("a", encoding="utf-8") as f:
            f.write(f"{int(time.time())} {line}\n")
    except Exception:  # noqa: BLE001
        pass


def request(tool: str, args: dict) -> str:
    """Create a pending approval for an active tool call; returns its id."""
    _ensure()
    aid = _args_hash(tool, args) + format(int(time.time()) % 100000, "05d")
    _rec_path(aid).write_text(json.dumps({
        "id": aid, "tool": tool, "args_hash": _args_hash(tool, args),
        "args_preview": {k: args.get(k) for k in _TARGET_KEYS if args.get(k)},
        "status": "pending", "created": time.time()}), encoding="utf-8")
    _audit(f"REQUEST {aid} {tool} {_rec_path(aid).name}")
    return aid


def approve(approval_id: str) -> tuple[bool, str]:
    p = _rec_path(approval_id)
    if not p.exists():
        return False, f"no pending approval '{approval_id}'"
    rec = json.loads(p.read_text(encoding="utf-8"))
    if rec["status"] == "used":
        return False, f"approval '{approval_id}' was already used"
    if time.time() - rec["created"] > PENDING_TTL:
        return False, f"request '{approval_id}' expired - the AI should request it again"
    rec["status"] = "approved"
    rec["approved_at"] = time.time()
    p.write_text(json.dumps(rec), encoding="utf-8")
    _audit(f"APPROVE {approval_id} {rec['tool']}")
    return True, f"approved {rec['tool']} ({approval_id}); valid {APPROVED_TTL}s, single use"


def consume(approval_id: str, tool: str, args: dict) -> tuple[bool, str]:
    """Check an approval is approved, fresh, single-use, and matches this exact call;
    mark it used on success."""
    p = _rec_path(approval_id)
    if not p.exists():
        return False, f"unknown approval_id '{approval_id}'"
    rec = json.loads(p.read_text(encoding="utf-8"))
    if rec["tool"] != tool or rec["args_hash"] != _args_hash(tool, args):
        return False, "approval does not match this tool+arguments - request a new one"
    if rec["status"] == "used":
        return False, "approval already used (single-use) - request a new one"
    if rec["status"] != "approved":
        return False, f"approval still '{rec['status']}' - operator must approve it"
    if time.time() - rec.get("approved_at", 0) > APPROVED_TTL:
        return False, "approval expired - request + approve again"
    rec["status"] = "used"
    rec["used_at"] = time.time()
    p.write_text(json.dumps(rec), encoding="utf-8")
    _audit(f"CONSUME {approval_id} {tool}")
    return True, "approved"


def list_pending() -> list[dict]:
    _ensure()
    out = []
    for p in _DIR.glob("*.json"):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if rec.get("status") == "pending" and time.time() - rec.get("created", 0) <= PENDING_TTL:
            out.append(rec)
    return sorted(out, key=lambda r: r.get("created", 0))


# ---- "armed" window: operator opts into autonomous active actions for N minutes --
def arm(minutes: float) -> str:
    _ensure()
    until = time.time() + minutes * 60
    _ARMED.write_text(json.dumps({"until": until}), encoding="utf-8")
    _audit(f"ARM {minutes}min")
    return f"armed for {minutes:g} min - in-scope active actions run without per-action approval"


def disarm() -> None:
    try:
        _ARMED.unlink()
    except FileNotFoundError:
        pass
    _audit("DISARM")


def is_armed() -> bool:
    try:
        return time.time() < json.loads(_ARMED.read_text(encoding="utf-8")).get("until", 0)
    except Exception:  # noqa: BLE001
        return False


# ---- the single entry point the server calls ------------------------------------
def guard(tool: str, args: dict, approval_id: str | None) -> tuple[bool, str]:
    """(allowed, reason). Passive tools always pass. Active tools must clear scope,
    then either an armed window or a valid single-use approval."""
    if not is_active(tool):
        return True, "passive"
    blocked = scope_block(args or {})
    if blocked:
        _audit(f"SCOPE-BLOCK {tool} {blocked}")
        return False, blocked
    if is_armed():
        _audit(f"ALLOW-ARMED {tool}")
        return True, "allowed (operator-armed window)"
    if approval_id:
        ok, why = consume(approval_id, tool, args or {})
        return ok, why
    aid = request(tool, args or {})
    return False, (f"BLOCKED: '{tool}' is an active action and needs operator approval. "
                   f"Pending id: {aid}. Ask the operator to run `c0mr4de mcp-approve {aid}` "
                   f"(or `c0mr4de mcp-arm <minutes>` to allow in-scope actions for a window), "
                   f"then retry this call with approval_id=\"{aid}\".")
