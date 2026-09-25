"""Scope / rules of engagement. The operator declares what's in and out of
scope and the focus for an engagement; c0mr4de injects it into the agent's
context and hard-refuses requests to explicitly out-of-scope hosts. This is
the bug-bounty 'rules of engagement' - keeps the agent inside the authorized
boundary and pointed at the vuln classes you care about."""
from __future__ import annotations

import threading
from urllib.parse import urlparse

_lock = threading.Lock()
_scope = {"in": [], "out": [], "focus": ""}


def _host(url_or_host: str) -> str:
    h = (url_or_host or "").strip().lower()
    if "://" in h:
        h = urlparse(h).netloc
    return h.split("/")[0].split(":")[0]


def set_scope(in_scope: list[str] | None = None, out_of_scope: list[str] | None = None, focus: str = "") -> str:
    with _lock:
        if in_scope is not None:
            _scope["in"] = [_host(x) for x in in_scope if x.strip()]
        if out_of_scope is not None:
            _scope["out"] = [_host(x) for x in out_of_scope if x.strip()]
        if focus:
            _scope["focus"] = focus.strip()
    return brief()


def clear_scope() -> None:
    with _lock:
        _scope.update({"in": [], "out": [], "focus": ""})


def _matches(host: str, patterns: list[str]) -> bool:
    return any(host == p or host.endswith("." + p) for p in patterns)


def check(url: str) -> str:
    """'out' (explicitly out of scope - block), 'in' (allowed), or 'unknown'."""
    host = _host(url)
    if not host:
        return "unknown"
    with _lock:
        if _matches(host, _scope["out"]):
            return "out"
        if _scope["in"] and _matches(host, _scope["in"]):
            return "in"
        if _scope["in"]:
            return "unknown"  # scope defined but host not listed
        return "in"  # no scope set -> nothing blocked


def brief() -> str:
    with _lock:
        if not (_scope["in"] or _scope["out"] or _scope["focus"]):
            return ""
        lines = ["RULES OF ENGAGEMENT:"]
        if _scope["in"]:
            lines.append(f"  IN SCOPE (only test these): {', '.join(_scope['in'])}")
        if _scope["out"]:
            lines.append(f"  OUT OF SCOPE (never touch): {', '.join(_scope['out'])}")
        if _scope["focus"]:
            lines.append(f"  FOCUS: {_scope['focus']}")
        lines.append("  Stay strictly inside scope. Do not test hosts not listed as in-scope.")
        return "\n".join(lines)
