"""Authenticated-testing session store.

The OPERATOR provides a session (cookie / auth header) for a host they are
authorized to test; c0mr4de's http_request and browser tools then attach it
automatically for requests to that host, so the agent operates as the
logged-in user. The agent never creates accounts, logs in, or harvests
credentials - auth is set out-of-band by you and only replayed to the host
you scoped it to.
"""
from __future__ import annotations

import threading
from urllib.parse import urlparse

_lock = threading.Lock()
# host -> {"cookie": "k=v; k2=v2", "headers": {"Authorization": "Bearer ..."}}
_store: dict[str, dict] = {}


def _norm(host: str) -> str:
    host = (host or "").strip().lower()
    if "://" in host:
        host = urlparse(host).netloc
    host = host.split("/")[0]
    return host.split(":")[0]  # strip port - cookies are host-scoped, not port-scoped


def set_auth(host: str, cookie: str = "", headers: dict | None = None) -> str:
    h = _norm(host)
    if not h:
        return "ERROR: no host given"
    with _lock:
        _store[h] = {"cookie": (cookie or "").strip(), "headers": headers or {}}
    return h


def clear_auth(host: str | None = None) -> None:
    with _lock:
        if host is None:
            _store.clear()
        else:
            _store.pop(_norm(host), None)


def for_url(url: str) -> dict:
    """Return {'cookie':..., 'headers':{...}} to attach for this URL's host,
    or {} if no auth is scoped to it. Matches the exact host or a parent
    domain (so auth for example.com also covers app.example.com)."""
    host = _norm(url)
    if not host:
        return {}
    with _lock:
        for stored_host, v in _store.items():
            if host == stored_host or host.endswith("." + stored_host):
                return {"cookie": v["cookie"], "headers": dict(v["headers"])}
    return {}


def status() -> list[str]:
    """Which hosts currently have auth set (values never exposed)."""
    with _lock:
        return sorted(_store.keys())
