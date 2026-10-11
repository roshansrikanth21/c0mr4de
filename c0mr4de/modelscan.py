"""Discover the local models actually installed on THIS device, so the UI model
picker shows what you really have instead of hardcoded presets.

Scans, each best-effort and FAST (never raises):
  - Ollama          -> GET <host>/api/tags      (every model you've pulled)
  - OpenAI-compatible local servers (LM Studio, llama.cpp, vLLM, Jan, Colibri, ...)
                    -> GET <base>/v1/models      (every model they currently serve)
  - config.yaml `models:` presets                (user-defined, always shown)

Speed matters: this runs on every UI load. A closed port is rejected by a
~0.3s socket pre-check (so we never wait on an HTTP timeout for a server that
isn't there), and all endpoints are probed concurrently, so discovery is sub-
second whether you have zero local servers or several.

Each discovered model carries a ready-to-use `backend` block (the same shape
build_backend() takes), so switching to it needs no config edit.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# Local OpenAI-compatible servers commonly listen on these. Extra ones can be
# added via config.yaml `local_endpoints:`.
_DEFAULT_OAI_ENDPOINTS = [
    "http://localhost:11434/v1",  # Ollama's own OpenAI-compatible shim
    "http://localhost:1234/v1",   # LM Studio
    "http://localhost:8080/v1",   # llama.cpp server / Colibri
    "http://localhost:8000/v1",   # vLLM / misc
    "http://localhost:1337/v1",   # Jan
    "http://localhost:5000/v1",   # text-generation-webui
]

_DEFAULT_OLLAMA_HOST = "http://localhost:11434"


def _port_open(url: str, timeout: float = 0.25) -> bool:
    """Fast gate: is anything listening on this URL's host:port? A closed local
    port is refused near-instantly, so we never pay an HTTP timeout for a server
    that isn't running. 'localhost' is forced to the IPv4 literal to skip DNS and
    the IPv6/IPv4 dual-stack retry that otherwise doubles the wait per probe."""
    try:
        u = urlparse(url if "://" in url else "http://" + url)
        host = u.hostname or "127.0.0.1"
        if host == "localhost":
            host = "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def _hsize(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.0f} PB"


def _sig(b: dict) -> tuple:
    """Identity of a backend block, so the same model is not listed twice."""
    return (b.get("type"), b.get("model"), b.get("host") or b.get("base_url"))


def _scan_ollama(host: str) -> list[dict]:
    if not _port_open(host):
        return []
    import httpx
    out = []
    try:
        r = httpx.get(host.rstrip("/") + "/api/tags", timeout=1.5)
        for m in r.json().get("models", []):
            name = m.get("name")
            if not name:
                continue
            out.append({
                "name": f"ollama:{name}",
                "label": name,
                "source": "ollama",
                "endpoint": host,
                "detail": _hsize(m.get("size")),
                "backend": {"type": "ollama", "model": name, "host": host},
            })
    except Exception:  # noqa: BLE001 - discovery must never raise
        pass
    return out


def _scan_openai(base_url: str, api_key: str = "local") -> list[dict]:
    if not _port_open(base_url):
        return []
    import httpx
    out = []
    base = base_url.rstrip("/")
    try:
        r = httpx.get(base + "/models",
                      headers={"Authorization": f"Bearer {api_key or 'local'}"}, timeout=1.2)
        if r.status_code != 200:
            return out
        for m in r.json().get("data", []):
            mid = m.get("id")
            if not mid:
                continue
            out.append({
                "name": f"oai:{base}:{mid}",
                "label": mid,
                "source": "openai",
                "endpoint": base,
                "detail": "served",
                "backend": {"type": "openai_compatible", "model": mid,
                            "base_url": base, "api_key": api_key or "local"},
            })
    except Exception:  # noqa: BLE001
        pass
    return out


def discover_models(cfg: dict | None = None) -> list[dict]:
    """Return the models available on this device: config presets first, then
    live-discovered Ollama + local OpenAI-compatible models, de-duplicated. All
    network probes run concurrently and fail fast, so this stays sub-second."""
    cfg = cfg or {}
    presets = {k: v for k, v in (cfg.get("models") or {}).items() if isinstance(v, dict)}

    # Ollama hosts: default + any referenced by a preset.
    ollama_hosts = {_DEFAULT_OLLAMA_HOST}
    for b in presets.values():
        if b.get("type") == "ollama" and b.get("host"):
            ollama_hosts.add(b["host"])

    # OpenAI-compatible endpoints: defaults + config extras + preset base_urls.
    oai_endpoints = list(_DEFAULT_OAI_ENDPOINTS)
    oai_endpoints += [e for e in (cfg.get("local_endpoints") or []) if isinstance(e, str)]
    oai_endpoints += [b["base_url"] for b in presets.values() if b.get("base_url")]
    oai_endpoints = list(dict.fromkeys(oai_endpoints))  # de-dup, keep order

    # Probe everything concurrently - total time ~ the single slowest probe.
    with ThreadPoolExecutor(max_workers=12) as ex:
        ollama_futs = [ex.submit(_scan_ollama, h) for h in ollama_hosts]
        oai_futs = [ex.submit(_scan_openai, ep) for ep in oai_endpoints]
        ollama_hits = [r for f in ollama_futs for r in f.result()]
        oai_hits = [r for f in oai_futs for r in f.result()]

    entries: list[dict] = []
    seen: set[tuple] = set()

    def _add(entry: dict) -> None:
        s = _sig(entry["backend"])
        if s in seen:
            return
        seen.add(s)
        entries.append(entry)

    # Presets first (they may carry keys/custom hosts and should win on dedup).
    for name, b in presets.items():
        _add({"name": name, "label": name, "source": "preset",
              "endpoint": b.get("base_url") or b.get("host") or "local",
              "detail": b.get("model", b.get("type", "")), "backend": b})
    for e in ollama_hits:
        _add(e)
    for e in oai_hits:
        _add(e)
    return entries


def find_entry(name: str, cfg: dict | None = None) -> dict | None:
    """Resolve a model `name` (from discover_models) back to its entry."""
    for e in discover_models(cfg):
        if e["name"] == name:
            return e
    return None
