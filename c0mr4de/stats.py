"""Process-global usage/efficiency stats so the UI can show how each LLM
in the chain is performing - calls, tokens, avg latency, failures. Written
by the agent loop after every model call, read by the /stats endpoint."""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_stats: dict[str, dict] = {}
_started = time.time()


def record(backend: str, in_tokens: int, out_tokens: int, latency: float, ok: bool = True) -> None:
    with _lock:
        s = _stats.setdefault(backend, {"calls": 0, "in_tokens": 0, "out_tokens": 0, "total_latency": 0.0, "errors": 0})
        s["calls"] += 1
        s["in_tokens"] += in_tokens
        s["out_tokens"] += out_tokens
        s["total_latency"] += latency
        if not ok:
            s["errors"] += 1


def record_error(backend: str) -> None:
    with _lock:
        s = _stats.setdefault(backend, {"calls": 0, "in_tokens": 0, "out_tokens": 0, "total_latency": 0.0, "errors": 0})
        s["errors"] += 1


def snapshot() -> dict:
    with _lock:
        out = []
        for name, s in _stats.items():
            calls = s["calls"] or 1
            out.append({
                "backend": name,
                "calls": s["calls"],
                "in_tokens": s["in_tokens"],
                "out_tokens": s["out_tokens"],
                "total_tokens": s["in_tokens"] + s["out_tokens"],
                "avg_latency": round(s["total_latency"] / calls, 2),
                "errors": s["errors"],
            })
        out.sort(key=lambda x: x["calls"], reverse=True)
        return {"backends": out, "uptime_s": int(time.time() - _started)}


def reset() -> None:
    with _lock:
        _stats.clear()
