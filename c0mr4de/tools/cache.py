"""Tool-result caching for idempotent recon/scan tools.

A hivemind run hits the same target from several specialists - recon, the
deterministic sweep, and each exploit specialist all crawl/probe the same host.
Re-running nmap/crawl/nuclei on an unchanged target wastes the biggest slice of a
run's wall-clock. This memoizes the EXPENSIVE, IDEMPOTENT recon tools (same tool +
same args -> same answer within a short window) in a process-global, TTL-bounded
cache, shared across every specialist's registry.

Only enumeration/scan tools are cached (see CACHEABLE). NOT cached: anything that
tests/exploits (http_request, test_injection - want fresh state/timing), polls
(oob_poll), reads mutable in-process state not captured by its args
(cve_for_surface, attack_surface_report, which read the growing _SURFACE), or
writes (write_report). Transient failures are never cached, so a rate-limit or a
down-Docker result doesn't get frozen in.

The orchestrator clears the cache at the start of each engagement, so caching is
per-run; disable entirely with C0MR4DE_TOOL_CACHE=0.
"""
from __future__ import annotations

import dataclasses
import json
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from c0mr4de.tools.base import Tool

_DEFAULT_TTL = 1800   # 30 min - a target's recon surface is stable within a run

# tool name -> ttl seconds. Idempotent enumeration/scan tools only.
CACHEABLE: dict[str, int] = {t: _DEFAULT_TTL for t in (
    "crawl_site", "crawl", "probe", "map_attack_surface", "fuzz_paths", "subfinder",
    "amass_enum", "katana_crawl", "gau_urls", "naabu_scan", "nuclei_scan", "shodan_host",
    "tlsx_sans", "dnsx_resolve", "cve_lookup",
)}

# a success result containing one of these is treated as transient and NOT cached
_TRANSIENT = ("tool error", "unavailable", "unreachable", "rate-limit", "rate limited",
              "not running", "cannot connect", "timed out", "timeout", "tpm", "docker",
              "all backends failed", "no such host", "connection refused")

_CACHE: dict[str, tuple[float, str]] = {}
_STATS = {"hits": 0, "misses": 0, "stored": 0}


def _enabled() -> bool:
    return os.environ.get("C0MR4DE_TOOL_CACHE", "1") not in ("0", "false", "no")


def _key(name: str, kwargs: dict) -> str:
    return name + "|" + json.dumps(kwargs, sort_keys=True, default=str)


def _cacheable_result(result) -> bool:
    if not isinstance(result, str) or not result.strip():
        return False
    low = result.lower()
    return not any(m in low for m in _TRANSIENT)


def maybe_wrap(tool: "Tool") -> "Tool":
    """Return a cache-wrapped copy of `tool` if it is cacheable, else the tool
    unchanged. Wraps the ORIGINAL fn each time (no double-wrapping), and every copy
    shares the process-global cache, so hits carry across specialists' registries."""
    ttl = CACHEABLE.get(tool.name)
    if ttl is None:
        return tool
    inner = tool.fn
    name = tool.name

    def cached_fn(**kwargs):
        if not _enabled():
            return inner(**kwargs)
        key = _key(name, kwargs)
        hit = _CACHE.get(key)
        if hit and (time.time() - hit[0]) < ttl:
            _STATS["hits"] += 1
            return hit[1]
        result = inner(**kwargs)              # may raise -> propagates to Tool.run, never cached
        _STATS["misses"] += 1
        if _cacheable_result(result):
            _CACHE[key] = (time.time(), result)
            _STATS["stored"] += 1
        return result

    return dataclasses.replace(tool, fn=cached_fn)


def clear() -> None:
    """Drop all cached results (call at the start of a new engagement)."""
    _CACHE.clear()


def stats() -> dict:
    total = _STATS["hits"] + _STATS["misses"]
    rate = round(_STATS["hits"] / total, 3) if total else 0.0
    return {**_STATS, "entries": len(_CACHE), "hit_rate": rate}
