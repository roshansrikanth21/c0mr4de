"""Intel Map - instant structured lookup over real disclosed bug-bounty writeups,
by vulnerability class. Built from the open pentester.land dataset (same source as
tools/writeups.py and memory/pentesterland.py), but as a precomputed JSON index
instead of free-text RAG, so these queries are instant: no embedder, no network.

Answers two questions a specialist actually needs mid-engagement:
  - "What does a real, disclosed XSS/IDOR/SSRF/... bug look like, and where was it
    found?" -> bug_class_intel(bug_class)
  - "Given this stack/surface, what vuln classes are most worth my time?" ->
    top_bug_classes()

Build the index once (or refresh weekly): `c0mr4de intel-map --ingest`
(c0mr4de/memory/intelmap.py). Passive, local file read only.
"""
from __future__ import annotations

import json
from pathlib import Path

from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE

_INDEX = WORKSPACE / "intel-map" / "index.json"
_cache: dict | None = None


def _load() -> dict | None:
    global _cache
    if _cache is not None:
        return _cache
    if not _INDEX.is_file():
        return None
    try:
        _cache = json.loads(_INDEX.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return _cache


def _missing_msg() -> str:
    return ("Intel Map index not built yet. Build it once:\n"
            "  c0mr4de intel-map --ingest\n"
            "(downloads pentester.land's open writeup index and builds a local, instant lookup - "
            "no key, no cost.)")


def _match_class(idx: dict, query: str) -> str | None:
    query = (query or "").strip().lower()
    if not query:
        return None
    classes = idx["classes"]
    if query in {c.lower() for c in classes}:
        return next(c for c in classes if c.lower() == query)
    hits = [c for c in classes if query in c.lower()]
    if not hits:
        return None
    return max(hits, key=lambda c: classes[c]["count"])


def available() -> bool:
    return _load() is not None


def stats() -> dict | None:
    """Raw {total_items, total_classes, classes:[{name,count}]} for the web UI -
    the full class list (small: name+count) so the UI can search/sort client side."""
    idx = _load()
    if idx is None:
        return None
    classes = sorted(({"name": n, "count": s["count"]} for n, s in idx["classes"].items()),
                      key=lambda c: -c["count"])
    return {"total_items": idx["total_items"], "total_classes": idx["total_classes"], "classes": classes}


def class_detail(bug_class: str, limit: int = 30) -> dict | None:
    """Raw detail for one class - {name, count, top_programs, items:[...]} - for the
    web UI's drill-down view. None if the class doesn't match anything."""
    idx = _load()
    if idx is None:
        return None
    name = _match_class(idx, bug_class)
    if not name:
        return None
    stat = idx["classes"][name]
    items = sorted((it for it in idx["items"] if name in it["b"]), key=lambda it: it.get("d", ""), reverse=True)
    return {"name": name, "count": stat["count"],
            "top_programs": [{"name": p, "count": n} for p, n in stat["top_programs"]],
            "items": items[:limit]}


def bug_class_intel(bug_class: str, limit: int = 8) -> str:
    """Real, disclosed bug-bounty writeups for a vulnerability class (e.g. 'IDOR',
    'SSRF', 'account takeover', 'SQL injection') - shows how that class is actually
    found and reported in the wild, with real programs/authors/dates/links. These
    are references to read, not proof for THIS target - still confirm with
    verify_finding."""
    idx = _load()
    if idx is None:
        return _missing_msg()
    name = _match_class(idx, bug_class)
    if not name:
        top = ", ".join(sorted(idx["classes"], key=lambda c: -idx["classes"][c]["count"])[:12])
        return f"No bug class matching '{bug_class}'. Try one of: {top}"
    stats = idx["classes"][name]
    items = sorted((it for it in idx["items"] if name in it["b"]), key=lambda it: it.get("d", ""), reverse=True)
    rows = items[:limit]
    progs = ", ".join(f"{p} ({n})" for p, n in stats["top_programs"][:5])
    head = (f"'{name}': {stats['count']} disclosed writeups" + (f" · common on: {progs}" if progs else "") +
            f". Showing {len(rows)} most recent:\n")
    body = "\n".join(f"  [{it.get('d') or '?'}] {it['t']}\n"
                     f"    {', '.join(it['p']) or '?'} · {it.get('a') or '?'} · {it['l']}" for it in rows)
    return head + body


def top_bug_classes(limit: int = 20, contains: str = "") -> str:
    """The most-reported real-world bug classes (from disclosed bug-bounty
    writeups), ranked by frequency - use this to prioritise what to test for on a
    target with a given stack/surface. Optional `contains` filters class names."""
    idx = _load()
    if idx is None:
        return _missing_msg()
    contains = (contains or "").strip().lower()
    ranked = sorted(idx["classes"].items(), key=lambda kv: -kv[1]["count"])
    if contains:
        ranked = [(n, s) for n, s in ranked if contains in n.lower()]
    ranked = ranked[:limit]
    if not ranked:
        return f"No bug classes match '{contains}'."
    head = f"Top {len(ranked)} bug classes by disclosed-writeup frequency ({idx['total_items']} total writeups):\n"
    body = "\n".join(f"  {name}: {s['count']}" for name, s in ranked)
    return head + body


TOOLS = [
    Tool(
        name="bug_class_intel",
        description=(
            "Real disclosed bug-bounty writeups for a vulnerability class (IDOR, SSRF, XSS, account "
            "takeover, SQLi, RCE, auth bypass, ...) - how that class is actually found in the wild, with "
            "real programs/authors/links. References to learn from, not proof for this target."
        ),
        parameters={"type": "object", "properties": {
            "bug_class": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["bug_class"]},
        fn=bug_class_intel,
    ),
    Tool(
        name="top_bug_classes",
        description=(
            "The most-reported real-world vulnerability classes from disclosed bug-bounty writeups, "
            "ranked by frequency - use to prioritise what to test for. Optional `contains` filter."
        ),
        parameters={"type": "object", "properties": {
            "limit": {"type": "integer"}, "contains": {"type": "string"}}, "required": []},
        fn=top_bug_classes,
    ),
]
