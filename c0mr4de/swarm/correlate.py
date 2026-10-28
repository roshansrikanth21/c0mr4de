"""Source<->runtime correlation - tie a SAST finding to the live endpoint.

Shannon's distinctive edge: a source-code finding ("param `id` in search.php flows
to a SQL sink") and a runtime surface point ("GET /search?id= is live") are far
stronger TOGETHER than apart. When the code audit says a sink is reachable from a
parameter AND recon found that same parameter/route live, that is a high-priority,
pre-validated lead pointed at the right exploit specialist - instead of two
unconnected entries sitting in separate buckets.

Both the CODE_AUDIT (source) and RUNTIME_RECON (runtime) specialists post to the
blackboard's `surface` bucket, tagged by agent, so correlation is a pure pass over
that bucket. Heuristic and best-effort - it emits LEADS, never confirmations; the
exploit/validate specialists still have to prove each one.
"""
from __future__ import annotations

import re

# source sink signatures -> (vuln class, which exploit specialist owns it)
_SINKS: list[tuple[str, str, str]] = [
    (r"mysql_query|mysqli|->query\(|cursor\.execute|execute\(|\bselect\b.*\bfrom\b|sqlalchemy", "sqli", "injection"),
    (r"system\(|exec\(|popen|subprocess|shell_exec|os\.system|passthru|proc_open", "command injection", "injection"),
    (r"\binclude\b|\brequire\b|fopen|readfile|file_get_contents|open\(|send_file|render_template\(", "file inclusion/path", "injection"),
    (r"unserialize|pickle\.loads|yaml\.load|marshal\.loads|readObject", "deserialization", "injection"),
    (r"echo |print |innerhtml|document\.write|response\.write|render\(|\.html\(|dangerouslysetinnerhtml", "xss", "client-side"),
    (r"curl_exec|requests\.(get|post)|urlopen|file_get_contents\(\s*\$|http\.get|fetch\(", "ssrf", "client-side"),
]
_PARAM_PATTERNS = [
    r"[?&]([a-zA-Z_][\w\-]{0,30})=",                               # query string  ?id=
    r"param(?:eter)?\s+['\"]?([a-zA-Z_]\w{0,30})",                 # "param 'id'" / "parameter id"
    r"\$_(?:GET|POST|REQUEST)\[['\"]?([a-zA-Z_]\w{0,30})",         # PHP superglobals
    r"request\.(?:args|form|GET|POST|values|params)(?:\.get\()?\[?['\"]?([a-zA-Z_]\w{0,30})",  # Flask/Django
    r"\bfield\s+['\"]?([a-zA-Z_]\w{0,30})",                        # "field 'id'"
]
_STOP_ROUTES = {"", "index", "api", "v1", "v2", "app", "home", "static", "assets", "public", "www"}


def _params(text: str) -> set[str]:
    out: set[str] = set()
    for pat in _PARAM_PATTERNS:
        for m in re.finditer(pat, text or "", re.I):
            out.add(m.group(1).lower())
    return out


def _route_tokens(text: str) -> set[str]:
    out: set[str] = set()
    # URL path segments
    for seg in re.findall(r"https?://[^\s]+", text or ""):
        for part in re.sub(r"https?://[^/]+", "", seg).split("?")[0].split("/"):
            part = re.sub(r"\.\w+$", "", part).strip().lower()
            if part and part not in _STOP_ROUTES and not part.isdigit():
                out.add(part)
    # source filename stems (search.php -> search)
    for fn in re.findall(r"\b([a-zA-Z_][\w\-]{1,40})\.(?:php|aspx?|jsp|py|rb|js|ts|go|java)\b", text or ""):
        if fn.lower() not in _STOP_ROUTES:
            out.add(fn.lower())
    return out


def _sink_class(text: str) -> tuple[str, str]:
    low = (text or "").lower()
    for pat, cls, specialist in _SINKS:
        if re.search(pat, low):
            return cls, specialist
    return "", ""


def _snip(text: str, n: int = 90) -> str:
    return " ".join((text or "").split())[:n]


def correlate(source_items: list[dict], runtime_items: list[dict], cap: int = 12) -> list[dict]:
    """Match source findings against live runtime surface. Returns correlated leads,
    strongest first: shared param + known sink > shared param > shared route + sink."""
    hits: list[dict] = []
    seen: set[tuple[int, int]] = set()
    for si, src in enumerate(source_items):
        sp, sroutes = _params(src["text"]), _route_tokens(src["text"])
        sink, specialist = _sink_class(src["text"])
        for ri, rt in enumerate(runtime_items):
            rp, rroutes = _params(rt["text"]), _route_tokens(rt["text"])
            shared_p = sp & rp
            shared_r = sroutes & rroutes
            if not (shared_p or (shared_r and sink)):
                continue
            if (si, ri) in seen:
                continue
            seen.add((si, ri))
            score = 3 if (shared_p and sink) else 2 if shared_p else 1
            via = ("param '" + sorted(shared_p)[0] + "'") if shared_p else ("route '" + sorted(shared_r)[0] + "'")
            who = f"{specialist} specialist" if specialist else "the matching exploit specialist"
            cls = sink or "input"
            text = (f"[CORRELATED] source {cls} sink ({_snip(src['text'])}) is reachable at runtime "
                    f"({_snip(rt['text'])}) via {via}. {who}: exploit + verify_finding FIRST - "
                    f"source and runtime agree, so this is the highest-value lead.")
            hits.append({"text": text, "score": score, "specialist": specialist,
                         "sink": sink, "via": via})
    hits.sort(key=lambda h: -h["score"])
    return hits[:cap]


def correlate_blackboard(bb, source_agents=("code-audit",)) -> list[dict]:
    """Split the blackboard's surface into source vs runtime items and post the
    correlated matches as leads. Returns the hits (also useful for events/tests)."""
    with bb._lock:
        surface = list(bb.surface)
    source = [s for s in surface if s.get("agent") in source_agents]
    runtime = [s for s in surface if s.get("agent") not in source_agents]
    if not source or not runtime:
        return []
    hits = correlate(source, runtime)
    for h in hits:
        bb.lead("correlator", h["text"])
    return hits
