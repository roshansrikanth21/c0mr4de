"""Native web discovery + active injection testing — no Docker required.

These close the two gaps a live run exposed: without katana the agent couldn't
find real endpoints/params, and it never actually tested an input, so it reported
a deliberately-vulnerable app as clean.

- crawl_site(url): BFS same-host crawler over http_request; returns endpoints,
  query params, and forms. The katana fallback that works in any sandbox.
- test_injection(url): DETECTION-ONLY probes on a URL's params (SQLi error/boolean,
  reflected-XSS marker) with differential analysis. Non-destructive: no stacked
  queries, no time-based blind, no data exfiltration — it flags likely-vulnerable
  params for you to confirm, it does not weaponize.
"""
from __future__ import annotations

import urllib.parse
from collections import deque

import httpx

from c0mr4de.tools.base import Tool
from c0mr4de.tools.web import _request, extract_surface

# SQL error signatures across common engines.
_SQL_ERRORS = (
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg::syntaxerror", "psqlexception", "sqlite3.",
    "sqlstate", "odbc", "ora-01756", "ora-00933", "sql syntax", "mysql_fetch",
    "native client", "postgresql query failed",
)
_XSS_MARK = "c0mr4dexss7"          # unlikely to collide; reflected verbatim => reflection point
_XSS_PAYLOAD = f"<{_XSS_MARK}>"    # angle brackets un-encoded in the response => likely XSS


def crawl_site(url: str, depth: int = 2, max_pages: int = 40) -> str:
    """Spider a site (same host) via native HTTP, collecting endpoints, params and
    forms. Use this when katana/crawl is unavailable — it needs no Docker."""
    try:
        start = _request(url).url
    except PermissionError as exc:
        return f"BLOCKED: {exc}."
    except httpx.HTTPError as exc:
        return f"crawl error: {exc}"
    base = urllib.parse.urlparse(str(start)).netloc
    seen: set[str] = set()
    endpoints: dict[str, set[str]] = {}   # url -> params
    forms: list[dict] = []
    q: deque[tuple[str, int]] = deque([(str(start), 0)])
    while q and len(seen) < max_pages:
        u, d = q.popleft()
        if u in seen or d > depth:
            continue
        seen.add(u)
        try:
            r = _request(u)
        except (PermissionError, httpx.HTTPError):
            continue
        if "html" not in r.headers.get("content-type", ""):
            continue
        surf = extract_surface(r.text, str(r.url))
        endpoints.setdefault(u, set())
        for f in surf["forms"]:
            if f not in forms:
                forms.append(f)
        for link in surf["links"]:
            p = urllib.parse.urlparse(link)
            if p.netloc and p.netloc != base:
                continue
            endpoints.setdefault(link, set())
            if link not in seen:
                q.append((link, d + 1))
    # fold query params discovered on links back onto their base path
    param_ep = [f"{u}  ?[{','.join(sorted(ps))}]" if ps else u for u, ps in sorted(endpoints.items())]
    out = [f"crawled {len(seen)} pages on {base} (depth {depth}). {len(endpoints)} endpoints:"]
    out += [f"  {e}" for e in param_ep[:50]]
    if forms:
        out.append(f"forms ({len(forms)}):")
        out += [f"  {f['method']} {f['action']} inputs=[{','.join(f['inputs'])}]" for f in forms[:15]]
    withparams = [u for u, ps in endpoints.items() if ps]
    if withparams:
        out.append("endpoints WITH params (prime targets for test_injection):")
        out += [f"  {u}" for u in withparams[:15]]
    else:
        out.append("no query-param endpoints found yet — check forms above and submit them, "
                   "or look at product/search/category links.")
    return "\n".join(out)


def _get(url: str) -> tuple[int, str]:
    r = _request(url)
    return r.status_code, r.text


def test_injection(url: str, param: str = "") -> str:
    """DETECTION-ONLY test of a URL's query params for SQLi (error + boolean-diff) and
    reflected XSS. Give a full URL with a query string (e.g. /search?q=apple). Reports
    likely-vulnerable params with evidence — confirm manually before reporting impact."""
    parts = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parts.query)
    if not qs:
        return ("no query params in that URL. Give a URL like https://site/search?q=apple "
                "(find params with crawl_site / http_request), or submit a form's inputs as a query.")
    targets = [param] if param else list(qs)
    findings = []
    try:
        base_status, base_body = _get(url)
    except PermissionError as exc:
        return f"BLOCKED: {exc}."
    except httpx.HTTPError as exc:
        return f"error: {exc}"
    base_len = len(base_body)

    def build(p, val):
        q = {k: v[:] for k, v in qs.items()}
        q[p] = [val]
        return parts._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()

    for p in targets:
        orig = qs.get(p, [""])[0]
        notes = []
        # 1) SQL error-based: append a single quote
        try:
            st, bd = _get(build(p, orig + "'"))
            if any(sig in bd.lower() for sig in _SQL_ERRORS) and not any(sig in base_body.lower() for sig in _SQL_ERRORS):
                notes.append("SQLi: DB error surfaced on a single-quote payload (error-based)")
        except httpx.HTTPError:
            pass
        # 2) SQL boolean-diff: TRUE vs FALSE condition should differ from each other
        try:
            _, t_body = _get(build(p, orig + "' OR '1'='1"))
            _, f_body = _get(build(p, orig + "' AND '1'='2"))
            if abs(len(t_body) - len(f_body)) > max(40, 0.05 * base_len):
                notes.append("SQLi (blind): TRUE vs FALSE payloads gave materially different responses")
        except httpx.HTTPError:
            pass
        # 3) reflected XSS marker
        try:
            _, x_body = _get(build(p, _XSS_PAYLOAD))
            if _XSS_PAYLOAD in x_body:
                notes.append("XSS: payload reflected UN-encoded (angle brackets intact) — likely reflected XSS")
            elif _XSS_MARK in x_body:
                notes.append("reflection: marker echoed but encoded — check context, may still be exploitable")
        except httpx.HTTPError:
            pass
        if notes:
            findings.append(f"  [{p}] " + "; ".join(notes))

    if not findings:
        return (f"tested params {targets} on {parts.path} — no SQLi/XSS signal (error, boolean-diff, or "
                f"reflection). Try other params/forms, a different injection context, or OOB (oob_start).")
    return (f"test_injection on {parts.path} — likely-vulnerable params:\n" + "\n".join(findings) +
            "\nConfirm before reporting: reproduce the exact request, and for SQLi consider sqlmap; "
            "for XSS load it in the browser. Detection only — this did not exploit or exfiltrate.")


TOOLS = [
    Tool(
        name="crawl_site",
        description=("Native same-host crawler (no Docker): discovers endpoints, query params and forms by "
                     "following links. Use this for endpoint discovery when katana/crawl is unavailable, or "
                     "any time you need the real URL/param surface before testing."),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "depth": {"type": "integer"}, "max_pages": {"type": "integer"}},
            "required": ["url"]},
        fn=crawl_site,
    ),
    Tool(
        name="test_injection",
        description=("Detection-only SQLi + reflected-XSS test of a URL's query params (error-based, boolean "
                     "differential, reflected marker). Give a URL with a query string. Flags likely-vulnerable "
                     "params with evidence; non-destructive (no exploitation/exfiltration). Confirm before reporting."),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "param": {"type": "string", "description": "optional single param to focus on"}},
            "required": ["url"]},
        fn=test_injection,
    ),
]
