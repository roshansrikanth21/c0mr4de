"""Native web discovery + active injection testing - no Docker required.

Closes the gaps live runs exposed: without katana the agent couldn't find real
endpoints/params, it never tested an input, and when it did it tested ONE param
and stopped. So:

- crawl_site(url): BFS same-host crawler → endpoints, param-bearing URLs, forms.
- test_injection(url): DETECTION-ONLY probes on one URL's query params.
- test_all_params(url): crawl, then sweep test_injection across EVERY discovered
  param-bearing URL and form (GET query + POST body), aggregated. This is the
  thorough pass - it catches form-only params (e.g. a search box) that
  single-URL testing misses.

Non-destructive: single-quote error probe, boolean-diff, reflected-XSS marker.
No stacked queries, time-based blind, or exfiltration - it flags leads to confirm.
"""
from __future__ import annotations

import time
import urllib.parse
from collections import deque

import httpx

from c0mr4de.tools.base import Tool
from c0mr4de.tools.web import _request, extract_surface

_SQL_ERRORS = (
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg::syntaxerror", "psqlexception", "sqlite3.",
    "sqlstate", "odbc", "ora-01756", "ora-00933", "sql syntax", "mysql_fetch",
    "native client", "postgresql query failed",
)
_XSS_MARK = "c0mr4dexss7"
_XSS_PAYLOAD = f"<{_XSS_MARK}>"
# Must match browser.py's _XSS_EXEC_FLAG. Execution-confirmation tier (Google
# PageBreak's validator pattern): don't just check the payload got reflected,
# load it in a real browser and check the JS actually RAN.
_XSS_EXEC_FLAG = "__c0mr4de_xss_exec7"
_XSS_EXEC_PAYLOAD = f'"><img src=x onerror=window.{_XSS_EXEC_FLAG}=1>'
_STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico",
               ".woff", ".woff2", ".ttf", ".webp", ".pdf", ".mp4")
# Time-based blind SQLi: a conditional-sleep payload should delay the response by
# ~N seconds, reproducibly. This is PageBreak's SQLi validator pattern ("verifying
# the output and/or timing") - often the ONLY signal when errors are suppressed and
# boolean-diff is too noisy. Multi-engine, tried in order, first confirmed hit wins.
# 5s (not 3s, and sqlmap's own default) - a live re-verification against a real WAN
# target found natural latency jitter reaching 2.3s across just 20 requests, which
# left too little margin above a 3s sleep and produced a real false "CONFIRMED" on
# a page that was a plain 404. See _confirm_time_sqli's noise-floor fix below.
_SQLI_SLEEP_SECONDS = 5
_SQLI_TIME_PAYLOADS = (
    f"' OR SLEEP({_SQLI_SLEEP_SECONDS})-- -",             # MySQL / MariaDB
    f"'||pg_sleep({_SQLI_SLEEP_SECONDS})||'",             # PostgreSQL (string context)
    f"'; WAITFOR DELAY '0:0:{_SQLI_SLEEP_SECONDS}'-- ",   # MSSQL
)


def _sql_err(body: str) -> bool:
    low = (body or "").lower()
    return any(s in low for s in _SQL_ERRORS)


def _timed(send, val) -> float:
    t0 = time.time()
    send(val)
    return time.time() - t0


def _confirm_time_sqli(send, orig: str) -> str | None:
    """Deterministic time-based blind SQLi confirmation, noise-aware against real
    WAN/CDN latency jitter. A real external target (m1rage.amritacybernation.com)
    was measured naturally varying 0.5s-2.3s across 20 plain GET requests - a flat
    threshold alone produced a real false "CONFIRMED" on a page that was a plain
    404. Fix, mirroring the boolean-diff noise-floor fix: take TWO baseline samples
    to estimate this target's own natural latency ceiling, and require the payload
    delay to clearly exceed THAT (not just a flat fraction of the sleep duration)
    before even trying to reproduce it on a second trial."""
    try:
        baseline_max = max(_timed(send, orig), _timed(send, orig))
    except httpx.HTTPError:
        return None
    if baseline_max >= _SQLI_SLEEP_SECONDS * 0.7:
        return None  # endpoint is already slow/noisy - timing signal unreliable here
    threshold = max(_SQLI_SLEEP_SECONDS * 0.7, baseline_max * 2, baseline_max + 1.5)
    for payload in _SQLI_TIME_PAYLOADS:
        try:
            if _timed(send, orig + payload) < threshold:
                continue
            if _timed(send, orig + payload) >= threshold:   # reproduced -> confirmed
                return (f"SQLi (time-based) CONFIRMED: a conditional sleep payload consistently "
                        f"delayed the response by ~{_SQLI_SLEEP_SECONDS}s across 2 trials, clearly "
                        f"above this target's own natural latency ceiling of {baseline_max:.1f}s "
                        f"(deterministic timing proof, not a guess)")
        except httpx.HTTPError:
            continue
    return None


def _get(url: str) -> tuple[int, str]:
    r = _request(url)
    return r.status_code, r.text


def _get_with_type(url: str) -> tuple[int, str, str]:
    r = _request(url)
    return r.status_code, r.text, r.headers.get("content-type", "")


# Content-types a browser will NOT render as executable HTML - reflection into
# these is not directly exploitable as XSS regardless of whether it's escaped.
# Caught a real false positive on a JSON API that reflected the payload verbatim
# (valid, harmless JSON) and got reported as "likely reflected XSS".
_NON_HTML_TYPES = ("json", "text/plain", "/csv")


def _analyze(send, base_body: str, base_len: int, orig: str, exec_url=None, content_type: str = "") -> list[str]:
    """Run the detection probes via a `send(value) -> (status, body)` closure.
    Shared by GET-query and POST-form testing. `exec_url(payload) -> url`, when
    given, lets the XSS check escalate from string-reflection to a PageBreak-style
    execution-confirmed result (load it in a real browser, check the JS actually ran).
    `content_type` gates the XSS heuristic to responses a browser would actually
    render as HTML - a JSON/plain-text reflection is not exploitable the same way."""
    notes: list[str] = []
    sqli_confirmed = False
    try:
        _, bd = send(orig + "'")
        if _sql_err(bd) and not _sql_err(base_body):
            notes.append("SQLi: DB error on a single-quote payload (error-based)")
            sqli_confirmed = True
    except httpx.HTTPError:
        pass
    if not sqli_confirmed:
        try:
            # A second, UNMODIFIED baseline sample measures the page's natural
            # response-length variance (random content, timestamps, ads, ...) -
            # caught a real false positive on a page with randomized filler text
            # where TRUE/FALSE-payload noise alone exceeded the flat 40-char/5%
            # floor. The real diff must clearly exceed what naturally varies.
            _, base2_body = send(orig)
            noise = abs(len(base2_body) - base_len)
            _, t_body = send(orig + "' OR '1'='1")
            _, f_body = send(orig + "' AND '1'='2")
            diff = abs(len(t_body) - len(f_body))
            threshold = max(40, 0.05 * base_len, noise * 3)
            if diff > threshold:
                notes.append(f"SQLi (blind): TRUE vs FALSE payloads gave materially different responses "
                             f"(diff={diff} chars, well above the page's natural noise of {noise})")
                sqli_confirmed = True
        except httpx.HTTPError:
            pass
    if not sqli_confirmed:
        # Only pay the timing cost (can take several seconds) when the cheap checks
        # above found nothing - this is the last-resort but strongest SQLi signal.
        time_note = _confirm_time_sqli(send, orig)
        if time_note:
            notes.append(time_note)
    ctype_low = (content_type or "").lower()
    non_html = any(t in ctype_low for t in _NON_HTML_TYPES) and "html" not in ctype_low
    if not non_html:
        try:
            _, x_body = send(_XSS_PAYLOAD)
            reflected_raw = _XSS_PAYLOAD in x_body
            reflected_enc = (not reflected_raw) and (_XSS_MARK in x_body)
            if reflected_raw or reflected_enc:
                confirmed = False
                if exec_url is not None:
                    try:
                        from c0mr4de.tools.browser import confirm_xss_exec
                        confirmed = confirm_xss_exec(exec_url(_XSS_EXEC_PAYLOAD))
                    except Exception:  # noqa: BLE001 - Playwright missing, etc.
                        confirmed = False
                if confirmed:
                    notes.append("XSS CONFIRMED: payload EXECUTED in a real browser (deterministic proof, not a guess)")
                elif reflected_raw:
                    notes.append("XSS: payload reflected UN-encoded - likely reflected XSS (browser confirm inconclusive/unavailable)")
                else:
                    notes.append("reflection: marker echoed but encoded - check context")
        except httpx.HTTPError:
            pass
    return notes


# ── discovery ────────────────────────────────────────────────────────────────
def _crawl(url: str, depth: int, max_pages: int):
    """Return (pages_seen, endpoints:set, param_urls:set, forms:list). param_urls
    keep their query string so their params can be tested."""
    start = _request(url).url
    base = urllib.parse.urlparse(str(start)).netloc
    seen: set[str] = set()
    endpoints: set[str] = set()
    param_urls: set[str] = set()
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
        for pu in surf.get("param_urls", []):
            param_urls.add(pu)
        for f in surf["forms"]:
            if f not in forms:
                forms.append(f)
        for link in surf["links"]:
            p = urllib.parse.urlparse(link)
            if p.netloc and p.netloc != base:
                continue
            endpoints.add(link)
            if link not in seen:
                q.append((link, d + 1))
    return seen, endpoints, param_urls, forms


def crawl_site(url: str, depth: int = 2, max_pages: int = 40) -> str:
    """Spider a site (same host) via native HTTP: endpoints, param-bearing URLs, forms.
    The katana fallback - needs no Docker. Follow with test_all_params to test them."""
    try:
        seen, endpoints, param_urls, forms = _crawl(url, depth, max_pages)
    except PermissionError as exc:
        return f"BLOCKED: {exc}."
    except httpx.HTTPError as exc:
        return f"crawl error: {exc}"
    base = urllib.parse.urlparse(url).netloc
    out = [f"crawled {len(seen)} pages on {base} (depth {depth}). {len(endpoints)} endpoints:"]
    out += [f"  {e}" for e in sorted(endpoints)[:40]]
    if forms:
        out.append(f"forms ({len(forms)}):")
        out += [f"  {f['method']} {f['action']} inputs=[{','.join(f['inputs'])}]" for f in forms[:15]]
    if param_urls:
        out.append("URLs WITH params (prime targets - run test_all_params or test_injection):")
        out += [f"  {u}" for u in sorted(param_urls)[:15]]
    if not param_urls and not forms:
        out.append("no params or forms found yet - raise depth, or look at product/search/category pages.")
    else:
        out.append("TIP: test_all_params(url) will sweep every param + form above at once.")
    return "\n".join(out)


# ── testing ──────────────────────────────────────────────────────────────────
def _test_query_url(url: str, only: str = "") -> list[str]:
    """Test a GET URL's query params. Returns ['[param] note; note', ...]."""
    parts = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parts.query)
    if not qs:
        return []
    base_status, base_body, ctype = _get_with_type(url)
    if base_status in (404, 410):
        # The endpoint itself doesn't exist - testing it wastes requests and, for
        # the timing check, risks a phantom signal from WAN jitter on a page with
        # nothing behind it (caught exactly this on a real m1rage crawl: two "SQLi
        # CONFIRMED" results that were actually plain 404s).
        return []
    base_len = len(base_body)
    out = []
    for p in ([only] if only else list(qs)):
        if p not in qs:
            continue
        orig = qs.get(p, [""])[0]

        def build_url(val, _p=p):
            q = {k: v[:] for k, v in qs.items()}
            q[_p] = [val]
            return parts._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()

        def send(val):
            return _get(build_url(val))
        notes = _analyze(send, base_body, base_len, orig, exec_url=build_url, content_type=ctype)
        if notes:
            out.append(f"[{parts.path}?{p}] " + "; ".join(notes))
    return out


def _test_form(form: dict) -> list[str]:
    """Test a form's inputs (GET → query, POST → urlencoded body)."""
    action, method, inputs = form["action"], form.get("method", "GET").upper(), form["inputs"]
    if not inputs:
        return []
    baseline = {i: "test" for i in inputs}

    def send_base():
        if method == "POST":
            r = _request(action, "POST", {"Content-Type": "application/x-www-form-urlencoded"},
                         urllib.parse.urlencode(baseline))
        else:
            r = _request(action + ("&" if urllib.parse.urlparse(action).query else "?") + urllib.parse.urlencode(baseline))
        return r.status_code, r.text, r.headers.get("content-type", "")
    try:
        base_status, base_body, ctype = send_base()
    except (PermissionError, httpx.HTTPError):
        return []
    if base_status in (404, 410):
        return []  # the form's action target doesn't exist - see the matching note above
    base_len = len(base_body)
    out = []
    for p in inputs[:8]:
        def build_get_url(val, _p=p):
            data = dict(baseline)
            data[_p] = val
            return action + ("&" if urllib.parse.urlparse(action).query else "?") + urllib.parse.urlencode(data)

        def send(val, _p=p):
            data = dict(baseline)
            data[_p] = val
            if method == "POST":
                r = _request(action, "POST", {"Content-Type": "application/x-www-form-urlencoded"},
                             urllib.parse.urlencode(data))
            else:
                r = _request(build_get_url(val))
            return r.status_code, r.text
        # Browser-confirmation only makes sense for GET forms (a URL we can load);
        # POST forms stay string-reflection-only - documented limitation.
        notes = _analyze(send, base_body, base_len, "test",
                         exec_url=build_get_url if method == "GET" else None, content_type=ctype)
        if notes:
            out.append(f"[{method} {urllib.parse.urlparse(action).path}:{p}] " + "; ".join(notes))
    return out


def test_injection(url: str, param: str = "") -> str:
    """DETECTION-ONLY test of ONE URL's query params for SQLi + reflected XSS. Give a
    URL with a query string. For a whole site use test_all_params instead."""
    parts = urllib.parse.urlparse(url)
    if not parts.query:
        return ("no query params in that URL. Give one like /search?q=apple, or use "
                "test_all_params(url) to crawl + sweep every param and form automatically.")
    try:
        findings = _test_query_url(url, param)
    except PermissionError as exc:
        return f"BLOCKED: {exc}."
    except httpx.HTTPError as exc:
        return f"error: {exc}"
    if not findings:
        return (f"tested {parts.path} params - no SQLi/XSS signal. Try test_all_params for full coverage, "
                f"other contexts, or OOB (oob_start).")
    return "likely-vulnerable:\n  " + "\n  ".join(findings) + "\nConfirm before reporting (detection only)."


def test_all_params(url: str, depth: int = 2, max_targets: int = 30) -> str:
    """Crawl the site, then sweep injection tests across EVERY discovered param-bearing
    URL and form (GET + POST). The thorough pass - catches form-only params single-URL
    testing misses. Detection-only + non-destructive; bounded by max_targets."""
    try:
        seen, endpoints, param_urls, forms = _crawl(url, depth, max(20, max_targets))
    except PermissionError as exc:
        return f"BLOCKED: {exc}."
    except httpx.HTTPError as exc:
        return f"crawl error: {exc}"
    findings: list[str] = []
    tested = 0
    # Forms first - they're the highest-signal inputs (search boxes, logins) and there
    # are few of them; testing param-URLs first can burn the budget on junk asset links.
    for f in forms:
        if tested >= max_targets:
            break
        findings += _test_form(f)
        tested += 1
    # Then param-bearing URLs, skipping static assets (image/css/js ?v= cache-busters).
    for u in sorted(param_urls):
        if tested >= max_targets:
            break
        if urllib.parse.urlparse(u).path.lower().endswith(_STATIC_EXT):
            continue
        try:
            findings += _test_query_url(u)
        except (PermissionError, httpx.HTTPError):
            continue
        tested += 1
    header = (f"test_all_params: crawled {len(seen)} pages, swept {tested} targets "
              f"({len(param_urls)} param-URLs + {len(forms)} forms).")
    if not findings:
        return (header + " No SQLi/XSS signal on any param/form. Consider OOB (blind), POST JSON bodies, "
                "authenticated areas, or header injection.")
    uniq = list(dict.fromkeys(findings))
    return (header + f" LIKELY-VULNERABLE ({len(uniq)}):\n  " + "\n  ".join(uniq) +
            "\nConfirm each before reporting (detection only - no exploitation/exfiltration).")


TOOLS = [
    Tool(
        name="crawl_site",
        description=("Native same-host crawler (no Docker): endpoints, param-bearing URLs, forms. Use for "
                     "endpoint discovery when katana/crawl is unavailable, then test_all_params to test them."),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "depth": {"type": "integer"}, "max_pages": {"type": "integer"}},
            "required": ["url"]},
        fn=crawl_site,
    ),
    Tool(
        name="test_injection",
        description=("Detection-only SQLi + reflected-XSS test of ONE URL's query params. Give a URL with a "
                     "query string. XSS leads get a second-tier execution check in a real browser (loads the "
                     "payload, confirms the JS actually ran) when possible, so a CONFIRMED result is deterministic "
                     "proof, not a guess. Non-destructive; flags leads. For whole-site coverage use test_all_params."),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "param": {"type": "string", "description": "optional single param"}},
            "required": ["url"]},
        fn=test_injection,
    ),
    Tool(
        name="test_all_params",
        description=("Crawl a site and sweep injection tests across EVERY discovered param and form (GET query "
                     "+ POST body) in one call - the thorough pass that catches form-only params (e.g. a search "
                     "box) single-URL testing misses. Detection-only, non-destructive, bounded by max_targets."),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "depth": {"type": "integer"}, "max_targets": {"type": "integer"}},
            "required": ["url"]},
        fn=test_all_params,
    ),
]
