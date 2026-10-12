"""Deterministic finding verification - c0mr4de's sharpest job.

Hand it a concrete request (a raw HTTP request from Burp, or url+param) and a
CLAIM, and it re-derives the HARD signal for that claim and returns a blunt
verdict: CONFIRMED only when a deterministic check proved it, UNCONFIRMED
otherwise. It never upgrades a claim it cannot reproduce, and a response code or
a reflection alone is never a confirmation.

The verdict is decided by CODE on measured signals, not by any language model -
that is what makes it trustworthy on a weak local model. It reuses the proven
confirmation machinery the hunting tools already use:
  - _analyze / _confirm_time_sqli (webrecon): error / boolean / time SQLi with
    noise floors, and reflected-vs-executed XSS via a real browser.
  - interactsh OOB (oob): blind SSRF/RCE/XXE via a real server-side callback.
and adds what verification needs on top: targeted injection into any point of a
given request, a single-hop open-redirect check, a cross-account IDOR
differential, and JWT signature-verification testing.
"""
from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass, field

import httpx


# These are imported LAZILY (inside thin wrappers) to avoid a circular import:
# c0mr4de.tools.__init__ registers the verify_finding tool, which imports this
# module, so this module must not import c0mr4de.tools at load time. At call time
# everything is fully initialized.
def _request(*args, **kwargs):
    from c0mr4de.tools.web import _request as fn
    return fn(*args, **kwargs)


def _scope_auth(*args, **kwargs):
    from c0mr4de.tools.web import _scope_auth as fn
    return fn(*args, **kwargs)


def _analyze(*args, **kwargs):
    from c0mr4de.tools.webrecon import _analyze as fn
    return fn(*args, **kwargs)


CLAIMS = ("auto", "sqli", "xss", "ssrf", "open_redirect", "idor", "jwt")

# --- verdict ----------------------------------------------------------------


@dataclass
class Verdict:
    verdict: str                       # CONFIRMED | UNCONFIRMED | INCONCLUSIVE | ERROR
    claim: str
    technique: str = ""
    evidence: list[str] = field(default_factory=list)
    reproduction: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "claim": self.claim, "technique": self.technique,
                "evidence": self.evidence, "reproduction": self.reproduction, "detail": self.detail}

    def to_text(self) -> str:
        icon = {"CONFIRMED": "[CONFIRMED]", "UNCONFIRMED": "[UNCONFIRMED]",
                "INCONCLUSIVE": "[INCONCLUSIVE]", "ERROR": "[ERROR]"}.get(self.verdict, "[?]")
        out = [f"{icon} claim: {self.claim}" + (f"  technique: {self.technique}" if self.technique else "")]
        if self.detail:
            out.append(self.detail)
        if self.evidence:
            out.append("evidence:")
            out += [f"  - {e}" for e in self.evidence]
        if self.reproduction:
            out.append("reproduce:\n" + self.reproduction)
        if self.verdict != "CONFIRMED":
            out.append("NOTE: not confirmed - do NOT report this as a vulnerability on this evidence alone.")
        return "\n".join(out)


# --- request parsing + injection -------------------------------------------


def parse_http_request(raw: str, base_scheme: str = "https") -> dict:
    """Parse a raw HTTP request (Burp 'Copy to file' style) into
    {method, url, headers, body}. The path may be absolute or combined with the
    Host header. Raises ValueError on anything it cannot turn into a real URL."""
    text = (raw or "").replace("\r\n", "\n").strip("\n")
    if not text:
        raise ValueError("empty request")
    lines = text.split("\n")
    first = lines[0].split()
    if len(first) < 2:
        raise ValueError("first line must be: METHOD PATH [HTTP/1.1]")
    method, target = first[0].upper(), first[1]
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i + 1:]).strip("\n") if i + 1 <= len(lines) else ""
    if target.startswith(("http://", "https://")):
        url = target
    else:
        host = headers.get("Host") or headers.get("host")
        if not host:
            raise ValueError("relative path but no Host header - cannot build a URL")
        url = f"{base_scheme}://{host}{target}"
    return {"method": method, "url": url, "headers": headers, "body": body}


def _fwd_headers(headers: dict) -> dict:
    """Headers safe to forward: httpx manages Host/Content-Length itself, and a
    stale one causes mismatches."""
    return {k: v for k, v in (headers or {}).items() if k.lower() not in ("host", "content-length")}


def _is_json_body(body: str) -> bool:
    try:
        return isinstance(json.loads(body), dict)
    except Exception:  # noqa: BLE001
        return False


def _locate(request: dict, point: str) -> tuple[str, str]:
    """Resolve where a named injection point lives. Explicit prefixes
    (query:/body:/json:/header:) win; otherwise auto-detect across query, body
    (form or JSON), then headers. Returns (kind, name)."""
    url, headers, body = request["url"], request["headers"], request["body"]
    for pre, kind in (("query:", "query"), ("body:", "body"), ("json:", "json"), ("header:", "header")):
        if point.startswith(pre):
            return kind, point[len(pre):]
    name = point
    if name in urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True):
        return "query", name
    if body and _is_json_body(body) and name in json.loads(body):
        return "json", name
    if body and name in urllib.parse.parse_qs(body, keep_blank_values=True):
        return "body", name
    if any(k.lower() == name.lower() for k in headers):
        return "header", name
    raise ValueError(f"injection point '{name}' not found in the request's query, body, or headers")


def _builder(request: dict, kind: str, name: str, requester=_request):
    """Return (raw_send, exec_url, orig): raw_send(value) -> httpx.Response with
    `value` placed at the located point, exec_url(value) -> a loadable URL (only
    for a GET query point, else None), and the point's original value."""
    method, url = request["method"], request["url"]
    fwd, body = _fwd_headers(request["headers"]), request["body"]

    if kind == "query":
        p = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        orig = q.get(name, [""])[0]

        def build(val, _q=q, _p=p):
            qq = {k: v[:] for k, v in _q.items()}
            qq[name] = [val]
            return _p._replace(query=urllib.parse.urlencode(qq, doseq=True)).geturl()

        def raw_send(val):
            return requester(build(val), method, dict(fwd), body)
        exec_url = (lambda val: build(val)) if method == "GET" else None
        return raw_send, exec_url, orig

    if kind == "body":
        q = urllib.parse.parse_qs(body, keep_blank_values=True)
        orig = q.get(name, [""])[0]

        def raw_send(val, _q=q):
            qq = {k: v[:] for k, v in _q.items()}
            qq[name] = [val]
            h = dict(fwd)
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return requester(url, method, h, urllib.parse.urlencode(qq, doseq=True))
        return raw_send, None, orig

    if kind == "json":
        obj = json.loads(body)
        orig = obj.get(name, "")

        def raw_send(val, _obj=obj):
            o = dict(_obj)
            o[name] = val
            h = dict(fwd)
            h.setdefault("Content-Type", "application/json")
            return requester(url, method, h, json.dumps(o))
        return raw_send, None, str(orig)

    # header
    orig = next((v for k, v in request["headers"].items() if k.lower() == name.lower()), "")

    def raw_send(val):
        h = {k: v for k, v in fwd.items() if k.lower() != name.lower()}
        h[name] = val
        return requester(url, method, h, body)
    return raw_send, None, orig


# --- curl reproduction ------------------------------------------------------


def _curl(method: str, url: str, headers: dict, body: str = "") -> str:
    import shlex
    parts = [f"curl -i -s -X {method} {shlex.quote(url)}"]
    for k, v in _fwd_headers(headers).items():
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if body:
        parts.append(f"--data {shlex.quote(body)}")
    return "  \\\n    ".join(parts)


# --- confirmation classification -------------------------------------------


def _confirmed_class(note: str) -> str | None:
    """Map an _analyze note to the vuln class it DETERMINISTICALLY confirms, or
    None if it is only a lead (e.g. reflected-but-not-executed XSS)."""
    low = note.lower()
    if "xss confirmed" in low:
        return "xss"
    if "sqli" in low and ("confirmed" in low or "db error on a single-quote" in low
                          or "materially different" in low):
        return "sqli"
    return None


_SQLI_REPRO_PAYLOAD = "' OR SLEEP(5)-- -"
_XSS_REPRO_PAYLOAD = '"><img src=x onerror=alert(1)>'


# --- individual verifiers ---------------------------------------------------


def _verify_injection(request: dict, point: str, claim: str) -> Verdict:
    """SQLi / XSS, reusing the proven _analyze engine on one targeted point."""
    kind, name = _locate(request, point)
    raw_send, exec_url, orig = _builder(request, kind, name)

    def send(val):
        r = raw_send(val)
        return r.status_code, r.text
    try:
        rb = raw_send(orig)
    except httpx.HTTPError as exc:
        return Verdict("ERROR", claim, detail=f"baseline request failed: {exc}")
    base_body, base_len = rb.text, len(rb.text)
    ctype = rb.headers.get("content-type", "")
    notes = _analyze(send, base_body, base_len, orig, exec_url=exec_url, content_type=ctype)

    confirmed = {c for n in notes if (c := _confirmed_class(n))}
    want = claim if claim in ("sqli", "xss") else None
    hit = (want in confirmed) if want else bool(confirmed)
    confirming = [n for n in notes if _confirmed_class(n) and (not want or _confirmed_class(n) == want)]
    leads = [n for n in notes if not _confirmed_class(n)]

    if hit:
        cls = want or next(iter(confirmed))
        payload = _XSS_REPRO_PAYLOAD if cls == "xss" else _SQLI_REPRO_PAYLOAD
        return Verdict(
            "CONFIRMED", claim or cls, technique=cls,
            evidence=confirming + ([f"(other signals: {'; '.join(leads)})"] if leads else []),
            reproduction=_repro_for(request, kind, name, payload),
            detail=f"Deterministically confirmed {cls.upper()} at {kind} param '{name}'.",
        )
    detail = (f"No deterministic {claim} signal at {kind} param '{name}'."
              if want else f"No deterministic SQLi/XSS signal at {kind} param '{name}'.")
    return Verdict("UNCONFIRMED", claim, evidence=leads, detail=detail)


def _repro_for(request: dict, kind: str, name: str, payload: str) -> str:
    """Build a curl that injects `payload` at the located point."""
    method, url = request["method"], request["url"]
    headers, body = request["headers"], request["body"]
    if kind == "query":
        p = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        q[name] = [payload]
        url = p._replace(query=urllib.parse.urlencode(q, doseq=True)).geturl()
        return _curl(method, url, headers, body)
    if kind == "body":
        q = urllib.parse.parse_qs(body, keep_blank_values=True)
        q[name] = [payload]
        return _curl(method, url, {**headers, "Content-Type": "application/x-www-form-urlencoded"},
                     urllib.parse.urlencode(q, doseq=True))
    if kind == "json":
        obj = json.loads(body)
        obj[name] = payload
        return _curl(method, url, {**headers, "Content-Type": "application/json"}, json.dumps(obj))
    hdrs = dict(headers)
    hdrs[name] = payload
    return _curl(method, url, hdrs, body)


def _verify_open_redirect(request: dict, point: str) -> Verdict:
    """Single-hop check: inject an attacker-controlled external URL and confirm
    only if the response redirects (3xx Location, or a meta/JS refresh) to THAT
    external host. Following is disabled so the off-host Location is observable
    and scope-safe."""
    kind, name = _locate(request, point)

    def no_follow(url, method, hdrs, body=""):
        from c0mr4de import scope
        if scope.check(url) == "out":
            raise PermissionError(f"{url} is OUT OF SCOPE")
        req_hdrs, _ = _scope_auth(url, dict(hdrs or {}))
        return httpx.request(method.upper(), url, headers=req_hdrs, content=body or None,
                             timeout=20, follow_redirects=False)

    raw_send, _, orig = _builder(request, kind, name, requester=no_follow)
    sentinel = "c0mr4de-redirect.example.net"
    payloads = [f"https://{sentinel}/", f"//{sentinel}/", f"https:/{sentinel}/", f"/\\{sentinel}/"]
    for pl in payloads:
        try:
            r = raw_send(pl)
        except (httpx.HTTPError, PermissionError):
            continue
        loc = r.headers.get("location", "")
        if loc and urllib.parse.urlparse(loc if "//" in loc else "//" + loc).hostname == sentinel:
            return Verdict(
                "CONFIRMED", "open_redirect", technique="external Location redirect",
                evidence=[f"payload {pl!r} -> HTTP {r.status_code}, Location: {loc}",
                          f"the server redirected to the attacker-controlled host '{sentinel}'"],
                reproduction=_repro_for(request, kind, name, payloads[0]),
                detail=f"Confirmed open redirect at {kind} param '{name}'.")
    return Verdict("UNCONFIRMED", "open_redirect",
                   detail=f"No external redirect from {kind} param '{name}' (Location stayed on-host or absent).")


def _verify_oob(request: dict, point: str, kind_claim: str = "ssrf", wait: float = 12.0) -> Verdict:
    """Blind SSRF/RCE/XXE via a real interactsh callback. CONFIRMED only if the
    target's server calls back to our unique OOB domain after we inject it."""
    from c0mr4de.tools import oob
    start = oob.oob_start()
    domain = oob._state.get("domain")
    if not domain:
        return Verdict("INCONCLUSIVE", kind_claim, technique="OOB",
                       detail="OOB client unavailable (interactsh not installed/reachable), "
                              "so a blind callback cannot be tested here. " + start)
    before = len(oob._state.get("interactions", []))
    kind, name = _locate(request, point)
    raw_send, _, _ = _builder(request, kind, name)
    payload = f"http://{domain}/c0mr4de"
    try:
        raw_send(payload)
    except (httpx.HTTPError, PermissionError) as exc:
        return Verdict("ERROR", kind_claim, detail=f"could not send OOB payload: {exc}")
    deadline = time.time() + wait
    while time.time() < deadline:
        if len(oob._state.get("interactions", [])) > before:
            hits = oob._state["interactions"][before:]
            protos = ", ".join(sorted({h.get("protocol", "?").upper() for h in hits}))
            srcs = ", ".join(sorted({h.get("source", "?") for h in hits}))
            return Verdict(
                "CONFIRMED", kind_claim, technique="out-of-band callback",
                evidence=[f"injected {payload} into {kind} param '{name}'",
                          f"{len(hits)} callback(s) to {domain} ({protos}) from {srcs}"],
                reproduction=_repro_for(request, kind, name, payload),
                detail=f"Confirmed blind {kind_claim} - the target's server called back out-of-band.")
        time.sleep(1.0)
    return Verdict("UNCONFIRMED", kind_claim, technique="OOB",
                   detail=f"No callback to {domain} within {wait:.0f}s after injecting it into "
                          f"'{name}'. Not confirmed (the server may not be reachable outbound, or not vulnerable).")


def _record_like(status: int, body: str) -> bool:
    """A 2xx response that looks like actual data, not a login/error/empty page."""
    if not (200 <= status < 300):
        return False
    low = (body or "").lower()
    if len(body) < 8:
        return False
    deny = ("sign in", "log in", "login", "unauthorized", "access denied", "forbidden",
            "not found", "error", "please authenticate")
    return not any(d in low for d in deny)


def _verify_access_control(request: dict, control_request: dict | None) -> Verdict:
    """IDOR / BOLA. A true confirmation needs TWO requests under YOUR session:
    one for your own object (control) and one for another user's object (target).
    CONFIRMED only if both return record-like 2xx bodies that materially DIFFER -
    i.e. changing the id fetched a different record you should not reach. Without
    the control request it stays INCONCLUSIVE, because a lone 200 cannot prove the
    object is not your own."""
    try:
        tr = _request(request["url"], request["method"], _fwd_headers(request["headers"]), request["body"])
    except (httpx.HTTPError, PermissionError) as exc:
        return Verdict("ERROR", "idor", detail=f"target request failed: {exc}")
    if not _record_like(tr.status_code, tr.text):
        return Verdict("UNCONFIRMED", "idor", technique="object access",
                       evidence=[f"target returned HTTP {tr.status_code}, {len(tr.text)} bytes "
                                 f"(not a record-like success)"],
                       detail="The targeted object was not accessible, so there is no IDOR to confirm.")
    if control_request is None:
        return Verdict(
            "INCONCLUSIVE", "idor", technique="object access",
            evidence=[f"target object returned HTTP {tr.status_code}, {len(tr.text)} bytes (record-like)"],
            detail="The object is accessible under this session, but a lone 200 cannot prove it is another "
                   "user's object rather than your own. Provide a control request (the SAME endpoint with "
                   "YOUR own id) so I can confirm the ids return DIFFERENT records.")
    try:
        cr = _request(control_request["url"], control_request["method"],
                      _fwd_headers(control_request["headers"]), control_request["body"])
    except (httpx.HTTPError, PermissionError) as exc:
        return Verdict("ERROR", "idor", detail=f"control request failed: {exc}")
    if not _record_like(cr.status_code, cr.text):
        return Verdict("INCONCLUSIVE", "idor",
                       evidence=[f"control returned HTTP {cr.status_code} (not record-like)"],
                       detail="Control (your own object) did not return a record, so the differential is "
                              "inconclusive. Check the control request.")
    if tr.text == cr.text:
        return Verdict("UNCONFIRMED", "idor", technique="object differential",
                       evidence=["target and control returned IDENTICAL bodies"],
                       detail="Both ids returned the same record - the target is likely your own object "
                              "(or a shared/empty resource), not an IDOR.")
    return Verdict(
        "CONFIRMED", "idor", technique="cross-object differential",
        evidence=[f"your object: HTTP {cr.status_code}, {len(cr.text)} bytes",
                  f"other object: HTTP {tr.status_code}, {len(tr.text)} bytes",
                  "both are record-like and the bodies DIFFER - changing the id returned a different record"],
        reproduction=_curl(request["method"], request["url"], request["headers"], request["body"]),
        detail="Confirmed IDOR/BOLA: your session can read another object's record by changing the id.")


def _find_jwt(request: dict) -> str | None:
    import re
    auth = next((v for k, v in request["headers"].items() if k.lower() == "authorization"), "")
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", auth)
    if m:
        return m.group(0)
    cookie = next((v for k, v in request["headers"].items() if k.lower() == "cookie"), "")
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", cookie)
    return m.group(0) if m else None


def _replace_token(request: dict, old: str, new: str) -> dict:
    r = {"method": request["method"], "url": request["url"], "body": request["body"],
         "headers": {k: v.replace(old, new) for k, v in request["headers"].items()}}
    return r


def _verify_jwt(request: dict, field_name: str, value: str) -> Verdict:
    """Test whether the server actually verifies the JWT signature. Sends three
    variants and decides in code:
      - original token            -> must be accepted (2xx), else not a valid baseline
      - corrupted-signature token -> SHOULD be rejected (proves it checks the sig)
      - tampered-payload token (field changed, ORIGINAL signature kept)
    CONFIRMED when the tampered-payload token is ACCEPTED while the corrupted one
    is REJECTED - the server does not bind the signature to the payload."""
    from c0mr4de.tools.web import tamper_jwt
    token = _find_jwt(request)
    if not token:
        return Verdict("ERROR", "jwt", detail="no JWT found in Authorization header or Cookie.")

    def status_of(req: dict) -> int:
        r = _request(req["url"], req["method"], _fwd_headers(req["headers"]), req["body"])
        return r.status_code

    try:
        orig_status = status_of(request)
    except (httpx.HTTPError, PermissionError) as exc:
        return Verdict("ERROR", "jwt", detail=f"baseline request failed: {exc}")
    if not (200 <= orig_status < 300):
        return Verdict("INCONCLUSIVE", "jwt",
                       evidence=[f"original token gave HTTP {orig_status}"],
                       detail="The original token was not accepted (non-2xx), so there is no authenticated "
                              "baseline to test signature verification against.")
    # corrupted signature: flip the signature segment
    parts = token.split(".")
    corrupt = f"{parts[0]}.{parts[1]}.{'A' * max(10, len(parts[2]) if len(parts) > 2 else 16)}"
    corrupt_status = status_of(_replace_token(request, token, corrupt))
    # tampered payload, original signature kept
    tampered_out = tamper_jwt(token, field_name, value)
    if tampered_out.startswith("ERROR"):
        return Verdict("ERROR", "jwt", detail=tampered_out)
    tampered = tampered_out.split("\n")[1].strip() if "\n" in tampered_out else ""
    import re
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", tampered_out)
    tampered = m.group(0) if m else tampered
    tampered_status = status_of(_replace_token(request, token, tampered))

    accepted = lambda s: 200 <= s < 300
    if not accepted(corrupt_status) and accepted(tampered_status):
        return Verdict(
            "CONFIRMED", "jwt", technique="signature not verified",
            evidence=[f"original token: HTTP {orig_status} (accepted)",
                      f"corrupted-signature token: HTTP {corrupt_status} (rejected - server does check the sig)",
                      f"tampered payload ({field_name}={value}) with ORIGINAL signature: HTTP {tampered_status} (accepted)"],
            reproduction=_curl(request["method"], request["url"],
                               _replace_token(request, token, tampered)["headers"], request["body"]),
            detail="Confirmed: the server accepts a token whose payload was changed but whose signature was "
                   "not recomputed. The signature is not bound to the payload - privilege/claim tampering is possible.")
    if accepted(corrupt_status):
        return Verdict("INCONCLUSIVE", "jwt",
                       evidence=[f"corrupted-signature token was also accepted (HTTP {corrupt_status})"],
                       detail="The endpoint accepts even a garbage signature, so it likely does not validate the "
                              "token at all (a different, possibly worse issue) rather than a payload-binding flaw. "
                              "Test the endpoint's auth directly.")
    return Verdict("UNCONFIRMED", "jwt", technique="signature verification",
                   evidence=[f"tampered-payload token was rejected (HTTP {tampered_status})"],
                   detail="The server rejected the token after its payload was changed - the signature IS verified. "
                          "No JWT tampering flaw on this field.")


# --- dispatcher -------------------------------------------------------------


def verify(claim: str, request: dict, point: str = "", control_request: dict | None = None,
           field_name: str = "", value: str = "") -> Verdict:
    """Route a claim to its deterministic verifier."""
    claim = (claim or "auto").lower()
    if claim not in CLAIMS:
        return Verdict("ERROR", claim, detail=f"unknown claim '{claim}'. One of: {', '.join(CLAIMS)}")
    try:
        if claim in ("sqli", "xss", "auto"):
            if not point:
                return Verdict("ERROR", claim, detail="this claim needs an injection point (param/header name).")
            return _verify_injection(request, point, claim)
        if claim == "open_redirect":
            if not point:
                return Verdict("ERROR", claim, detail="open_redirect needs the redirect param name as point.")
            return _verify_open_redirect(request, point)
        if claim == "ssrf":
            if not point:
                return Verdict("ERROR", claim, detail="ssrf needs the injection point (the URL/host param).")
            return _verify_oob(request, point, "ssrf")
        if claim == "idor":
            return _verify_access_control(request, control_request)
        if claim == "jwt":
            if not field_name:
                return Verdict("ERROR", claim, detail="jwt needs field_name (and value) to tamper, e.g. role=admin.")
            return _verify_jwt(request, field_name, value)
    except ValueError as exc:
        return Verdict("ERROR", claim, detail=str(exc))
    except PermissionError as exc:
        return Verdict("ERROR", claim, detail=f"blocked by scope: {exc}")
    return Verdict("ERROR", claim, detail="no verifier matched")
