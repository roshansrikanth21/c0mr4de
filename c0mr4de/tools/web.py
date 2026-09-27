"""Web-layer tools: raw HTTP requests, sqlmap, nikto, and a JWT
decode/tamper helper - the exact primitive that found the Haveloc
payment-gate bypass (see playbooks/jwt-client-side-bypass.md)."""
from __future__ import annotations

import base64
import json
import re
import shlex
import urllib.parse

import httpx

from c0mr4de import auth
from c0mr4de.tools.base import Tool
from c0mr4de.tools.recon import _run_in_kali

# Headers worth showing; everything else (esp. giant Set-Cookie/AWSALB blobs) is noise
# that used to drown the actual page content in the tool result.
_KEEP_HEADERS = ("content-type", "server", "location", "x-powered-by", "www-authenticate",
                 "content-length", "content-security-policy", "access-control-allow-origin")
_LINK_RE = re.compile(r"""(?:href|action|src)\s*=\s*["']([^"'#>]+)""", re.I)
_FORM_RE = re.compile(r"(?is)<form\b[^>]*>.*?</form>")
_ACTION_RE = re.compile(r"""(?is)\baction\s*=\s*["']([^"']*)""")
_METHOD_RE = re.compile(r"""(?is)\bmethod\s*=\s*["']([^"']*)""")
_INPUT_RE = re.compile(r"""(?is)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)""")


def _scope_auth(url: str, hdrs: dict) -> tuple[dict, bool]:
    """Merge operator session auth for this host. Agent headers win; a stored
    Cookie is added only when absent. Returns (headers, authed)."""
    a = auth.for_url(url)
    authed = False
    if a:
        for k, v in a.get("headers", {}).items():
            hdrs.setdefault(k, v)
        if a.get("cookie") and not any(k.lower() == "cookie" for k in hdrs):
            hdrs["Cookie"] = a["cookie"]
        authed = bool(a.get("headers")) or bool(a.get("cookie"))
    return hdrs, authed


def _request(url: str, method: str = "GET", hdrs: dict | None = None, body: str = "") -> httpx.Response:
    """Low-level request with scope + auth applied. Raises on scope block / HTTP error.
    Shared by http_request, the crawler, and the injection tester."""
    from c0mr4de import scope
    if scope.check(url) == "out":
        raise PermissionError(f"{url} is OUT OF SCOPE per the rules of engagement")
    hdrs, _ = _scope_auth(url, dict(hdrs or {}))
    return httpx.request(method.upper(), url, headers=hdrs, content=body or None,
                         timeout=20, follow_redirects=True)


def extract_surface(html: str, base_url: str, same_host_only: bool = True) -> dict:
    """Pull the testable surface out of an HTML body: same-host links, the query
    params seen on them, and forms (action/method/inputs). This is what lets the
    agent FOLLOW a page instead of guessing paths."""
    base = urllib.parse.urlparse(base_url)
    links, params, forms = set(), set(), []
    for raw in _LINK_RE.findall(html or ""):
        if raw.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        u = urllib.parse.urljoin(base_url, raw)
        p = urllib.parse.urlparse(u)
        if same_host_only and p.netloc and p.netloc != base.netloc:
            continue
        links.add(p._replace(query="", fragment="").geturl())
        for k in urllib.parse.parse_qs(p.query):
            params.add(k)
    for fhtml in _FORM_RE.findall(html or ""):
        am = _ACTION_RE.search(fhtml)
        mm = _METHOD_RE.search(fhtml)
        inputs = _INPUT_RE.findall(fhtml)
        forms.append({"action": urllib.parse.urljoin(base_url, am.group(1)) if am else base_url,
                      "method": (mm.group(1).upper() if mm else "GET"), "inputs": inputs})
        params.update(inputs)
    return {"links": sorted(links), "params": sorted(params), "forms": forms}


def http_request(url: str, method: str = "GET", headers: str = "{}", body: str = "") -> str:
    try:
        hdrs = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        return "ERROR: headers must be a JSON object string, e.g. '{\"Cookie\": \"a=b\"}'"
    try:
        resp = _request(url, method, hdrs, body)
    except PermissionError as exc:
        return f"BLOCKED: {exc}. Do not test it."
    except httpx.HTTPError as exc:
        return f"REQUEST ERROR: {exc}"
    _, authed = _scope_auth(url, dict(hdrs))
    kept = {k: v for k, v in resp.headers.items() if k.lower() in _KEEP_HEADERS}
    cookie_names = [c.split("=", 1)[0].strip() for c in resp.headers.get_list("set-cookie")]
    out = [f"status: {resp.status_code}{'  [authenticated session]' if authed else ''}",
           f"headers: {kept}"]
    if cookie_names:
        out.append(f"set-cookie: {', '.join(cookie_names)} (values hidden)")
    ctype = resp.headers.get("content-type", "")
    if "html" in ctype:
        surf = extract_surface(resp.text, str(resp.url))
        if surf["links"]:
            out.append(f"links ({len(surf['links'])}): " + ", ".join(surf["links"][:20]))
        if surf["forms"]:
            out.append("forms: " + "; ".join(
                f"{f['method']} {f['action']} inputs=[{','.join(f['inputs'])}]" for f in surf["forms"][:6]))
        if surf["params"]:
            out.append(f"params seen: {', '.join(surf['params'][:20])}  <- test these (test_injection)")
    out.append(f"body (first 2000 chars):\n{resp.text[:2000]}")
    return "\n".join(out)


def decode_jwt(token: str) -> str:
    """Decode (not verify) a JWT's header and payload. Mirrors step 1 of
    the Haveloc audit: always look at what's actually inside the token
    before assuming it's opaque/secure."""
    parts = token.split(".")
    if len(parts) < 2:
        return "ERROR: not a JWT (expected header.payload.signature)"

    def _pad_decode(segment: str) -> str:
        padded = segment + "=" * (-len(segment) % 4)
        try:
            return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return f"<decode error: {exc}>"

    header = _pad_decode(parts[0])
    payload = _pad_decode(parts[1])
    has_sig = len(parts) == 3 and bool(parts[2])
    return (
        f"header: {header}\n"
        f"payload: {payload}\n"
        f"has signature segment: {has_sig}\n"
        f"NOTE: this only decodes - it does not tell you if the server verifies the signature. "
        f"Test that by modifying the payload and replaying the token (see playbook)."
    )


def tamper_jwt(token: str, field: str, value: str) -> str:
    """Modify one field in a JWT's payload and re-emit the token, keeping
    the ORIGINAL signature segment. This is the exact primitive for testing
    whether a server verifies signatures: if a token with a changed payload
    but stale signature is still accepted, the server isn't verifying. Pass
    the result to http_request as the Bearer token and replay it."""
    parts = token.split(".")
    if len(parts) != 3:
        return "ERROR: not a standard JWT (expected header.payload.signature)"
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad))
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: could not decode payload: {exc}"
    # coerce common boolean/number-looking values so acs="Active" vs paid=true both work
    coerced: object = value
    if value.lower() in ("true", "false"):
        coerced = value.lower() == "true"
    elif value.lstrip("-").isdigit():
        coerced = int(value)
    payload[field] = coerced
    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
    return (
        f"tampered token (payload {field}={coerced!r}, original signature kept):\n{tampered}\n"
        f"Now replay it: http_request to the protected endpoint with header "
        f'{{"Authorization": "Bearer {tampered}"}} and compare the response to the untampered request.'
    )


def sqlmap(url: str, extra_flags: str = "--batch --level=2") -> str:
    return _run_in_kali(f"sqlmap -u {shlex.quote(url)} {extra_flags}")


def nikto(url: str) -> str:
    return _run_in_kali(f"nikto -h {shlex.quote(url)}")


TOOLS = [
    Tool(
        name="http_request",
        description="Make a raw HTTP request. Use this to test IDOR, auth bypass, tampered tokens/cookies, etc.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "description": "GET, POST, PUT, DELETE, ..."},
                "headers": {"type": "string", "description": "JSON object as a string, e.g. '{\"Cookie\": \"session=abc\"}'"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
        fn=http_request,
    ),
    Tool(
        name="decode_jwt",
        description="Decode a JWT's header and payload without verifying it. Always run this on any token you find before assuming it's secure.",
        parameters={"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]},
        fn=decode_jwt,
    ),
    Tool(
        name="tamper_jwt",
        description=(
            "Change one field in a JWT payload and get back a tampered token (original signature kept). "
            "Use this to test whether a server verifies signatures - flip a status/role/payment field, "
            "then replay the returned token with http_request. Do NOT hand-write JWT crypto code; use this."
        ),
        parameters={
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "field": {"type": "string", "description": "payload field to change, e.g. acs, role, paid"},
                "value": {"type": "string", "description": "new value, e.g. Active, admin, true"},
            },
            "required": ["token", "field", "value"],
        },
        fn=tamper_jwt,
    ),
]

# These shell out to the kali-mcp Docker image, so they're only registered
# when Docker is available (see tools/__init__.py) - same as the recon tools.
DOCKER_TOOLS = [
    Tool(
        name="sqlmap",
        description="Test a URL for SQL injection.",
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}, "extra_flags": {"type": "string"}},
            "required": ["url"],
        },
        fn=sqlmap,
    ),
    Tool(
        name="nikto",
        description="Run a general web-server vulnerability scan.",
        parameters={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        fn=nikto,
    ),
]
