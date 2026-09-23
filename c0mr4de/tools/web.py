"""Web-layer tools: raw HTTP requests, sqlmap, nikto, and a JWT
decode/tamper helper - the exact primitive that found the Haveloc
payment-gate bypass (see playbooks/jwt-client-side-bypass.md)."""
from __future__ import annotations

import base64
import json
import shlex

import httpx

from c0mr4de.tools.base import Tool
from c0mr4de.tools.recon import _run_in_kali


def http_request(url: str, method: str = "GET", headers: str = "{}", body: str = "") -> str:
    try:
        hdrs = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        return "ERROR: headers must be a JSON object string, e.g. '{\"Cookie\": \"a=b\"}'"
    try:
        resp = httpx.request(method.upper(), url, headers=hdrs, content=body or None, timeout=20, follow_redirects=True)
    except httpx.HTTPError as exc:
        return f"REQUEST ERROR: {exc}"
    body_preview = resp.text[:3000]
    return (
        f"status: {resp.status_code}\n"
        f"headers: {dict(resp.headers)}\n"
        f"body (first 3000 chars):\n{body_preview}"
    )


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
