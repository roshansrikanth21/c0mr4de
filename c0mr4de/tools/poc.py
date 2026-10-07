"""Auto-PoC: turn a CONFIRMED finding into a copy-pasteable, reproducible curl command.

Strix and Vulnhuntr both attach a working PoC to every finding; this does the same
for c0mr4de. The agent calls make_poc for a finding it actually confirmed, then puts
the result in that finding's proof_of_concept so write_report ships a reproducible
PoC. Only make a PoC for a verified finding - a PoC for an unconfirmed guess is worse
than none."""
from __future__ import annotations

import json
import shlex
import urllib.parse

from c0mr4de.tools.base import Tool


def make_poc(url: str, method: str = "GET", param: str = "", payload: str = "",
             headers: str = "{}", body: str = "", observe: str = "") -> str:
    """Generate a copy-pasteable curl PoC that reproduces a confirmed finding.

    url: the target URL. method: GET/POST/etc. param+payload: if given and the request
    is query-based, the payload is injected into that query parameter; otherwise pass
    the already-built body. headers: JSON object of extra headers (e.g. auth/cookie).
    observe: the confirming signal to look for. Returns the curl command + what to watch."""
    method = (method or "GET").upper()
    final_url = url
    if param and payload and (not body):
        parts = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        q[param] = payload
        final_url = parts._replace(query=urllib.parse.urlencode(q)).geturl()

    cmd = ["curl", "-i", "-s"]
    if method not in ("GET",):
        cmd += ["-X", method]
    try:
        hdrs = json.loads(headers) if headers else {}
    except (json.JSONDecodeError, TypeError):
        hdrs = {}
    for k, v in hdrs.items():
        cmd += ["-H", f"{k}: {v}"]
    if body:
        cmd += ["--data", body]
    elif param and payload and method in ("POST", "PUT", "PATCH"):
        cmd += ["--data", f"{param}={payload}"]
    cmd.append(final_url)

    curl = " ".join(shlex.quote(c) for c in cmd)
    note = observe or ("observe the response for the confirming signal: reflected-payload "
                       "execution, a DB/stack error, a conditional time delay vs baseline, an "
                       "OOB callback, or returned data the request should not expose.")
    raw = f"\n(payload: {payload})" if payload else ""
    return f"PoC - reproduce with:\n{curl}{raw}\n\nWhat to observe: {note}"


TOOLS = [
    Tool(
        name="make_poc",
        description=(
            "Turn a CONFIRMED finding into a copy-pasteable curl PoC. Give the request that "
            "triggers it (url, method, optional param+payload to inject into the query, "
            "headers as JSON, or an explicit body) plus what to observe. Returns a runnable "
            "curl + the confirming signal. Put the output in the finding's proof_of_concept so "
            "the report ships a reproducible PoC. Only call this for a finding you actually "
            "verified - never fabricate a PoC for an unconfirmed guess."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "param": {"type": "string", "description": "query/body param to inject the payload into"},
                "payload": {"type": "string"},
                "headers": {"type": "string", "description": "JSON object of extra headers (auth/cookie)"},
                "body": {"type": "string", "description": "explicit request body (overrides param/payload injection)"},
                "observe": {"type": "string", "description": "the confirming signal to look for"},
            },
            "required": ["url"],
        },
        fn=make_poc,
    ),
]
