"""verify_finding tool: deterministic confirmation of a single claimed finding.

This is the verification counterpart to the hunting tools. You hand it a concrete
request (a raw HTTP request pasted from Burp, or url+params) and a CLAIM, and it
re-derives the hard signal and returns CONFIRMED / UNCONFIRMED / INCONCLUSIVE.
The verdict is computed from measured signals, never asserted by the model, so a
response code or a reflection alone is never a confirmation.
"""
from __future__ import annotations

import json

from c0mr4de.tools.base import Tool
from c0mr4de.verifier import CLAIMS, parse_http_request, verify


def verify_finding(claim: str = "auto", request: str = "", url: str = "", method: str = "GET",
                   headers: str = "{}", body: str = "", point: str = "", control_request: str = "",
                   field: str = "", value: str = "", base_scheme: str = "https") -> str:
    try:
        if (request or "").strip():
            req = parse_http_request(request, base_scheme)
        elif (url or "").strip():
            try:
                hdrs = json.loads(headers) if headers else {}
            except json.JSONDecodeError:
                return "ERROR: headers must be a JSON object string, e.g. '{\"Authorization\": \"Bearer x\"}'"
            req = {"method": (method or "GET").upper(), "url": url, "headers": hdrs, "body": body or ""}
        else:
            return "ERROR: provide either `request` (a raw HTTP request) or `url`."
        ctrl = parse_http_request(control_request, base_scheme) if (control_request or "").strip() else None
    except ValueError as exc:
        return f"ERROR parsing request: {exc}"
    return verify(claim, req, point=point, control_request=ctrl, field_name=field, value=value).to_text()


TOOLS = [
    Tool(
        name="verify_finding",
        description=(
            "Deterministically VERIFY one claimed finding before reporting it. Give a concrete request "
            "(`request` = a raw HTTP request pasted from Burp, preferred; or `url` + `method`/`headers`/`body`) "
            "and a `claim`: " + " | ".join(CLAIMS) + ". `point` names the injection point (a query/body/header "
            "param; prefix with query:/body:/json:/header: to be explicit). For idor, pass `control_request` = the "
            "SAME endpoint with YOUR own id. For jwt, pass `field` and `value` to tamper (e.g. role=admin). Returns "
            "CONFIRMED only when a hard signal proves it (timing/OOB/execution/differential); otherwise UNCONFIRMED "
            "or INCONCLUSIVE. A response code or a reflection alone never confirms. Use this to check your own "
            "findings and to gate anything before it goes in a report."
        ),
        parameters={
            "type": "object",
            "properties": {
                "claim": {"type": "string", "description": "one of: " + ", ".join(CLAIMS)},
                "request": {"type": "string", "description": "raw HTTP request (Burp style): request line, headers, blank line, body"},
                "url": {"type": "string", "description": "alternative to `request`: the target URL (include the query string)"},
                "method": {"type": "string"},
                "headers": {"type": "string", "description": "JSON object string, used with `url`"},
                "body": {"type": "string"},
                "point": {"type": "string", "description": "injection point name, e.g. id, q, or header:X-Forwarded-For"},
                "control_request": {"type": "string", "description": "for idor: raw request for the SAME endpoint with your OWN id"},
                "field": {"type": "string", "description": "for jwt: payload field to tamper, e.g. role"},
                "value": {"type": "string", "description": "for jwt: new value, e.g. admin"},
                "base_scheme": {"type": "string", "description": "http or https when a raw request has a relative path (default https)"},
            },
            "required": ["claim"],
        },
        fn=verify_finding,
    ),
]
