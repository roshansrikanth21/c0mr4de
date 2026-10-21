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
                   field: str = "", value: str = "", victim_marker: str = "", base_scheme: str = "https") -> str:
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
            ex = {
                "sqli": "verify_finding(claim='sqli', url='http://host/item?id=1', point='id')",
                "xss": "verify_finding(claim='xss', url='http://host/search?q=x', point='q')",
                "open_redirect": "verify_finding(claim='open_redirect', url='http://host/go?next=/a', point='next')",
                "ssrf": "verify_finding(claim='ssrf', url='http://host/fetch?u=x', point='u')",
                "idor": "verify_finding(claim='idor', url='http://host/u?id=2', "
                        "control_request='GET http://host/u?id=1 HTTP/1.1', victim_marker='victim@x.com')",
                "jwt": "verify_finding(claim='jwt', url='http://host/me', field='role', value='admin')",
            }.get(claim, "verify_finding(claim='sqli', url='http://host/path?p=1', point='p')")
            return (f"ERROR: verify_finding needs a target. Pass `url` (the exact URL you tested) and `point` "
                    f"(the parameter name), or a raw `request`. This is not a missing tool - just call it again "
                    f"with the arguments. Example for {claim}: {ex}")
        ctrl = parse_http_request(control_request, base_scheme) if (control_request or "").strip() else None
    except ValueError as exc:
        return f"ERROR parsing request: {exc}"
    # Convenience: when the param is obvious (one query string) and the model forgot `point`,
    # infer it - weak models often pass the url but omit the param name.
    if not point and claim in ("sqli", "xss", "open_redirect", "ssrf", "auto"):
        import urllib.parse as _up
        qs = _up.parse_qs(_up.urlparse(req["url"]).query)
        if qs:
            point = list(qs.keys())[0]
    return verify(claim, req, point=point, control_request=ctrl, field_name=field, value=value,
                  victim_marker=victim_marker).to_text()


TOOLS = [
    Tool(
        name="verify_finding",
        description=(
            "Deterministically VERIFY one claimed finding before reporting it. Give a concrete request "
            "(`request` = a raw HTTP request pasted from Burp, preferred; or `url` + `method`/`headers`/`body`) "
            "and a `claim`: " + " | ".join(CLAIMS) + ". `point` names the injection point (a query/body/header "
            "param; prefix with query:/body:/json:/header: to be explicit). For idor, pass `control_request` = the "
            "SAME endpoint with YOUR own id AND `victim_marker` = the victim's unique datum (email/id) that should "
            "appear only in their record - IDOR CONFIRMS only when that marker is in the target and not your control. "
            "For jwt, pass `field` and `value` to tamper (e.g. role=admin). Returns "
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
                "victim_marker": {"type": "string", "description": "for idor: the victim's unique datum (email/id) that should appear only in their record"},
                "field": {"type": "string", "description": "for jwt: payload field to tamper, e.g. role"},
                "value": {"type": "string", "description": "for jwt: new value, e.g. admin"},
                "base_scheme": {"type": "string", "description": "http or https when a raw request has a relative path (default https)"},
            },
            "required": ["claim"],
        },
        fn=verify_finding,
    ),
]
