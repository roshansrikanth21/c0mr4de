"""Ingest a Burp Suite / Caido proxy-history export so c0mr4de can mine your
real captured traffic - the actual endpoints, parameters, methods, status
codes and interesting responses you proxied - instead of only what it can
discover blind. The operator exports proxy history (Burp: right-click ->
Save items; Caido: export) to XML; this parses it into a digest the agent
acts on. No live Burp connection required."""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from c0mr4de.tools.base import Tool


def _text(el, default=""):
    return (el.text or default) if el is not None else default


def _decode(el) -> str:
    if el is None:
        return ""
    raw = el.text or ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ""
    return raw


def burp_import(path: str, only_params: bool = False) -> str:
    p = Path(path)
    if not p.exists():
        return f"ERROR: file not found: {path}. Export Burp proxy history via right-click -> Save items (XML)."
    try:
        root = ET.parse(str(p)).getroot()
    except ET.ParseError as exc:
        return f"ERROR: not a valid Burp/Caido XML export ({exc})."

    items = root.findall("item")
    if not items:
        return "No items in the export."

    endpoints = []          # (method, url, status)
    params: set[str] = set()
    interesting = []        # non-200, auth headers, tokens
    hosts: set[str] = set()

    for it in items[:2000]:
        url = _text(it.find("url"))
        method = _text(it.find("method"), "GET")
        status = _text(it.find("status"))
        if url:
            hosts.add(urlparse(url).netloc)
            endpoints.append((method, url, status))
            for k in parse_qs(urlparse(url).query):
                params.add(k)
        req = _decode(it.find("request"))
        if req:
            # body params (form/JSON keys) and interesting headers
            for m in re.finditer(r"(?:^|&)([A-Za-z0-9_.\-\[\]]+)=", req.split("\r\n\r\n", 1)[-1]):
                params.add(m.group(1))
            for m in re.finditer(r'"([A-Za-z0-9_]+)"\s*:', req.split("\r\n\r\n", 1)[-1]):
                params.add(m.group(1))
            if re.search(r"(?i)authorization:|x-api-key:|cookie:.*(session|token|jwt)", req):
                interesting.append(f"auth material on {method} {url}")
        if status and status not in ("200", "301", "302", "304"):
            interesting.append(f"{status} on {method} {url}")

    uniq_ep = list(dict.fromkeys(endpoints))
    if only_params:
        return f"{len(params)} parameters across {len(uniq_ep)} requests:\n  " + ", ".join(sorted(params))

    lines = [f"Burp import: {len(uniq_ep)} unique requests across {len(hosts)} host(s)."]
    lines.append(f"\nHosts: {', '.join(sorted(hosts))}")
    lines.append(f"\nParameters ({len(params)}): {', '.join(sorted(params)[:60])}")
    lines.append("\nEndpoints (first 50):")
    for method, url, status in uniq_ep[:50]:
        lines.append(f"  {method} {url}  [{status}]")
    if interesting:
        lines.append("\nInteresting (auth / non-200):")
        for i in dict.fromkeys(interesting[:25]):
            lines.append(f"  - {i}")
    lines.append("\nPivot: test these endpoints/params for IDOR, injection, auth bypass; the auth-bearing ones first.")
    return "\n".join(lines)


TOOLS = [
    Tool(
        name="burp_import",
        description=("Ingest a Burp Suite / Caido proxy-history XML export (operator exports it: Burp right-click "
                     "-> Save items). Extracts real endpoints, parameters, methods, status codes and auth-bearing "
                     "requests from captured traffic - use to attack the actual surface the operator proxied. "
                     "only_params=true returns just the parameter list."),
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}, "only_params": {"type": "boolean"}},
            "required": ["path"],
        },
        fn=burp_import,
    ),
]
