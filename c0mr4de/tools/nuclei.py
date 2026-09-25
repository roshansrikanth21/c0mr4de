"""nuclei - template-based vulnerability scanning for breadth. Runs
ProjectDiscovery's nuclei (thousands of community templates: CVEs,
exposures, misconfigurations, default creds, tech detection) against a
target and returns the matches, parsed.

Prefers a native `nuclei` binary; falls back to the official Docker image
(`projectdiscovery/nuclei`). Degrades to a clear message if neither exists.
Bounded by default (severity filter + timeout + rate limit) so it stays a
quick sweep, not an hours-long crawl."""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess

from c0mr4de.tools.base import Tool

_TIMEOUT = 240
_IMAGE = "projectdiscovery/nuclei:latest"


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _docker_image_present() -> bool:
    try:
        r = subprocess.run(["docker", "images", "-q", _IMAGE], capture_output=True, text=True, timeout=8)
        return bool(r.stdout.strip())
    except Exception:  # noqa: BLE001
        return False


def _build_cmd(target: str, severity: str, tags: str) -> list[str] | None:
    flags = ["-u", target, "-jsonl", "-silent", "-rate-limit", "50", "-timeout", "8"]
    if severity:
        flags += ["-severity", severity]
    if tags:
        flags += ["-tags", tags]
    if _have("nuclei"):
        return ["nuclei", *flags]
    if _have("docker") and _docker_image_present():
        # cache templates in a named volume so they aren't re-downloaded every --rm run
        return ["docker", "run", "--rm", "--network", "host",
                "-v", "c0mr4de-nuclei-templates:/root/nuclei-templates", _IMAGE, *flags]
    return None


def nuclei_scan(target: str, severity: str = "critical,high,medium", tags: str = "") -> str:
    cmd = _build_cmd(target, severity, tags)
    if cmd is None:
        return ("nuclei not available. Install the binary (github.com/projectdiscovery/nuclei) or pull the "
                "image: `docker pull projectdiscovery/nuclei`. Meanwhile use fuzz_paths / http_request / nikto.")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"nuclei timed out after {_TIMEOUT}s — narrow the scan with tags= or a tighter severity=."
    except FileNotFoundError:
        return "ERROR: could not launch nuclei (docker/binary missing)."

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        findings.append({
            "id": d.get("template-id", "?"),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "matched": d.get("matched-at", d.get("host", "")),
        })
    if not findings:
        tail = (result.stderr or "").strip()[-300:]
        return f"nuclei ran on {target}: no matches for severity={severity or 'all'} tags={tags or 'all'}." + (f"\n{tail}" if tail else "")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 5))
    lines = [f"nuclei: {len(findings)} match(es) on {target}"]
    for f in findings[:40]:
        lines.append(f"  [{f['severity'].upper()}] {f['id']} — {f['name']}  @ {f['matched']}")
    return "\n".join(lines)


TOOLS = [
    Tool(
        name="nuclei_scan",
        description=(
            "Template-based vuln scan (nuclei): thousands of checks for CVEs, exposures, "
            "misconfigurations, default creds, exposed panels. Use for broad coverage on a target. "
            "severity: comma list (critical,high,medium,low,info). tags: optional focus (e.g. 'cve,exposure')."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL/host to scan"},
                "severity": {"type": "string"},
                "tags": {"type": "string", "description": "optional template tags to focus the scan"},
            },
            "required": ["target"],
        },
        fn=nuclei_scan,
    ),
]
