"""Heavy recon stacking - wrap larger recon frameworks/tools so c0mr4de
can go past single-tool scans into full recon. reconftw (six2dez) is the
headline one: it orchestrates ~50 tools (subfinder, amass, nuclei, httpx,
...) for subdomain enum, port scan, web probing and vuln checks.

reconftw is a heavy bash framework with many Linux deps - runs best under
WSL/Linux with reconftw properly installed. These wrappers invoke it and
degrade gracefully if it isn't runnable here."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from c0mr4de.tools.base import Tool

# Roshan's install per memory (reconftw-tool): ~/reconftw
_RECONFTW_HOME = Path.home() / "reconftw"
_TIMEOUT = 1800  # recon is slow; 30 min ceiling


def _reconftw_script() -> Path | None:
    candidate = _RECONFTW_HOME / "reconftw.sh"
    return candidate if candidate.exists() else None


def reconftw(domain: str, mode: str = "-s") -> str:
    """mode: -s subdomains only (fast), -r full recon (slow), -w web only.
    Defaults to -s so it doesn't run for hours unless asked."""
    script = _reconftw_script()
    if script is None:
        return (
            f"reconftw not found at {_RECONFTW_HOME}/reconftw.sh. It's a bash framework - "
            f"install/clone it (github.com/six2dez/reconftw) and run under WSL/Linux. "
            f"Until then, use the individual tools (subfinder/nmap/httpx) instead."
        )
    if shutil.which("bash") is None:
        return "ERROR: bash not on PATH - reconftw needs a Linux/WSL bash environment."
    cmd = ["bash", str(script), "-d", domain, mode]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT, cwd=str(_RECONFTW_HOME))
    except subprocess.TimeoutExpired:
        return f"reconftw timed out after {_TIMEOUT}s (recon can take longer; run it directly for full sweeps)."
    out = (result.stdout + result.stderr)[-8000:]
    return out or "(reconftw produced no output)"


def subfinder(domain: str) -> str:
    """Fast standalone subdomain enumeration (if subfinder is installed)."""
    if shutil.which("subfinder") is None:
        return "subfinder not on PATH. Install it (github.com/projectdiscovery/subfinder) or use reconftw -s."
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "subfinder timed out after 300s."
    return result.stdout[:8000] or "(no subdomains found)"


TOOLS = [
    Tool(
        name="reconftw",
        description=(
            "Run the reconftw framework against a DOMAIN for stacked recon (subdomains, ports, web probing, "
            "vuln checks). mode: '-s' subdomains only (fast, default), '-r' full recon (slow), '-w' web only. "
            "Slow - only for domains, not IPs."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "mode": {"type": "string", "description": "-s (subdomains), -r (full), -w (web)"},
            },
            "required": ["domain"],
        },
        fn=reconftw,
    ),
    Tool(
        name="subfinder",
        description="Fast standalone subdomain enumeration for a domain.",
        parameters={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        fn=subfinder,
    ),
]
