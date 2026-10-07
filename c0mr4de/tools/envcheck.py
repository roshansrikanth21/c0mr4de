"""Environment doctor: report which external pentest tools and runtimes are
available, so c0mr4de knows what runs natively, what falls back to Docker, and
what to install for a self-sufficient setup. Read-only."""
from __future__ import annotations

import os
import shutil
import subprocess

from c0mr4de.tools.base import Tool

_GROUPS = {
    "recon": ["nmap", "subfinder", "amass", "naabu", "httpx", "dnsx", "tlsx", "katana", "gau"],
    "vuln": ["nuclei", "sqlmap", "ffuf", "dalfox", "semgrep"],
    "runtime": ["docker", "git", "go"],
}

# Passive-intel API keys and what unlocks them. crt.sh + urlscan.io need no key,
# so they are intentionally absent here - they always work.
_API_KEYS = {
    "SHODAN_API_KEY": "shodan_host",
    "VT_API_KEY": "virustotal_lookup",
    "ABUSEIPDB_API_KEY": "abuseipdb_check",
    "OTX_API_KEY": "otx_indicator",
    "GREYNOISE_API_KEY": "greynoise_check (optional - raises community rate limit)",
}


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=8).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _ollama_up() -> bool:
    try:
        import httpx
        httpx.get("http://localhost:11434/api/tags", timeout=3)
        return True
    except Exception:  # noqa: BLE001
        return False


def env_report() -> str:
    """Report which external pentest tools (nmap/nuclei/katana/gau/semgrep/...) and
    runtimes (docker/ollama) are available, so you know what runs natively vs via Docker
    and what to install for a self-sufficient environment."""
    lines, present, missing = ["c0mr4de environment check:"], 0, 0
    miss_names = []
    for group, bins in _GROUPS.items():
        row = []
        for b in bins:
            ok = shutil.which(b) is not None
            row.append(b if ok else f"{b} (missing)")
            present += ok
            if not ok:
                missing += 1
                miss_names.append(b)
        lines.append(f"  {group:8}: " + ", ".join(row))
    key_row = []
    for env, tool in _API_KEYS.items():
        key_row.append(f"{env.split('_')[0].lower()}" if os.environ.get(env)
                       else f"{env.split('_')[0].lower()} (no key -> {tool} limited)")
    lines.append("  intel keys: " + ", ".join(key_row))
    lines.append("  keyless intel: crt_sh, urlscan_search (always available)")
    dk, ol = _docker_up(), _ollama_up()
    lines.append(f"  docker daemon: {'up' if dk else 'down'}  (runs missing ProjectDiscovery tools if the image is pulled)")
    lines.append(f"  ollama       : {'up' if ol else 'down'}  (local model fallback + knowledge-store embeddings)")
    lines.append(f"summary: {present} tools present, {missing} missing.")
    if miss_names:
        lines.append("to go self-sufficient: install the missing tools natively, or keep Docker up so the "
                     "PD tools (katana/naabu/httpx/dnsx/tlsx) run from their images. semgrep: pip install semgrep. "
                     "nuclei/subfinder/katana/dnsx/tlsx: go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest.")
    if not ol:
        lines.append("ollama is down: consult_knowledge (vector search) and the local model fallback are unavailable "
                     "until `ollama serve` is running; recall_related (graph) still works.")
    return "\n".join(lines)


TOOLS = [
    Tool(
        name="env_report",
        description=(
            "Report which external pentest tools (nmap/nuclei/katana/gau/semgrep/sqlmap/...) and "
            "runtimes (docker/ollama) are available on this host, so you know what will run "
            "natively, what falls back to Docker, and what is missing. Call it when a tool fails "
            "or when planning, to avoid trying tools that are not installed."
        ),
        parameters={"type": "object", "properties": {}, "required": []},
        fn=env_report,
    ),
]
