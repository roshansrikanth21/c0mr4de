"""Attack-surface tools: run the recon scanners, OR import scans you already ran,
into one structured model — then get a clean prioritized "where is it most likely
vulnerable" report + an interactive map, instead of scrolling raw tool spew.

- import_scan(tool, source)      : parse a scan you already ran (file path or pasted text)
- amass_enum / naabu_scan / shodan_host : run the scanners this repo didn't wrap yet
- map_attack_surface(domain)     : orchestrate subfinder+amass -> httpx (+opt ports/nuclei),
                                    aggregate, score, and render report + map
- attack_surface_report()        : render the current accumulated surface

Existing tools (subfinder, crawl/katana, probe/httpx, nuclei_scan, oob_*) already
feed the same model when their output is imported. Everything degrades to a clear
message if a binary/image/key is missing."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx

from c0mr4de.surface import AttackSurface
from c0mr4de.surface.analyze import summarize
from c0mr4de.surface.render import write_reports
from c0mr4de.tools.base import Tool

# one accumulating surface per process (like the OSINT graph); import/scan tools add to it
_SURFACE = AttackSurface()

_AMASS_IMG = "caffix/amass:latest"
_NAABU_IMG = "projectdiscovery/naabu:latest"
_HTTPX_IMG = "projectdiscovery/httpx:latest"


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _img(img: str) -> bool:
    try:
        return bool(subprocess.run(["docker", "images", "-q", img], capture_output=True, text=True, timeout=8).stdout.strip())
    except Exception:  # noqa: BLE001
        return False


def _run(binary: str, image: str, flags: list[str], timeout: int) -> tuple[str, str] | str:
    if _have(binary):
        cmd = [binary, *flags]
    elif _have("docker") and _img(image):
        from c0mr4de.tools.dockerutil import ADD_HOST, docker_target
        cmd = ["docker", "run", "--rm", *ADD_HOST, image, *[docker_target(f) for f in flags]]
    else:
        return f"{binary} not available (install it or `docker pull {image}`)."
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return f"{binary} timed out after {timeout}s — narrow the scope."
    except FileNotFoundError:
        return f"ERROR: could not launch {binary}."


# ---------------------------------------------------------------- scanners
def amass_enum(domain: str, timeout_min: int = 3) -> str:
    """Passive+active subdomain enumeration (OWASP Amass) for a domain."""
    out = _run("amass", _AMASS_IMG, ["enum", "-d", domain, "-timeout", str(timeout_min)], timeout_min * 60 + 60)
    if isinstance(out, str):
        return out
    n = _SURFACE.ingest_amass(out[0])
    return f"amass: +{n} subdomains for {domain} (merged into the attack surface). " + _stat_tail()


def naabu_scan(target: str, top_ports: int = 100) -> str:
    """Fast SYN/CONNECT port scan (naabu) on a host/IP. Feeds open ports into the surface."""
    out = _run("naabu", _NAABU_IMG, ["-host", target, "-top-ports", str(top_ports), "-json", "-silent"], 300)
    if isinstance(out, str):
        return out
    n = _SURFACE.ingest_naabu(out[0])
    return f"naabu: +{n} open ports on {target} (merged). " + _stat_tail()


def shodan_host(ip: str) -> str:
    """Passive host intel from Shodan (open ports, products, known CVEs). Needs SHODAN_API_KEY."""
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        return "Shodan needs an API key: set SHODAN_API_KEY (free key at shodan.io/account)."
    try:
        r = httpx.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}, timeout=20)
        if r.status_code == 404:
            return f"Shodan has no data for {ip}."
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return f"Shodan error: {exc}"
    n = _SURFACE.ingest_shodan(r.text)
    return f"shodan: merged {n} service records for {ip}. " + _stat_tail()


def _batch_httpx(hosts: list[str]) -> int:
    """Probe many hosts at once with httpx -l, feeding status/title/tech into the surface."""
    if not hosts:
        return 0
    tmp = Path(tempfile.gettempdir()) / "c0mr4de_httpx_targets.txt"
    tmp.write_text("\n".join(hosts), encoding="utf-8")
    flags = ["-l", str(tmp), "-json", "-silent", "-title", "-tech-detect", "-web-server", "-status-code", "-no-color"]
    if _have("httpx"):
        cmd = ["httpx", *flags]
    elif _have("docker") and _img(_HTTPX_IMG):
        from c0mr4de.tools.dockerutil import ADD_HOST
        cmd = ["docker", "run", "--rm", *ADD_HOST, "-v", f"{tmp}:{tmp}", _HTTPX_IMG, *flags]
    else:
        return -1
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception:  # noqa: BLE001
        return 0
    return _SURFACE.ingest_httpx(r.stdout)


# ---------------------------------------------------------------- import
_INGESTORS = {
    "subfinder": _SURFACE.ingest_subfinder, "amass": _SURFACE.ingest_amass,
    "naabu": _SURFACE.ingest_naabu, "httpx": _SURFACE.ingest_httpx,
    "nuclei": _SURFACE.ingest_nuclei, "shodan": _SURFACE.ingest_shodan,
    "bbot": _SURFACE.ingest_bbot,
}


def import_scan(tool: str, source: str) -> str:
    """Parse output from a scan you ALREADY ran into the structured attack surface.
    tool: subfinder|amass|naabu|httpx|nuclei|shodan|bbot. source: a file path OR the
    raw pasted output. This is how you clean up messy tool spew you already have."""
    tool = tool.lower().strip()
    fn = _INGESTORS.get(tool)
    if fn is None:
        return f"unknown tool '{tool}'. Supported: {', '.join(sorted(_INGESTORS))}."
    text = source
    p = Path(source)
    try:
        if len(source) < 500 and p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    n = fn(text)
    return f"imported {tool}: +{n} records into the attack surface. " + _stat_tail()


def _stat_tail() -> str:
    s = _SURFACE.stats()
    return f"[surface: {s['hosts']} hosts, {s['endpoints']} endpoints, {s['open_ports']} ports, {s['findings']} findings]"


# ---------------------------------------------------------------- orchestrate / report
def map_attack_surface(domain: str, ports: bool = False, vulns: bool = False) -> str:
    """One command: enumerate subdomains (subfinder+amass), probe them (httpx) for live
    web + tech, optionally port-scan (naabu) and vuln-scan (nuclei), then return the clean
    prioritized attack surface + write a report and interactive map. ports/vulns are slower."""
    _SURFACE.domain = domain
    log = []
    if _have("subfinder"):
        try:
            r = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=300)
            log.append(f"subfinder +{_SURFACE.ingest_subfinder(r.stdout)}")
        except Exception:  # noqa: BLE001
            log.append("subfinder failed")
    a = amass_enum(domain)
    log.append("amass ok" if a.startswith("amass:") else "amass skipped")
    _SURFACE.host(domain, "seed")

    hosts = list(_SURFACE.hosts)
    probed = _batch_httpx(hosts)
    log.append("httpx unavailable" if probed == -1 else f"httpx probed {len(hosts)} hosts (+{probed} live)")

    if ports:
        for h in hosts[:25]:
            naabu_scan(h)
        log.append("naabu done")
    if vulns:
        from c0mr4de.tools.nuclei import _build_cmd  # reuse its binary/docker resolution
        live = [e.url for e in _SURFACE.endpoints.values() if (e.status or 0) < 400][:15] or [f"https://{h}" for h in hosts[:15]]
        added = 0
        for u in live:
            cmd = _build_cmd(u, "critical,high,medium", "")
            if cmd is None:
                log.append("nuclei unavailable")
                break
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
                added += _SURFACE.ingest_nuclei(r.stdout)
            except Exception:  # noqa: BLE001
                continue
        else:
            log.append(f"nuclei +{added} findings")

    paths = write_reports(_SURFACE, domain)
    return f"recon: {'; '.join(log)}\n\n{summarize(_SURFACE)}\n\nwritten: {paths}"


def attack_surface_report() -> str:
    """Render the current accumulated attack surface (from imports/scans) to a clean
    prioritized report + interactive map, and return the summary."""
    if not _SURFACE.hosts and not _SURFACE.endpoints and not _SURFACE.findings:
        return "attack surface is empty — run map_attack_surface(domain) or import_scan(tool, output) first."
    paths = write_reports(_SURFACE)
    return summarize(_SURFACE) + f"\n\nwritten: {paths}"


TOOLS = [
    Tool(name="map_attack_surface",
         description=("Full attack-surface recon on a DOMAIN: enumerate subdomains (subfinder+amass), probe "
                      "them with httpx (live/status/title/tech), optionally port-scan (ports=true, naabu) and "
                      "vuln-scan (vulns=true, nuclei). Returns a prioritized 'most likely vulnerable' list + "
                      "writes a clean report and interactive map. The one command that replaces reading raw spew."),
         parameters={"type": "object", "properties": {
             "domain": {"type": "string"}, "ports": {"type": "boolean"}, "vulns": {"type": "boolean"}},
             "required": ["domain"]},
         fn=map_attack_surface),
    Tool(name="import_scan",
         description=("Parse output from a scan you ALREADY ran into the structured attack surface, so messy "
                      "tool spew becomes a clean prioritized map. tool: subfinder|amass|naabu|httpx|nuclei|"
                      "shodan|bbot. source: a file path OR the raw pasted output."),
         parameters={"type": "object", "properties": {
             "tool": {"type": "string"}, "source": {"type": "string"}}, "required": ["tool", "source"]},
         fn=import_scan),
    Tool(name="attack_surface_report",
         description="Render the current accumulated attack surface to a clean prioritized report + interactive map.",
         parameters={"type": "object", "properties": {}, "required": []},
         fn=attack_surface_report),
    Tool(name="amass_enum",
         description="OWASP Amass subdomain enumeration for a domain; merges results into the attack surface.",
         parameters={"type": "object", "properties": {"domain": {"type": "string"}, "timeout_min": {"type": "integer"}},
                     "required": ["domain"]},
         fn=amass_enum),
    Tool(name="naabu_scan",
         description="Fast port scan (naabu) of a host/IP; merges open ports into the attack surface. top_ports default 100.",
         parameters={"type": "object", "properties": {"target": {"type": "string"}, "top_ports": {"type": "integer"}},
                     "required": ["target"]},
         fn=naabu_scan),
    Tool(name="shodan_host",
         description="Passive Shodan host lookup for an IP (open ports, products, known CVEs). Needs SHODAN_API_KEY.",
         parameters={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
         fn=shodan_host),
]
