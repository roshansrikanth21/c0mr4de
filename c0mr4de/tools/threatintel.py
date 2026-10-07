"""Threat-intel + reputation lookups - the "THREAT INTEL" and passive-OSINT tools
c0mr4de was missing (VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, crt.sh,
urlscan.io). All PASSIVE: they query third-party databases, they never touch the
target, so they are safe to run before any authorization and carry no scan traffic.

Same shape as surface.shodan_host: read the API key from the environment, degrade
with a clear "set X_API_KEY" message when it is absent, and keep the output short
for a weak model's context. crt.sh and urlscan.io search need no key, so they work
out of the box. Parsing is split into pure _summarize_*/_parse_* helpers so the
logic is testable without network.
"""
from __future__ import annotations

import ipaddress
import os
import re

import httpx

from c0mr4de.tools.base import Tool

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _classify(resource: str) -> str:
    """Rough type of an indicator: 'ip', 'hash', 'url', or 'domain'."""
    resource = resource.strip()
    if _is_ip(resource):
        return "ip"
    if _HASH_RE.match(resource):
        return "hash"
    if resource.startswith(("http://", "https://")):
        return "url"
    return "domain"


def _get_json(url: str, headers: dict | None = None, params: dict | None = None):
    r = httpx.get(url, headers=headers or {}, params=params or {}, timeout=20,
                  follow_redirects=True)
    return r


# ── VirusTotal ────────────────────────────────────────────────────────────────
def _summarize_vt(data: dict, resource: str) -> str:
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int)) or 0
    verdict = "MALICIOUS" if mal else ("SUSPICIOUS" if sus else "clean")
    extra = []
    if attrs.get("reputation") is not None:
        extra.append(f"reputation={attrs['reputation']}")
    if attrs.get("as_owner"):
        extra.append(f"as={attrs['as_owner']}")
    if attrs.get("meaningful_name"):
        extra.append(attrs["meaningful_name"])
    tail = ("  " + ", ".join(extra)) if extra else ""
    return (f"VirusTotal {resource}: {verdict} - {mal} malicious / {sus} suspicious "
            f"of {total} engines.{tail}")


def virustotal_lookup(resource: str) -> str:
    """Passive VirusTotal reputation for an IP, domain, URL, or file hash (MD5/SHA1/
    SHA256). Needs VT_API_KEY (free at virustotal.com). Does not touch the target."""
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY") or ""
    if not key:
        return "VirusTotal needs an API key: set VT_API_KEY (free at virustotal.com/gui/join-us)."
    kind = _classify(resource)
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}[kind]
    ident = resource
    if kind == "url":
        import base64
        ident = base64.urlsafe_b64encode(resource.encode()).decode().rstrip("=")
    try:
        r = _get_json(f"https://www.virustotal.com/api/v3/{path}/{ident}",
                      headers={"x-apikey": key})
        if r.status_code == 404:
            return f"VirusTotal has no record for {resource} (not necessarily safe - just unseen)."
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return f"VirusTotal error: {exc}"
    return _summarize_vt(r.json(), resource)


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
def _summarize_abuseipdb(data: dict, ip: str) -> str:
    d = data.get("data") or {}
    score = d.get("abuseConfidenceScore", 0)
    verdict = "HIGH-ABUSE" if score >= 50 else ("some reports" if score else "clean")
    bits = [f"score={score}%", f"reports={d.get('totalReports', 0)}"]
    if d.get("countryCode"):
        bits.append(f"cc={d['countryCode']}")
    if d.get("isp"):
        bits.append(f"isp={d['isp']}")
    if d.get("domain"):
        bits.append(d["domain"])
    return f"AbuseIPDB {ip}: {verdict} - " + ", ".join(bits)


def abuseipdb_check(ip: str) -> str:
    """Passive IP abuse reputation from AbuseIPDB (confidence score, report count,
    ISP, country). Needs ABUSEIPDB_API_KEY (free at abuseipdb.com)."""
    if not _is_ip(ip):
        return f"AbuseIPDB takes an IP address, got '{ip}'."
    key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return "AbuseIPDB needs an API key: set ABUSEIPDB_API_KEY (free at abuseipdb.com/register)."
    try:
        r = _get_json("https://api.abuseipdb.com/api/v2/check",
                      headers={"Key": key, "Accept": "application/json"},
                      params={"ipAddress": ip, "maxAgeInDays": 90})
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return f"AbuseIPDB error: {exc}"
    return _summarize_abuseipdb(r.json(), ip)


# ── GreyNoise (community) ─────────────────────────────────────────────────────
def _summarize_greynoise(data: dict, ip: str) -> str:
    # community API returns {ip, noise, riot, classification, name, last_seen, message}
    if data.get("message") and "not" in str(data.get("message", "")).lower() and not data.get("classification"):
        return f"GreyNoise {ip}: not seen scanning the internet (no noise record)."
    cls = data.get("classification", "unknown")
    name = data.get("name", "")
    flags = []
    if data.get("noise"):
        flags.append("internet-scanner (noise)")
    if data.get("riot"):
        flags.append("common-business-service (RIOT)")
    tail = f"  {name}" if name and name != "unknown" else ""
    return (f"GreyNoise {ip}: classification={cls}"
            + (f", {', '.join(flags)}" if flags else "")
            + (f", last_seen={data['last_seen']}" if data.get("last_seen") else "") + tail)


def greynoise_check(ip: str) -> str:
    """Is this IP mass-scanning the internet (background noise) or a known benign
    service? GreyNoise community API. GREYNOISE_API_KEY optional (raises the free
    community rate limit). Passive."""
    if not _is_ip(ip):
        return f"GreyNoise takes an IP address, got '{ip}'."
    headers = {"Accept": "application/json"}
    key = os.environ.get("GREYNOISE_API_KEY", "")
    if key:
        headers["key"] = key
    try:
        r = _get_json(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        if r.status_code == 404:
            return f"GreyNoise {ip}: not seen scanning the internet (no noise record)."
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return f"GreyNoise error: {exc}"
    return _summarize_greynoise(r.json(), ip)


# ── AlienVault OTX ────────────────────────────────────────────────────────────
def _summarize_otx(data: dict, indicator: str) -> str:
    pulse = data.get("pulse_info") or {}
    count = pulse.get("count", 0)
    names = [p.get("name", "") for p in (pulse.get("pulses") or [])][:4]
    if not count:
        return f"OTX {indicator}: in 0 threat pulses (no community threat reports)."
    sample = "; ".join(n for n in names if n)
    return f"OTX {indicator}: referenced in {count} threat pulse(s). e.g. {sample}"


def otx_indicator(indicator: str) -> str:
    """AlienVault OTX community threat pulses referencing an IP, domain, or file
    hash. Needs OTX_API_KEY (free at otx.alienvault.com). Passive."""
    key = os.environ.get("OTX_API_KEY", "")
    if not key:
        return "OTX needs an API key: set OTX_API_KEY (free at otx.alienvault.com, Settings > API)."
    kind = _classify(indicator)
    section = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "domain"}[kind]
    try:
        r = _get_json(f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
                      headers={"X-OTX-API-KEY": key})
        if r.status_code == 404:
            return f"OTX has no record for {indicator}."
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return f"OTX error: {exc}"
    return _summarize_otx(r.json(), indicator)


# ── crt.sh (certificate transparency - free, no key) ──────────────────────────
def _parse_crtsh(entries: list, domain: str) -> list[str]:
    """Pull unique sub-domains of `domain` from crt.sh name_value fields."""
    subs: set[str] = set()
    for e in entries:
        for name in str(e.get("name_value", "")).split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain.lower()) and name:
                subs.add(name)
    return sorted(subs)


def crt_sh(domain: str) -> str:
    """Enumerate sub-domains from certificate-transparency logs via crt.sh. Free, no
    key, fully passive - a strong first OSINT move before active recon."""
    try:
        r = _get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        r.raise_for_status()
        entries = r.json()
    except httpx.HTTPError as exc:
        return f"crt.sh error: {exc}"
    except ValueError:
        return "crt.sh returned no parseable JSON (it is often rate-limited; retry shortly)."
    subs = _parse_crtsh(entries if isinstance(entries, list) else [], domain)
    if not subs:
        return f"crt.sh: no sub-domains found for {domain} in CT logs."
    shown = subs[:60]
    tail = f"\n  ... +{len(subs) - 60} more" if len(subs) > 60 else ""
    return f"crt.sh: {len(subs)} unique sub-domains for {domain}:\n  " + "\n  ".join(shown) + tail


# ── urlscan.io (search - free, no key) ────────────────────────────────────────
def _summarize_urlscan(data: dict, query: str) -> str:
    results = data.get("results") or []
    if not results:
        return f"urlscan.io: no public scans matching '{query}'."
    lines = []
    for res in results[:10]:
        page = res.get("page") or {}
        task = res.get("task") or {}
        lines.append(f"  {page.get('url', '?')}  (ip={page.get('ip', '?')}, "
                     f"server={page.get('server', '?')}, {task.get('time', '')[:10]})")
    more = f"\n  ... +{len(results) - 10} more" if len(results) > 10 else ""
    return f"urlscan.io: {len(results)} public scan(s) for '{query}':\n" + "\n".join(lines) + more


def urlscan_search(query: str) -> str:
    """Search urlscan.io's public database of prior scans for a domain/host - who
    scanned it, resolved IPs, servers, redirects. Free, no key, passive. query is a
    urlscan search term, e.g. 'example.com' or 'domain:example.com'."""
    q = query if ":" in query else f"domain:{query}"
    try:
        r = _get_json("https://urlscan.io/api/v1/search/", params={"q": q, "size": 20})
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return f"urlscan.io error: {exc}"
    return _summarize_urlscan(r.json(), query)


TOOLS = [
    Tool(
        name="virustotal_lookup",
        description=("Passive VirusTotal reputation for an IP, domain, URL, or file hash (how many AV "
                     "engines flag it, reputation, ASN). Needs VT_API_KEY. Never touches the target."),
        parameters={"type": "object", "properties": {"resource": {"type": "string"}}, "required": ["resource"]},
        fn=virustotal_lookup,
    ),
    Tool(
        name="abuseipdb_check",
        description=("Passive IP abuse reputation from AbuseIPDB (confidence score, report count, ISP, "
                     "country). Use to triage a suspicious source IP. Needs ABUSEIPDB_API_KEY."),
        parameters={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
        fn=abuseipdb_check,
    ),
    Tool(
        name="greynoise_check",
        description=("Is an IP mass-scanning the internet (background noise) or a known benign service? "
                     "GreyNoise community lookup. GREYNOISE_API_KEY optional. Passive."),
        parameters={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
        fn=greynoise_check,
    ),
    Tool(
        name="otx_indicator",
        description=("AlienVault OTX community threat pulses referencing an IP, domain, or file hash - "
                     "ties an indicator to known campaigns. Needs OTX_API_KEY. Passive."),
        parameters={"type": "object", "properties": {"indicator": {"type": "string"}}, "required": ["indicator"]},
        fn=otx_indicator,
    ),
    Tool(
        name="crt_sh",
        description=("Enumerate sub-domains from certificate-transparency logs via crt.sh. Free, no key, "
                     "fully passive - a strong first recon move to map the attack surface before scanning."),
        parameters={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        fn=crt_sh,
    ),
    Tool(
        name="urlscan_search",
        description=("Search urlscan.io's public scan database for a domain/host (resolved IPs, servers, "
                     "redirects seen by prior scans). Free, no key, passive."),
        parameters={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        fn=urlscan_search,
    ),
]
