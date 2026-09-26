"""The unified attack-surface model + parsers that absorb each tool's output.

Every recon tool speaks its own messy dialect; this collapses them into one
structure: hosts (subdomains + IPs + open ports/services), web endpoints (status,
title, tech, server), and findings (nuclei/shodan/bbot vulns). Parsers accept
JSON/JSONL where the tool emits it and fall back to plain-text lines, because the
operator's existing scan dumps come in both forms."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class Host:
    host: str
    ips: set[str] = field(default_factory=set)
    ports: dict[int, str] = field(default_factory=dict)   # port -> service/product string
    sources: set[str] = field(default_factory=set)


@dataclass
class Endpoint:
    url: str
    status: int | None = None
    title: str = ""
    tech: list[str] = field(default_factory=list)
    webserver: str = ""
    sources: set[str] = field(default_factory=set)


@dataclass
class Finding:
    ident: str
    name: str
    severity: str          # critical/high/medium/low/info
    location: str
    source: str
    tags: list[str] = field(default_factory=list)


def _host_of(url_or_host: str) -> str:
    s = re.sub(r"^\w+://", "", url_or_host.strip()).split("/")[0]
    return s.split(":")[0].lower().strip()


class AttackSurface:
    def __init__(self, domain: str = "") -> None:
        self.domain = domain
        self.hosts: dict[str, Host] = {}
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: list[Finding] = []

    # ---- mutation helpers -------------------------------------------------
    def host(self, name: str, source: str = "") -> Host:
        name = name.lower().strip()
        h = self.hosts.get(name)
        if h is None:
            h = Host(host=name)
            self.hosts[name] = h
        if source:
            h.sources.add(source)
        return h

    def add_resolution(self, name: str, ip: str, source: str = "") -> None:
        if ip:
            self.host(name, source).ips.add(ip.strip())

    def add_port(self, name: str, port: int, service: str = "", source: str = "") -> None:
        h = self.host(name, source)
        # keep the most descriptive service string we've seen for the port
        if port not in h.ports or (service and len(service) > len(h.ports[port])):
            h.ports[port] = service

    def add_endpoint(self, url: str, status=None, title="", tech=None, webserver="", source="") -> Endpoint:
        url = url.strip()
        e = self.endpoints.get(url)
        if e is None:
            e = Endpoint(url=url)
            self.endpoints[url] = e
            self.host(_host_of(url), source)  # an endpoint implies its host is live
        if status is not None:
            try:
                e.status = int(status)
            except (TypeError, ValueError):
                pass
        if title:
            e.title = title
        if webserver:
            e.webserver = webserver
        for t in (tech or []):
            if t and t not in e.tech:
                e.tech.append(t)
        if source:
            e.sources.add(source)
        return e

    def add_finding(self, ident, name, severity, location, source, tags=None) -> None:
        self.findings.append(Finding(ident=ident or "?", name=name or "", severity=(severity or "info").lower(),
                                     location=location or "", source=source, tags=list(tags or [])))

    # ---- parsers (one per tool; each tolerant of JSON or plain text) ------
    def ingest_subfinder(self, text: str, source="subfinder") -> int:
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("[", "{", "http")):
                if line.startswith("{"):
                    try:
                        line = json.loads(line).get("host", "")
                    except json.JSONDecodeError:
                        continue
                else:
                    continue
            if "." in line and " " not in line:
                self.host(line, source)
                n += 1
        return n

    def ingest_amass(self, text: str, source="amass") -> int:
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):                       # amass -json
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = d.get("name", "")
                if name:
                    self.host(name, source)
                    n += 1
                    for a in d.get("addresses", []):
                        self.add_resolution(name, a.get("ip", ""), source)
            else:                                           # "name --> ... --> ip" or bare name
                m = re.match(r"([a-z0-9._-]+\.[a-z]{2,})", line, re.I)
                if m:
                    self.host(m.group(1), source)
                    n += 1
                    for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line):
                        self.add_resolution(m.group(1), ip, source)
        return n

    def ingest_naabu(self, text: str, source="naabu") -> int:
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = d.get("host") or d.get("ip", "")
                port = d.get("port")
                if host and port:
                    self.add_port(host, int(port), str(d.get("service", "")), source)
                    if d.get("ip"):
                        self.add_resolution(host, d["ip"], source)
                    n += 1
            else:                                           # host:port
                m = re.match(r"([a-z0-9._-]+):(\d+)$", line, re.I)
                if m:
                    self.add_port(m.group(1), int(m.group(2)), "", source)
                    n += 1
        return n

    def ingest_httpx(self, text: str, source="httpx") -> int:
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):                        # httpx -json
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = d.get("url") or d.get("input", "")
                if not url:
                    continue
                self.add_endpoint(url, status=d.get("status_code"), title=d.get("title", ""),
                                  tech=d.get("tech") or d.get("technologies") or [],
                                  webserver=d.get("webserver", ""), source=source)
                for ip in (d.get("a") or []):
                    self.add_resolution(_host_of(url), ip, source)
                n += 1
            else:                                           # "url [200] [Title] [Nginx,PHP]"
                m = re.match(r"(https?://\S+)", line)
                if m:
                    url = m.group(1)
                    status = None
                    sm = re.search(r"\[(\d{3})\]", line)
                    if sm:
                        status = sm.group(1)
                    brackets = re.findall(r"\[([^\]]+)\]", line)
                    tech = brackets[-1].split(",") if len(brackets) >= 2 else []
                    self.add_endpoint(url, status=status, tech=[t.strip() for t in tech], source=source)
                    n += 1
        return n

    def ingest_nuclei(self, text: str, source="nuclei") -> int:
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = d.get("info", {})
            self.add_finding(d.get("template-id", "?"), info.get("name", ""), info.get("severity", "info"),
                             d.get("matched-at", d.get("host", "")), source, info.get("tags", []))
            n += 1
        return n

    def ingest_shodan(self, text: str, source="shodan") -> int:
        """A Shodan host lookup JSON (from `shodan host --format json <ip>` or the API)."""
        try:
            d = json.loads(text)
        except json.JSONDecodeError:
            return 0
        ip = d.get("ip_str") or d.get("ip", "")
        for hn in d.get("hostnames", []):
            self.host(hn, source)
            self.add_resolution(hn, ip, source)
        target = (d.get("hostnames") or [ip])[0]
        for svc in d.get("data", []):
            port = svc.get("port")
            product = " ".join(str(x) for x in [svc.get("product", ""), svc.get("version", "")] if x).strip()
            if port:
                self.add_port(target, int(port), product or svc.get("_shodan", {}).get("module", ""), source)
        for cve in (d.get("vulns", []) or []):
            self.add_finding(cve, f"Shodan-reported {cve}", "high", f"{target} ({ip})", source, ["cve", "shodan"])
        return len(d.get("data", []))

    def ingest_bbot(self, text: str, source="bbot") -> int:
        """bbot ndjson events (output.ndjson): DNS_NAME, OPEN_TCP_PORT, URL, TECHNOLOGY, FINDING, VULNERABILITY."""
        n = 0
        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            t, data = ev.get("type", ""), ev.get("data")
            if t == "DNS_NAME" and isinstance(data, str):
                self.host(data, source); n += 1
            elif t == "OPEN_TCP_PORT" and isinstance(data, str) and ":" in data:
                h, _, p = data.rpartition(":")
                if p.isdigit():
                    self.add_port(h, int(p), "", source); n += 1
            elif t == "URL" and isinstance(data, str):
                self.add_endpoint(data, source=source); n += 1
            elif t == "TECHNOLOGY" and isinstance(data, dict):
                url = data.get("url") or data.get("host", "")
                if url:
                    self.add_endpoint(url if url.startswith("http") else "http://" + url,
                                      tech=[data.get("technology", "")], source=source)
            elif t in ("FINDING", "VULNERABILITY") and isinstance(data, dict):
                sev = sev_map.get(str(data.get("severity", "")).upper(), "info" if t == "FINDING" else "medium")
                self.add_finding(data.get("host", "?"), data.get("description", t), sev,
                                 data.get("url") or data.get("host", ""), source, ["bbot"])
                n += 1
        return n

    # ---- serialization ----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "hosts": [{"host": h.host, "ips": sorted(h.ips), "ports": h.ports, "sources": sorted(h.sources)}
                      for h in self.hosts.values()],
            "endpoints": [{"url": e.url, "status": e.status, "title": e.title, "tech": e.tech,
                           "webserver": e.webserver, "sources": sorted(e.sources)}
                          for e in self.endpoints.values()],
            "findings": [{"id": f.ident, "name": f.name, "severity": f.severity, "location": f.location,
                          "source": f.source, "tags": f.tags} for f in self.findings],
        }

    def stats(self) -> dict:
        return {"hosts": len(self.hosts), "endpoints": len(self.endpoints),
                "open_ports": sum(len(h.ports) for h in self.hosts.values()), "findings": len(self.findings)}
