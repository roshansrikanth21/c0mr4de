"""Turn a normalized AttackSurface into a prioritized "where is it most likely
vulnerable" view. Pure heuristics over the model - no network. Signals:

- nuclei/shodan/bbot findings (the strongest signal, weighted by severity)
- exposed sensitive ports (databases, admin services, container/orchestration)
- exposed sensitive paths/panels in discovered endpoints
- detected technologies that map to well-known vuln classes / CVE families

Each scored item carries the reasons, so the output is explainable, not a
black-box number."""
from __future__ import annotations

from c0mr4de.surface.model import AttackSurface

_SEV_WEIGHT = {"critical": 100, "high": 60, "medium": 30, "low": 12, "info": 3}

# port -> (label, score, why)
SENSITIVE_PORTS = {
    3306: ("MySQL", 40, "database exposed"), 5432: ("PostgreSQL", 40, "database exposed"),
    27017: ("MongoDB", 55, "often unauthenticated"), 6379: ("Redis", 55, "often unauthenticated -> RCE"),
    9200: ("Elasticsearch", 55, "often unauthenticated data exposure"), 11211: ("Memcached", 45, "amplification/exposure"),
    2375: ("Docker API", 90, "unauth Docker API = host RCE"), 2379: ("etcd", 70, "cluster secrets"),
    6443: ("Kubernetes API", 70, "cluster control"), 3389: ("RDP", 45, "brute/BlueKeep surface"),
    445: ("SMB", 45, "SMB exposure"), 23: ("Telnet", 50, "cleartext admin"), 21: ("FTP", 30, "check anon login"),
    5900: ("VNC", 55, "remote desktop, often weak/no auth"), 1433: ("MSSQL", 40, "database exposed"),
    9000: ("app/PHP-FPM/SonarQube", 25, "dev service"), 8080: ("HTTP-alt/proxy", 15, "secondary web app"),
    8443: ("HTTPS-alt", 15, "secondary web app"), 5601: ("Kibana", 40, "data UI, often open"),
    15672: ("RabbitMQ mgmt", 40, "default creds common"), 8086: ("InfluxDB", 40, "db exposed"),
}

# substring in tech/title -> (vuln hint, score). Matched case-insensitively.
TECH_VULN_HINTS = {
    "wordpress": ("plugin/theme CVEs, xmlrpc, user enum", 30),
    "drupal": ("Drupalgeddon-class RCE CVEs", 35), "joomla": ("component CVEs", 30),
    "jenkins": ("script console / unauth RCE CVEs", 60), "gitlab": ("known RCE/auth CVEs", 45),
    "jira": ("SSRF/RCE CVEs (CVE-2019-11581, etc.)", 45), "confluence": ("OGNL RCE CVEs", 60),
    "struts": ("Struts OGNL RCE", 70), "weblogic": ("deserialization RCE CVEs", 65),
    "phpmyadmin": ("admin DB panel exposed", 45), "grafana": ("path traversal / auth CVEs", 40),
    "kibana": ("prototype pollution RCE CVEs", 40), "solr": ("velocity template RCE", 55),
    "tomcat": ("manager app / Ghostcat", 40), "spring": ("Spring4Shell/actuator exposure", 45),
    "elasticsearch": ("unauth data / scripting RCE", 50), "citrix": ("CVE-2019-19781 traversal RCE", 65),
    "fortinet": ("SSL-VPN path traversal CVEs", 60), "exchange": ("ProxyShell/ProxyLogon", 65),
    "wp-": ("WordPress internals exposed", 20), "swagger": ("API spec exposed -> map endpoints", 20),
    "graphql": ("introspection / authz / batching", 30), "s3": ("bucket perms", 25),
}

# path/title fragments in an endpoint -> (tag, score, why, needs_live).
# needs_live=True: it's an "is this file actually exposed?" check, so it only
# counts when the endpoint really responded (status < 400). A 404 .git is NOT a
# finding. needs_live=False: a surface marker (admin/login/api) that matters even
# behind auth.
SENSITIVE_PATHS = [
    (".git", 55, "exposed .git -> source disclosure", True), (".env", 60, "exposed .env -> secrets", True),
    ("/actuator", 45, "Spring actuator exposed", True), ("/admin", 30, "admin panel", False),
    ("/login", 12, "auth surface", False), ("/phpmyadmin", 45, "DB admin panel", True),
    ("/wp-admin", 25, "WP admin", False), ("/wp-login", 20, "WP login", False), ("/jenkins", 45, "Jenkins", True),
    ("/swagger", 22, "API docs -> endpoint map", True), ("/graphql", 28, "GraphQL endpoint", False),
    ("/api", 12, "API surface", False), ("/debug", 40, "debug endpoint", True), ("/.svn", 45, "SVN exposed", True),
    ("/server-status", 35, "Apache status exposed", True), ("/config", 30, "config exposed", True),
    ("/backup", 40, "backup exposed", True), ("/.ds_store", 25, "DS_Store listing", True),
    ("/graphiql", 30, "GraphQL IDE exposed", True), ("/metrics", 25, "metrics exposed", True),
]

# statuses worth attention beyond obvious 200s
_INTERESTING_STATUS = {401: "auth-gated (worth trying to bypass)", 403: "forbidden (try bypass)",
                       500: "server error (fuzz for stack traces)", 200: "live"}


def _score_endpoint(e) -> tuple[int, list[str]]:
    score, reasons = 0, []
    low_url, low_title = e.url.lower(), (e.title or "").lower()
    reachable = e.status is None or e.status < 400        # 404/gone => file not actually exposed
    for frag, s, why, needs_live in SENSITIVE_PATHS:
        if frag in low_url and not (needs_live and not reachable):
            score += s
            reasons.append(why)
    for tech in e.tech + [e.webserver, low_title]:
        for key, (hint, s) in TECH_VULN_HINTS.items():
            if key in (tech or "").lower():
                score += s
                reasons.append(f"{tech}: {hint}")
    if e.status in (401, 403):
        score += 10
        reasons.append(_INTERESTING_STATUS[e.status])
    return score, reasons


def _score_host(h) -> tuple[int, list[str]]:
    score, reasons = 0, []
    for port, svc in h.ports.items():
        if port in SENSITIVE_PORTS:
            label, s, why = SENSITIVE_PORTS[port]
            score += s
            reasons.append(f"port {port} ({svc or label}): {why}")
    return score, reasons


def prioritize(surf: AttackSurface) -> list[dict]:
    """Rank hosts and endpoints by likelihood of being vulnerable, with reasons."""
    items: list[dict] = []
    # findings attach their weight to the host they touch
    finding_boost: dict[str, list] = {}
    for f in surf.findings:
        loc = f.location.lower()
        finding_boost.setdefault(loc, []).append(f)

    for e in surf.endpoints.values():
        score, reasons = _score_endpoint(e)
        for f in surf.findings:
            if f.location and (f.location in e.url or e.url in f.location):
                score += _SEV_WEIGHT.get(f.severity, 3)
                reasons.append(f"nuclei [{f.severity}] {f.name or f.ident}")
        if score > 0:
            items.append({"kind": "endpoint", "ref": e.url, "score": score,
                          "detail": f"{e.status or '?'} {e.title[:50]}", "reasons": reasons})

    for h in surf.hosts.values():
        score, reasons = _score_host(h)
        for f in surf.findings:
            if h.host in f.location:
                score += _SEV_WEIGHT.get(f.severity, 3)
                reasons.append(f"{f.source} [{f.severity}] {f.name or f.ident}")
        if score > 0:
            ports = ",".join(str(p) for p in sorted(h.ports)) or "-"
            items.append({"kind": "host", "ref": h.host, "score": score,
                          "detail": f"ips={','.join(sorted(h.ips)) or '?'} ports={ports}", "reasons": reasons})

    items.sort(key=lambda x: x["score"], reverse=True)
    return items


def summarize(surf: AttackSurface, top: int = 12) -> str:
    """One clean text block: stats, the ranked likely-vulnerable list, findings by severity."""
    st = surf.stats()
    ranked = prioritize(surf)
    out = [f"ATTACK SURFACE — {surf.domain or '(target)'}",
           f"  hosts={st['hosts']}  endpoints={st['endpoints']}  open_ports={st['open_ports']}  findings={st['findings']}",
           ""]
    if ranked:
        out.append(f"MOST LIKELY VULNERABLE (top {min(top, len(ranked))} of {len(ranked)} flagged):")
        for i, it in enumerate(ranked[:top], 1):
            out.append(f"  {i}. [{it['score']:>3}] {it['kind']}: {it['ref']}  ({it['detail']})")
            for r in dict.fromkeys(it["reasons"]):     # dedupe, keep order
                out.append(f"        - {r}")
    else:
        out.append("No high-signal weak points flagged yet (run more tools, or the surface looks hardened).")

    sev_order = ["critical", "high", "medium", "low", "info"]
    if surf.findings:
        by_sev = {s: [f for f in surf.findings if f.severity == s] for s in sev_order}
        out.append("\nFINDINGS BY SEVERITY:")
        for s in sev_order:
            if by_sev[s]:
                out.append(f"  {s.upper()} ({len(by_sev[s])}):")
                for f in by_sev[s][:8]:
                    out.append(f"     {f.ident} — {f.name}  @ {f.location}  [{f.source}]")
    return "\n".join(out)
