"""Per-chat roles (Hermes-style profiles).

Each chat can be a SPECIALIST instead of a generalist with every tool: a role
scopes c0mr4de to a focused capability set (which tools are callable) and injects
a methodology focus into the agent. The UI picks a role per chat and shows its
capability digest. 'general' keeps everything, so this is purely additive.
"""
from __future__ import annotations

from c0mr4de.tools.base import ToolRegistry

DEFAULT_ROLE = "general"

# Tools every role gets - workspace, memory, reporting, PoC, self-check.
_ALWAYS = {
    "read_file", "write_file", "list_workspace", "worklog", "read_worklog",
    "ask_operator", "consult_knowledge", "recall_related", "write_report",
    "make_poc", "env_report", "ocr_image",
}

ROLES: dict[str, dict] = {
    "general": {
        "label": "General",
        "desc": "Full toolset - a generalist operator with every capability enabled.",
        "tools": None,  # None = no filter (all tools)
        "focus": "",
    },
    "bug_bounty": {
        "label": "Bug bounty",
        "desc": "Web vuln hunting - recon a target, find and execution-confirm web vulns, chain them, PoC, report.",
        "tools": {"http_request", "crawl_site", "crawl", "probe", "test_injection", "test_all_params",
                  "fuzz_paths", "fuzz_param", "nuclei_scan", "browser_navigate", "browser_storage",
                  "browser_eval", "browser_screenshot", "oob_start", "oob_poll", "decode_jwt", "tamper_jwt",
                  "burp_import", "katana_crawl", "gau_urls", "map_attack_surface", "subfinder",
                  "search_writeups", "fetch_writeup"},
        "focus": ("You are a focused bug-bounty hunter. Prioritise high-signal web vulns (IDOR, SQLi, XSS, "
                  "SSRF, auth / access-control, business logic). CONFIRM every finding deterministically "
                  "(execution-confirmed XSS, timing or boolean SQLi, OOB callback) before reporting - a "
                  "response code alone is never a finding. Chain findings for impact, attach a PoC with "
                  "make_poc, and report only what you actually proved."),
    },
    "ctf": {
        "label": "CTF",
        "desc": "Capture-the-flag - web / crypto / forensics / reversing / pwn; solve the challenge, get the flag.",
        "tools": {"http_request", "crawl_site", "browser_navigate", "browser_eval", "browser_screenshot",
                  "oob_start", "oob_poll", "decode_jwt", "tamper_jwt", "fuzz_paths", "fuzz_param",
                  "test_injection", "search_writeups", "fetch_writeup"},
        "focus": ("You are a CTF player. The goal is the FLAG, not a report. Move fast, try the standard "
                  "exploitation paths for the challenge category, and recognise flag formats (flag{...}, "
                  "MIRAGE{...}, etc.). Consult the playbooks / ctf knowledge for the category's known tricks."),
    },
    "source_audit": {
        "label": "Source audit",
        "desc": "White-box code review - trace user input to dangerous sinks, confirm the dataflow, PoC.",
        "tools": {"audit_source", "semgrep_scan", "search_writeups", "fetch_writeup"},
        "focus": ("You are a source-code auditor. Use audit_source and semgrep_scan to surface candidate "
                  "input->sink flows, then READ the full functions and trace the real dataflow (it can cross "
                  "files) before claiming anything. Every SAST / regex hit is a LEAD - confirm exploitability "
                  "against the matching playbook, attach a PoC, and mark a finding verified ONLY when you "
                  "genuinely confirmed the flow."),
    },
    "osint": {
        "label": "OSINT",
        "desc": "Open-source intelligence - investigate a person / handle / email / domain, map the graph.",
        "tools": {"username_search", "email_osint", "google_dork", "add_osint_note", "render_osint_graph",
                  "crt_sh", "urlscan_search", "shodan_host", "virustotal_lookup", "abuseipdb_check",
                  "otx_indicator", "greynoise_check", "http_request", "fetch_writeup"},
        "focus": ("You are an OSINT investigator. Pivot across handles, emails, domains and infrastructure; "
                  "record every entity and relationship with add_osint_note and render the graph. State "
                  "confidence - distinguish confirmed links from inferred ones. Stay PASSIVE; do not actively "
                  "attack the target."),
    },
    "recon": {
        "label": "Recon",
        "desc": "Attack-surface mapping - enumerate, probe, and structure the surface; no exploitation.",
        "tools": {"map_attack_surface", "import_scan", "attack_surface_report", "amass_enum", "naabu_scan",
                  "subfinder", "shodan_host", "katana_crawl", "gau_urls", "tlsx_sans", "dnsx_resolve",
                  "nuclei_scan", "reconftw", "probe", "crawl", "crawl_site", "http_request"},
        "focus": ("You map attack surface and STOP before exploitation. Enumerate subdomains, resolve and "
                  "prune them, probe live hosts and tech, pull historical URLs, and structure it all into the "
                  "attack surface; hand off a prioritised 'where is it most likely vulnerable' view. "
                  "Detection-only - no active exploitation."),
    },
    "red_team": {
        "label": "Red team",
        "desc": "Objective-driven engagement - recon to foothold to lateral / privesc to objective, mapped to ATT&CK.",
        "tools": {"http_request", "crawl_site", "crawl", "probe", "test_injection", "test_all_params",
                  "fuzz_paths", "fuzz_param", "nuclei_scan", "browser_navigate", "browser_eval", "oob_start",
                  "oob_poll", "decode_jwt", "tamper_jwt", "map_attack_surface", "subfinder", "amass_enum",
                  "naabu_scan", "katana_crawl", "gau_urls", "tlsx_sans", "dnsx_resolve", "shodan_host",
                  "reconftw", "search_writeups", "fetch_writeup"},
        "focus": ("You run an objective-driven engagement: recon -> initial access -> escalate -> lateral "
                  "movement -> objective, mapping each technique to MITRE ATT&CK. Prefer stealthy, confirmed "
                  "steps; chain findings toward the crown-jewel objective and narrate the attack path."),
    },
}


def role_names() -> list[str]:
    return list(ROLES.keys())


def get_role(name: str) -> dict:
    return ROLES.get(name or DEFAULT_ROLE, ROLES[DEFAULT_ROLE])


def filter_registry(registry: ToolRegistry, role_name: str) -> ToolRegistry:
    """Return a registry scoped to the role's tools (+ the always-on set). The
    'general' role (tools=None) returns the registry unchanged. Tools a role names
    but that are not registered are simply skipped."""
    role = get_role(role_name)
    allow = role["tools"]
    if allow is None:
        return registry
    keep = _ALWAYS | allow
    scoped = ToolRegistry()
    for name in registry.names():
        if name in keep:
            scoped.register(registry.get(name))
    return scoped


def role_focus(name: str) -> str:
    """The methodology focus for this role, injected into the agent's task."""
    return get_role(name)["focus"]


def role_digest(name: str, registry: ToolRegistry | None = None) -> dict:
    """A capability digest for a role (what this chat can do) - for the UI."""
    role = get_role(name)
    if role["tools"] is None:
        tools = sorted(registry.names()) if registry is not None else []
        count = len(tools) if registry is not None else None
        cap = "all tools enabled"
    else:
        tools = sorted(_ALWAYS | role["tools"])
        if registry is not None:
            present = set(registry.names())
            tools = [t for t in tools if t in present]
        count = len(tools)
        cap = f"{count} tools"
    return {
        "name": name,
        "label": role["label"],
        "desc": role["desc"],
        "focus": role["focus"],
        "tools": tools,
        "tool_count": count,
        "capabilities": cap,
    }
