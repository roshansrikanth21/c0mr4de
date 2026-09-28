"""Per-step tool-schema selection — send the model only the tools that matter
right now, not all ~42.

Why: every request ships the full tool schema set, and ~42 schemas is a big fixed
token cost that pushes free-tier requests over Groq's 8000 TPM ceiling (a live run
died on an empty reply from exactly this). Trimming to a relevant, capped subset
cuts the per-request floor by ~60% while keeping the loop capable.

How: a small always-on CORE set + groups unlocked by keywords in the task and the
recent context + any tool already used this run (so the visible set stays
consistent as the run evolves). The FULL registry stays executable — trimming only
changes what the model SEES/prefers, so a tool called from memory still runs.
Re-selected each step, so JWT tools appear once a token shows up, etc.
Deterministic, no extra model round-trip. Disable with AgentLoop(trim_tools=False)."""
from __future__ import annotations

# Always available — the essential ReAct loop for any web engagement.
CORE = ["http_request", "crawl_site", "test_injection", "consult_knowledge",
        "recall_related", "write_report", "worklog", "read_worklog", "ask_operator",
        "browser_navigate"]

# keyword tuple -> tools unlocked when any keyword appears in task/context.
GROUPS: list[tuple[tuple[str, ...], list[str]]] = [
    (("jwt", "token", "bearer", "session", "cookie", "auth", "login", "sso"),
     ["decode_jwt", "tamper_jwt", "browser_storage", "browser_eval"]),
    (("sql", "sqli", "injection", "inject", "xss", "error-based"),
     ["sqlmap", "fuzz_param", "oob_start", "oob_poll"]),
    (("ssrf", "xxe", "blind", "rce", "oob", "out-of-band", "out of band", "deserial", "ssti", "smuggl"),
     ["oob_start", "oob_poll"]),
    (("idor", "access control", "privilege", "broken access", "authorization", "param"),
     ["fuzz_param"]),
    (("subdomain", "attack surface", "surface", "amass", "recon a domain", "map the"),
     ["map_attack_surface", "subfinder", "amass_enum", "attack_surface_report", "import_scan"]),
    (("port", "naabu", "service"), ["naabu_scan"]),
    (("shodan", "exposed host", "internet-exposed"), ["shodan_host"]),
    (("recon", "enumerat", "fingerprint", "discover", "spider", "endpoint", "hidden", "directory"),
     ["crawl", "probe", "fuzz_paths"]),
    (("nuclei", "cve", "template", "misconfig", "exposure"), ["nuclei_scan"]),
    (("osint", "email", "username", "person", "people", "handle", "profile", "who is", "behind the email"),
     ["email_osint", "username_search", "google_dork", "add_osint_note", "render_osint_graph"]),
    (("writeup", "ctf", "challenge", "how others", "reference", "prior art"),
     ["search_writeups", "fetch_writeup"]),
    (("burp", "caido", "proxy history", "har"), ["burp_import"]),
    (("screenshot", "image", "ocr", "photo", "read the token from"),
     ["ocr_image", "browser_screenshot"]),
    (("javascript", "dom", "localstorage", "storage", "render", "spa", "client-side"),
     ["browser_storage", "browser_eval", "browser_screenshot"]),
    (("file", "workspace", "save", "note"), ["read_file", "write_file", "list_workspace"]),
    (("subfinder", "reconftw"), ["subfinder", "reconftw"]),
]


def select_names(task: str, context_text: str, used: set[str], available: set[str], cap: int = 18) -> list[str]:
    """Choose which tool names to expose. Order: CORE, then already-used (kept for
    consistency), then keyword-unlocked groups. Capped, with CORE+used protected."""
    text = f"{task} {context_text}".lower()
    picked: list[str] = [n for n in CORE if n in available]
    for n in sorted(used):                       # tools already used this run survive the cap
        if n in available and n not in picked:
            picked.append(n)
    for keys, tools in GROUPS:
        if any(k in text for k in keys):
            for t in tools:
                if t in available and t not in picked:
                    picked.append(t)
    return picked[:cap] if len(picked) > cap else picked


def select_schemas(registry, task: str, context_text: str = "", used: set[str] | None = None,
                   cap: int = 18) -> list[dict]:
    names = set(select_names(task, context_text, used or set(), set(registry.names()), cap))
    return [s for s in registry.schemas() if s["name"] in names]
