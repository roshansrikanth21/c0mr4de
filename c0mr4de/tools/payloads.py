"""Payload bank - serve real attack payloads from a local PayloadsAllTheThings
(PATT) clone to the exploit specialists.

c0mr4de is validation-first: it confirms with a deterministic signal, it doesn't
spray. But when the standard payload is filtered/WAF'd, a specialist needs VARIANTS
to get past the filter - that's exactly what PATT's Intruder wordlists are. This
tool indexes the local clone by vuln class and returns a capped, deduped, optionally
filtered list of payloads to try. Every hit still goes through verify_finding.

PATT is NOT redistributed in this repo (licensing + size) - this reads your local
clone at _corpus_src/PayloadsAllTheThings (override with C0MR4DE_PATT_DIR). If it's
absent the tool says how to clone it. Pure file I/O: no model, no network, no embedder.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from c0mr4de.tools.base import Tool

_REPO = Path(__file__).resolve().parent.parent.parent

# vuln-class alias -> PATT top-level folder name
_CATEGORIES = {
    "sqli": "SQL Injection", "sql": "SQL Injection",
    "xss": "XSS Injection",
    "ssrf": "Server Side Request Forgery",
    "ssti": "Server Side Template Injection", "template": "Server Side Template Injection",
    "xxe": "XXE Injection",
    "lfi": "File Inclusion", "rfi": "File Inclusion", "file_inclusion": "File Inclusion",
    "traversal": "Directory Traversal", "path_traversal": "Directory Traversal", "lfd": "Directory Traversal",
    "command": "Command Injection", "cmdi": "Command Injection", "rce": "Command Injection",
    "nosql": "NoSQL Injection",
    "ldap": "LDAP Injection",
    "open_redirect": "Open Redirect", "redirect": "Open Redirect",
    "jwt": "JSON Web Token",
    "crlf": "CRLF Injection",
    "csv": "CSV Injection",
    "deserialization": "Insecure Deserialization", "deser": "Insecure Deserialization",
    "graphql": "GraphQL Injection",
    "prototype": "Prototype Pollution", "prototype_pollution": "Prototype Pollution",
    "idor": "Insecure Direct Object References",
    "csrf": "Cross-Site Request Forgery",
}
_FENCE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)```", re.S)


def _patt_dir() -> Path:
    env = os.environ.get("C0MR4DE_PATT_DIR")
    return Path(env) if env else (_REPO / "_corpus_src" / "PayloadsAllTheThings")


def _looks_payload(line: str) -> bool:
    line = line.strip()
    if not line or line.startswith(("#", ">", "|", "---", "* ", "- [", "[!")) or len(line) > 400:
        return False
    # keep lines that look like payloads, not prose: contain a payload-ish char,
    # or no spaces, or are short. Drop obvious sentences.
    if re.search(r"[<>'\";{}()$|&=/\\]|SELECT|UNION|SLEEP|script|alert|\.\./|%2e|exec|\bOR\b", line, re.I):
        return len(line.split()) <= 25
    return " " not in line and len(line) <= 120


def _gather(folder: Path, cap: int, contains: str) -> list[str]:
    files: list[Path] = []
    intr = folder / "Intruder"
    if intr.is_dir():
        files += [f for f in sorted(intr.iterdir()) if f.is_file()]
    files += sorted(folder.rglob("*.txt"))
    lines: list[str] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        lines += [ln.strip() for ln in text.splitlines() if _looks_payload(ln)]
    if not lines:                                   # no wordlists -> mine README fenced code
        rm = folder / "README.md"
        if rm.exists():
            for block in _FENCE.findall(rm.read_text(encoding="utf-8", errors="ignore")):
                lines += [ln.strip() for ln in block.splitlines() if _looks_payload(ln)]
    seen, out = set(), []
    for ln in lines:
        if contains and contains.lower() not in ln.lower():
            continue
        if ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
        if len(out) >= cap:
            break
    return out


def list_payload_categories() -> str:
    base = _patt_dir()
    present = sorted({name for name in set(_CATEGORIES.values()) if (base / name).is_dir()}) if base.exists() else []
    aliases = sorted(set(_CATEGORIES))
    return ("payload categories: " + ", ".join(aliases) +
            (f"\n(available in your PATT clone: {', '.join(present)})" if present else
             f"\nPATT clone not found at {base}."))


def payloads(category: str, contains: str = "", limit: int = 40) -> str:
    """Real attack payloads for a vuln class from the local PayloadsAllTheThings
    clone - variants to try when the standard payload is filtered. Confirm every hit
    with verify_finding; a payload that lands is a lead, not a finding."""
    base = _patt_dir()
    if not base.exists():
        return ("PayloadsAllTheThings not found. Clone it (once):\n"
                "  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings "
                "_corpus_src/PayloadsAllTheThings\n(or set C0MR4DE_PATT_DIR to an existing clone).")
    folder_name = _CATEGORIES.get((category or "").lower().strip())
    if not folder_name:
        return "unknown category. " + list_payload_categories()
    folder = base / folder_name
    if not folder.is_dir():
        return f"'{folder_name}' not in your PATT clone. " + list_payload_categories()
    items = _gather(folder, limit, contains)
    if not items:
        return f"no payloads extracted for '{category}'" + (f" matching '{contains}'" if contains else "") + "."
    head = (f"{len(items)} '{category}' payloads from PayloadsAllTheThings ({folder_name})" +
            (f" matching '{contains}'" if contains else "") +
            ". Try these when the standard payload is filtered, then CONFIRM with verify_finding:\n")
    return head + "\n".join("  " + p for p in items)


TOOLS = [
    Tool(
        name="payloads",
        description=(
            "Real attack payloads for a vuln class (sqli, xss, ssrf, ssti, xxe, lfi, traversal, command, "
            "nosql, ldap, open_redirect, jwt, crlf, graphql, deserialization, prototype, idor, csrf) from "
            "the PayloadsAllTheThings bank - WAF/filter-bypass variants to try when the standard payload is "
            "blocked. Optional `contains` filters (e.g. 'mysql', 'bypass'). Confirm any hit with verify_finding."
        ),
        parameters={"type": "object", "properties": {
            "category": {"type": "string"},
            "contains": {"type": "string"},
            "limit": {"type": "integer"}}, "required": ["category"]},
        fn=payloads,
    ),
]
