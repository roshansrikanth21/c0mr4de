"""Structured per-target engagement logging (bug-bounty style). During an
engagement the agent accumulates leads, confirmed vulns, discovered
endpoints, and working payloads into per-target markdown files it can read
back - so nothing is lost across a long run and a report can be assembled
from real notes. One directory per target under workspace/targets/."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE

_CATEGORIES = {
    "vulnerability": "vulnerabilities.md",
    "endpoint": "endpoints.md",
    "payload": "payloads.md",
    "credential": "credentials.md",
    "note": "notes.md",
}


def _target_dir(target: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target.replace("https://", "").replace("http://", ""))[:60] or "target"
    d = WORKSPACE / "targets" / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def worklog(target: str, category: str, entry: str) -> str:
    cat = category.lower().strip()
    if cat not in _CATEGORIES:
        return f"ERROR: category must be one of {', '.join(_CATEGORIES)}."
    d = _target_dir(target)
    f = d / _CATEGORIES[cat]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(f, "a", encoding="utf-8") as fh:
        fh.write(f"\n### {ts}\n{entry.strip()}\n")
    return f"logged to targets/{d.name}/{_CATEGORIES[cat]}"


def read_worklog(target: str, category: str = "") -> str:
    d = _target_dir(target)
    files = [d / _CATEGORIES[category.lower()]] if category.lower() in _CATEGORIES else sorted(d.glob("*.md"))
    out = []
    for f in files:
        if f.exists():
            out.append(f"===== {f.name} =====\n{f.read_text(encoding='utf-8', errors='replace').strip()}")
    return "\n\n".join(out) if out else f"no worklog yet for {target}. Use worklog() to record findings as you go."


TOOLS = [
    Tool(
        name="worklog",
        description=("Record an engagement note into a per-target file so it's not lost across a long run. "
                     "category: vulnerability, endpoint, payload, credential, or note. Log confirmed vulns, "
                     "discovered endpoints, and working payloads as you find them; assemble the report from these."),
        parameters={
            "type": "object",
            "properties": {"target": {"type": "string"}, "category": {"type": "string"}, "entry": {"type": "string"}},
            "required": ["target", "category", "entry"],
        },
        fn=worklog,
    ),
    Tool(
        name="read_worklog",
        description="Read back what you've logged for a target (all files, or one category) to review accumulated intel before deciding next steps or writing the report.",
        parameters={
            "type": "object",
            "properties": {"target": {"type": "string"}, "category": {"type": "string"}},
            "required": ["target"],
        },
        fn=read_worklog,
    ),
]
