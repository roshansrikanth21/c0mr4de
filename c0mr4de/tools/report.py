"""Report generation - assembles findings into Roshan's standard report
format (see playbooks/report-writing-template.md) and saves it to the
workspace. This is the "pentest report at your fingertips" piece: the
agent collects findings as it works, then calls write_report to produce
a finished, consistently-formatted document."""
from __future__ import annotations

import json
from datetime import date

from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_report(target: str, findings_json: str, summary: str = "", positives: str = "") -> str:
    """findings_json: a JSON array of objects with keys:
    title, severity, category, description, steps_to_reproduce, proof_of_concept,
    impact, remediation, references (all strings; references optional)."""
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as exc:
        return f"ERROR: findings_json is not valid JSON ({exc}). Expected an array of finding objects."
    if not isinstance(findings, list):
        return "ERROR: findings_json must be a JSON array."

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 5))

    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).capitalize()
        counts[sev] = counts.get(sev, 0) + 1
    count_line = ", ".join(f"{v} {k}" for k, v in counts.items()) or "no findings recorded"

    lines = [
        f"# Security Assessment Report: {target}",
        f"\n*Date: {date.today().isoformat()}*",
        "\n## Executive Summary\n",
        summary or "_(summary not provided)_",
        f"\n**Findings by severity:** {count_line}",
        "\n## Findings\n",
    ]

    for i, f in enumerate(findings, 1):
        lines.append(f"### Finding {i}: {f.get('title', 'Untitled')}\n")
        lines.append(f"**Severity:** {f.get('severity', 'Info')}")
        lines.append(f"**Vulnerability Category:** {f.get('category', 'N/A')}\n")
        lines.append(f"**Description:** {f.get('description', '')}\n")
        lines.append(f"**Technical Details:** {f.get('technical_details', '')}\n")
        lines.append(f"**Steps to Reproduce:**\n{f.get('steps_to_reproduce', '')}\n")
        lines.append(f"**Proof of Concept:**\n{f.get('proof_of_concept', '')}\n")
        lines.append(f"**Impact:** {f.get('impact', '')}\n")
        lines.append(f"**Remediation:** {f.get('remediation', '')}\n")
        if f.get("references"):
            lines.append(f"**References:** {f['references']}\n")

    if positives:
        lines.append("## Positives\n")
        lines.append(positives)

    report = "\n".join(lines)
    filename = f"report-{target.replace('/', '_').replace(':', '')}-{date.today().isoformat()}.md"
    (WORKSPACE / filename).write_text(report, encoding="utf-8")
    return f"Report written to workspace/{filename} ({len(findings)} findings: {count_line})"


TOOLS = [
    Tool(
        name="write_report",
        description=(
            "Assemble collected findings into a finished pentest report in the standard format and "
            "save it to the workspace. Call this once you've gathered your findings. findings_json is a "
            "JSON array; each finding has: title, severity, category, description, technical_details, "
            "steps_to_reproduce, proof_of_concept, impact, remediation, references."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "findings_json": {"type": "string", "description": "JSON array of finding objects"},
                "summary": {"type": "string", "description": "executive summary text"},
                "positives": {"type": "string", "description": "what the target does well, optional"},
            },
            "required": ["target", "findings_json"],
        },
        fn=write_report,
    ),
]
