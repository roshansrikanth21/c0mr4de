"""Report generation - assembles findings into a properly structured vulnerability
assessment / penetration test report (template logic lives in c0mr4de/reportgen.py,
kept separate so it's testable without the Tool plumbing) and saves it to the
workspace. This is the "pentest report at your fingertips" piece: the agent
collects findings as it works, then calls write_report to produce a finished,
consistently formatted, sanitized document - no em-dashes or curly quotes reach
the output regardless of what the agent/model wrote."""
from __future__ import annotations

import json
from datetime import date

from c0mr4de.reportgen import generate_report
from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE


def write_report(target: str, findings_json: str, summary: str = "", positives: str = "",
                 report_type: str = "pentest", tester: str = "", scope_in: str = "",
                 scope_out: str = "", testing_window: str = "", authorized_by: str = "",
                 tools_used_json: str = "", attack_narrative: str = "",
                 recommendations_priority: str = "", retest_diff: str = "") -> str:
    """findings_json: a JSON array of objects with keys: title, severity, category,
    description, steps_to_reproduce, proof_of_concept, impact, remediation,
    references (all strings; cvss_score/cvss_vector/affected_component/likelihood/
    references optional). report_type: 'pentest' or 'vulnerability_assessment'.
    verified (bool, optional): set True ONLY if a deterministic tool actually
    confirmed this (execution-confirmed XSS, timing/boolean-diff-confirmed SQLi,
    an HTTP status/response you observed directly, etc.) - not because the model
    reasoned it was plausible from reading a file or a response body. Omit/False
    renders as UNVERIFIED in the report, which is the honest default."""
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as exc:
        return f"ERROR: findings_json is not valid JSON ({exc}). Expected an array of finding objects."
    if not isinstance(findings, list):
        return "ERROR: findings_json must be a JSON array."

    tools_used: list[str] = []
    if tools_used_json:
        try:
            parsed = json.loads(tools_used_json)
            tools_used = parsed if isinstance(parsed, list) else [str(parsed)]
        except json.JSONDecodeError:
            tools_used = [t.strip() for t in tools_used_json.split(",") if t.strip()]

    report = generate_report(
        target=target, findings=findings, summary=summary, positives=positives,
        report_type=report_type, tester=tester, scope_in=scope_in, scope_out=scope_out,
        testing_window=testing_window, authorized_by=authorized_by, tools_used=tools_used,
        attack_narrative=attack_narrative, recommendations_priority=recommendations_priority,
        retest_diff=retest_diff,
    )

    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).capitalize()
        counts[sev] = counts.get(sev, 0) + 1
    count_line = ", ".join(f"{v} {k}" for k, v in counts.items()) or "no findings recorded"

    filename = f"report-{target.replace('/', '_').replace(':', '')}-{date.today().isoformat()}.md"
    (WORKSPACE / filename).write_text(report, encoding="utf-8")
    return f"Report written to workspace/{filename} ({len(findings)} findings: {count_line})"


TOOLS = [
    Tool(
        name="write_report",
        description=(
            "Assemble collected findings into a FORMAL, properly structured report - cover page, "
            "document control, executive summary with a risk table, scope, methodology, findings "
            "summary table, detailed per-finding sections, appendix - and save it to the workspace. "
            "report_type: 'pentest' (default; narrative/exploitation-chain-driven, leads with what an "
            "attacker could actually do) or 'vulnerability_assessment' (inventory/coverage-driven, "
            "broader and shallower, framed around remediation priority). All text is sanitized - no "
            "em-dashes or curly quotes reach the final document regardless of what you write. "
            "findings_json is a JSON array; each finding supports: title, severity, category, "
            "cvss_score, cvss_vector (both optional - skip CVSS unless explicitly asked for), "
            "affected_component, likelihood, description, technical_details, steps_to_reproduce "
            "(mandatory in practice), proof_of_concept (mandatory in practice), impact, remediation, "
            "references (string or list), verified (bool - set True ONLY when a deterministic tool "
            "actually confirmed the finding, e.g. confirm_xss_exec fired, a timing/boolean-diff SQLi "
            "check passed, an HTTP response you observed directly proves it - NOT because the finding "
            "sounds plausible from reading a file or response body. Default/omitted renders as "
            "UNVERIFIED in the report; do not mark something verified to make the report look stronger)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "findings_json": {"type": "string", "description": "JSON array of finding objects"},
                "summary": {"type": "string", "description": "executive summary text"},
                "positives": {"type": "string", "description": "what the target does well, optional"},
                "report_type": {"type": "string", "description": "'pentest' or 'vulnerability_assessment'"},
                "tester": {"type": "string", "description": "who/what performed the assessment"},
                "scope_in": {"type": "string"},
                "scope_out": {"type": "string"},
                "testing_window": {"type": "string"},
                "authorized_by": {"type": "string"},
                "tools_used_json": {"type": "string", "description": "JSON array or comma-separated list of tools used"},
                "attack_narrative": {"type": "string", "description": "pentest-style: how findings chained together, optional"},
                "recommendations_priority": {"type": "string", "description": "prioritized remediation order, optional"},
                "retest_diff": {"type": "string", "description": "for a re-test round: what's fixed/still open/new, optional"},
            },
            "required": ["target", "findings_json"],
        },
        fn=write_report,
    ),
]
