"""Formal report generator - vulnerability assessment / penetration test report
template. Separated from tools/report.py (the thin Tool wrapper) so the template
logic is testable without the Tool plumbing, matching the surface/ + tools/
surface.py and memory/graph.py + tools-wrapper pattern already used in this repo.

Produces a properly structured document - cover page, document control, executive
summary with a risk table, scope, methodology, findings summary table, detailed
per-finding sections, positive observations, appendix - in TWO profiles, since
pentest and VA reports genuinely differ in real practice:

  pentest                : narrative / exploitation-chain driven. Leads with what
                            an attacker could ACTUALLY do, chains findings together.
  vulnerability_assessment: inventory / coverage driven. Broader, shallower, framed
                            around confirmed issues and remediation priority rather
                            than a narrative of compromise.

Every text field is sanitized before it reaches the document: em-dashes and curly
quotes are not acceptable typography for a client deliverable, and the model
writing the finding text cannot be trusted to avoid them on its own, so
sanitize_text() strips/normalizes them deterministically regardless of input.

Follows the structure already established in playbooks/report-writing-template.md
(Roshan's per-finding format from the PINERP audit onward) - skip CVSS unless asked
for, mandatory steps-to-reproduce + PoC, positives section, optional re-test diff.
"""
from __future__ import annotations

import re
from datetime import date

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_CVSS_RANGE = {
    "critical": "9.0 - 10.0", "high": "7.0 - 8.9", "medium": "4.0 - 6.9",
    "low": "0.1 - 3.9", "info": "0.0 (informational)",
}
_SEVERITY_DEF = {
    "critical": ("Immediate exploitation risk with severe impact - typically unauthenticated "
                "remote compromise, full data exposure, or complete loss of confidentiality, "
                "integrity, or availability. Requires urgent remediation."),
    "high": ("Significant risk of exploitation with serious impact - may require some "
            "precondition (e.g. low-privilege access) but leads to major compromise. "
            "Should be remediated as a priority."),
    "medium": ("Moderate risk - exploitation requires specific conditions or yields limited "
              "impact. Should be remediated in the normal patch cycle."),
    "low": "Minor risk - difficult to exploit or yields minimal impact. Remediate when convenient.",
    "info": ("No direct security risk, but worth noting for hardening, awareness, or as "
            "supporting context for other findings."),
}


def sanitize_text(text) -> str:
    """Strip typographic punctuation that does not belong in a formal deliverable -
    em dashes, en dashes, and curly quotes - regardless of what the source contains.
    An en/em dash directly between two digits (a range, e.g. "10-20") becomes a
    plain hyphen with no spaces; anywhere else it becomes a plain hyphen with spaces,
    matching how the same sentence would normally be written without a dash."""
    if text is None:
        return ""
    s = str(text)
    s = re.sub(r"(?<=\d)[–—](?=\d)", "-", s)   # digit-dash-digit -> plain range
    s = re.sub(r"\s*[–—]\s*", " - ", s)          # any remaining em/en dash
    s = s.replace("‘", "'").replace("’", "'")     # curly single quotes
    s = s.replace("“", '"').replace("”", '"')     # curly double quotes
    s = s.replace("…", "...")                           # ellipsis character
    return s


def _san_all(obj):
    """Recursively sanitize every string in a dict/list structure; other types pass through."""
    if isinstance(obj, dict):
        return {k: _san_all(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_san_all(v) for v in obj]
    if isinstance(obj, str):
        return sanitize_text(obj)
    return obj


def _toc(sections: list[str]) -> str:
    lines = ["## Table of Contents", ""]
    for i, s in enumerate(sections, 1):
        anchor = s.lower().replace(" ", "-").replace("/", "")
        lines.append(f"{i}. [{s}](#{anchor})")
    return "\n".join(lines)


def generate_report(
    target: str,
    findings: list[dict],
    summary: str = "",
    positives: str = "",
    report_type: str = "pentest",
    tester: str = "",
    scope_in: str = "",
    scope_out: str = "",
    testing_window: str = "",
    authorized_by: str = "",
    tools_used: list[str] | None = None,
    attack_narrative: str = "",
    recommendations_priority: str = "",
    retest_diff: str = "",
) -> str:
    """Build the full report body as a markdown string.

    report_type: 'pentest' (default) or 'vulnerability_assessment' ('va' also
    accepted). Each finding dict supports: title, severity, category,
    cvss_score, cvss_vector (both optional - skip CVSS unless explicitly
    requested, per the house convention), affected_component/location,
    likelihood, description, technical_details, steps_to_reproduce (mandatory
    in practice), proof_of_concept (mandatory in practice), impact,
    remediation, references (string or list)."""
    is_va = report_type.lower() in ("vulnerability_assessment", "va", "vuln_assessment")
    doc_title = "Vulnerability Assessment Report" if is_va else "Penetration Test Report"

    findings = _san_all(findings or [])
    summary = sanitize_text(summary)
    positives = sanitize_text(positives)
    attack_narrative = sanitize_text(attack_narrative)
    recommendations_priority = sanitize_text(recommendations_priority)
    retest_diff = sanitize_text(retest_diff)
    tester = sanitize_text(tester) or "c0mr4de autonomous assessment"

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 5))

    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    today = date.today().isoformat()

    out: list[str] = []

    # ---- Cover page ----
    out += [
        f"# {doc_title}", "", "**CONFIDENTIAL**", "",
        f"**Target:** {target}",
        f"**Report Date:** {today}",
        f"**Prepared By:** {tester}",
        "**Report Version:** 1.0",
        "", "---", "",
    ]

    # ---- Document control ----
    out += [
        "## Document Control", "",
        "| Version | Date | Author | Summary of Changes |",
        "|---|---|---|---|",
        f"| 1.0 | {today} | {tester} | Initial report |",
        "",
    ]

    # ---- Table of contents ----
    sections = ["Executive Summary", "Scope", "Methodology", "Findings Summary", "Detailed Findings"]
    if attack_narrative:
        sections.insert(4, "Attack Narrative")
    if retest_diff:
        sections.append("Re-Test Results")
    if positives:
        sections.append("Positive Observations")
    if recommendations_priority:
        sections.append("Prioritized Recommendations")
    sections.append("Appendix")
    out += [_toc(sections), "", "---", ""]

    # ---- Executive summary ----
    out += ["## Executive Summary", ""]
    out.append(summary or "_No executive summary was provided for this assessment._")
    out += ["", "### Risk Rating Summary", "", "| Severity | Count | CVSS Range |", "|---|---:|---|"]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            out.append(f"| {sev.capitalize()} | {counts[sev]} | {_SEVERITY_CVSS_RANGE[sev]} |")
    if not findings:
        out.append("| - | 0 | No findings recorded |")
    out.append("")
    overall = ("Critical" if counts.get("critical") else "High" if counts.get("high") else
              "Medium" if counts.get("medium") else "Low" if counts.get("low") else "Informational")
    urgent = counts.get("critical", 0) + counts.get("high", 0)
    out.append(f"**Overall Risk Posture:** {overall}" +
              (f" - {urgent} finding(s) require urgent attention." if urgent else "."))
    out += ["", "---", ""]

    # ---- Scope ----
    out += ["## Scope", ""]
    out.append(f"**In Scope:** {sanitize_text(scope_in) or target}")
    out.append(f"**Out of Scope:** {sanitize_text(scope_out) or 'Not explicitly restricted beyond the in-scope target(s) above.'}")
    out.append(f"**Testing Window:** {sanitize_text(testing_window) or today}")
    out.append(f"**Authorized By:** {sanitize_text(authorized_by) or 'Engagement owner (see engagement records)'}")
    out += ["", "---", ""]

    # ---- Methodology ----
    out += ["## Methodology", ""]
    if is_va:
        out.append(
            "This assessment followed a structured vulnerability assessment methodology: "
            "asset and attack-surface enumeration, automated and manual vulnerability scanning, "
            "false-positive triage, and risk-based prioritization of confirmed issues. "
            "Exploitation was performed only where needed to confirm a finding, not to achieve maximum impact."
        )
    else:
        out.append(
            "This assessment followed a structured penetration testing methodology aligned with "
            "industry practice (OWASP Testing Guide / PTES phases): reconnaissance and attack-surface "
            "mapping, vulnerability discovery, exploitation and impact validation, and where possible, "
            "chaining of findings to demonstrate realistic business impact."
        )
    out.append("")
    if tools_used:
        out.append("**Tools Used:** " + ", ".join(sanitize_text(t) for t in tools_used))
    out += ["", "---", ""]

    # ---- Findings summary table ----
    out += ["## Findings Summary", ""]
    if findings:
        out += ["| # | Title | Severity | Component |", "|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            out.append(f"| {i} | {f.get('title', 'Untitled')} | {str(f.get('severity', 'info')).upper()} | "
                       f"{f.get('affected_component') or f.get('location') or '-'} |")
    else:
        out.append("No findings were confirmed during this assessment.")
    out += ["", "---", ""]

    # ---- Attack narrative (pentest only, if provided) ----
    if attack_narrative:
        out += ["## Attack Narrative", "", attack_narrative, "", "---", ""]

    # ---- Detailed findings ----
    out += ["## Detailed Findings", ""]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity", "info")).lower()
        out += [f"### Finding {i}: {f.get('title', 'Untitled')}", "",
                "| | |", "|---|---|", f"| **Severity** | {sev.upper()} |"]
        if f.get("cvss_score"):
            out.append(f"| **CVSS Score** | {f['cvss_score']} |")
        if f.get("cvss_vector"):
            out.append(f"| **CVSS Vector** | {f['cvss_vector']} |")
        out.append(f"| **Category** | {f.get('category', 'N/A')} |")
        if f.get("affected_component") or f.get("location"):
            out.append(f"| **Affected Component** | {f.get('affected_component') or f.get('location')} |")
        if f.get("likelihood"):
            out.append(f"| **Likelihood** | {f['likelihood']} |")
        out.append("")
        for label, key, code in (
            ("Description", "description", False), ("Technical Details", "technical_details", False),
            ("Steps to Reproduce", "steps_to_reproduce", False), ("Proof of Concept", "proof_of_concept", True),
            ("Impact", "impact", False), ("Remediation", "remediation", False),
        ):
            if f.get(key):
                out.append(f"**{label}**")
                out.append("")
                if code:
                    out += ["```", f[key], "```"]
                else:
                    out.append(f[key])
                out.append("")
        if f.get("references"):
            refs = f["references"]
            out.append("**References**")
            out.append("")
            if isinstance(refs, list):
                out += [f"- {r}" for r in refs]
            else:
                out.append(str(refs))
            out.append("")
        out += ["---", ""]

    # ---- Re-test results (optional) ----
    if retest_diff:
        out += ["## Re-Test Results", "", retest_diff, "", "---", ""]

    # ---- Positive observations ----
    if positives:
        out += ["## Positive Observations", "", positives, "", "---", ""]

    # ---- Prioritized recommendations (optional) ----
    if recommendations_priority:
        out += ["## Prioritized Recommendations", "", recommendations_priority, "", "---", ""]

    # ---- Appendix ----
    out += ["## Appendix", "", "### Severity Definitions", "", "| Severity | Definition |", "|---|---|"]
    for sev in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {sev.capitalize()} | {_SEVERITY_DEF[sev]} |")
    out += [
        "", "### Limitations", "",
        ("This assessment reflects the state of the target at the time of testing. It is not "
         "exhaustive: findings are limited to what was discovered within the defined scope and "
         "testing window, and the absence of a finding does not guarantee the absence of vulnerabilities."),
        "",
    ]
    return "\n".join(out)
