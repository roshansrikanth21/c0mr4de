"""Hivemind specialists. Each is a domain expert: a focused mandate, a scoped
tool subset, and domain-grounded via consult_knowledge (RAG over the playbooks),
NOT a fine-tuned model. They run as ordinary AgentLoops.

Specialists are grouped into PHASES. Specialists WITHIN a phase run in PARALLEL
(threads - real speedup on a hosted backend; a single local model serializes
gracefully at the model). PHASES run in SEQUENCE, so recon informs exploitation
and only verified findings reach the report. This is a DAG, not a free-for-all:
there is no cycle where A waits on B while B waits on A.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from c0mr4de.tools import build_default_registry
from c0mr4de.tools.base import ToolRegistry


@dataclass
class AgentProfile:
    name: str
    domain: str
    system: str
    tool_names: list[str]
    posts: str = "notes"   # bucket captured outputs land in: surface | leads | confirmed | notes
    phase: str = ""

    def registry(self) -> ToolRegistry:
        full = build_default_registry()
        scoped = ToolRegistry()
        for n in self.tool_names:
            t = full.get(n)
            if t:
                scoped.register(t)
        return scoped


_CONSULT = ["consult_knowledge", "recall_related"]

# ---- RECON phase (runtime DAST branch + source SAST branch, in parallel) ----

RUNTIME_RECON = AgentProfile(
    name="runtime-recon", domain="recon", posts="surface", phase="recon",
    system=("You are the RUNTIME RECON specialist in a pentest hivemind. Map the live target's attack surface "
            "for the exploitation specialists who run after you: enumerate endpoints/paths/params, fingerprint "
            "the stack, find auth mechanism, tokens/cookies, and admin/non-prod surface. Do NOT exploit - just "
            "discover and summarise the surface and which spots look most promising. consult_knowledge for the "
            "stack you find. Be thorough but fast; issue real tool calls."),
    tool_names=["map_attack_surface", "import_scan", "attack_surface_report", "amass_enum", "naabu_scan",
                "shodan_host", "crawl", "crawl_site", "probe", "fuzz_paths", "fuzz_param", "http_request",
                "browser_navigate", "browser_storage", "subfinder", "katana_crawl", "gau_urls", "nuclei_scan",
                "env_report", *_CONSULT],
)

CODE_AUDIT = AgentProfile(
    name="code-audit", domain="source audit", posts="surface", phase="recon",
    system=("You are the SOURCE-CODE AUDIT specialist in a pentest hivemind, running IN PARALLEL with runtime "
            "recon. If source is available in the workspace, trace user input to dangerous sinks with "
            "audit_source and semgrep_scan, then READ the real functions to confirm the dataflow. Post concrete "
            "input->sink candidates (file + param + sink) as surface for the exploitation specialists to drive "
            "and verify at runtime. Every SAST hit is a LEAD, not a finding. If there is no source, say so and stop."),
    tool_names=["audit_source", "semgrep_scan", "read_file", "list_workspace", "search_writeups", "fetch_writeup",
                *_CONSULT],
)

# ---- EXPLOIT phase (one specialist per vuln class, in parallel) ----

INJECTION = AgentProfile(
    name="injection", domain="SQLi/command injection", posts="leads", phase="exploit",
    system=("You are the INJECTION specialist (SQLi, command, template, LDAP) in a pentest hivemind. Use the "
            "shared attack surface instead of re-enumerating. Test injectable params, and CONFIRM every hit with "
            "verify_finding (claim=sqli) before claiming it - a response code or an error string alone is not "
            "proof. For blind cases use oob_start/oob_poll. consult_knowledge for the DB/stack. Attach a PoC."),
    tool_names=["http_request", "crawl_site", "test_injection", "test_all_params", "verify_finding",
                "oob_start", "oob_poll", "make_poc", *_CONSULT],
)

CLIENT_SIDE = AgentProfile(
    name="client-side", domain="XSS/SSRF", posts="leads", phase="exploit",
    system=("You are the CLIENT-SIDE & SSRF specialist (XSS, SSRF, open redirect) in a pentest hivemind. Use the "
            "shared surface. For XSS, CONFIRM execution with verify_finding (claim=xss) - reflection is not "
            "execution. For SSRF/blind use verify_finding (claim=ssrf) with oob_start. For redirects use "
            "claim=open_redirect. Never report what you did not confirm. Attach a PoC."),
    tool_names=["http_request", "test_injection", "browser_navigate", "browser_eval", "browser_storage",
                "oob_start", "oob_poll", "verify_finding", "make_poc", *_CONSULT],
)

ACCESS_CONTROL = AgentProfile(
    name="access-control", domain="IDOR/BOLA/authz", posts="leads", phase="exploit",
    system=("You are the ACCESS-CONTROL specialist (IDOR, BOLA, broken authorization) in a pentest hivemind. Use "
            "the shared surface and the operator session. To CONFIRM an IDOR, use verify_finding (claim=idor) with "
            "a control request (the same endpoint with YOUR own id) AND the victim's unique marker - differing "
            "bodies alone are NOT proof. Attach a PoC. Report only confirmed cross-user access."),
    tool_names=["http_request", "crawl_site", "verify_finding", "decode_jwt", "make_poc", *_CONSULT],
)

AUTH = AgentProfile(
    name="auth", domain="auth/session/JWT", posts="leads", phase="exploit",
    system=("You are the AUTHENTICATION & SESSION specialist (JWT, session, token) in a pentest hivemind. Decode "
            "any JWT, and to test whether the server verifies signatures use verify_finding (claim=jwt, field, "
            "value) - it checks that a tampered-payload token is accepted while a corrupted-signature token is "
            "rejected. Check storage for tokens with browser_storage. Confirm before reporting; attach a PoC."),
    tool_names=["http_request", "decode_jwt", "tamper_jwt", "verify_finding", "browser_storage", "make_poc",
                *_CONSULT],
)

# ---- VALIDATION phase (the "no proof, no report" gate) ----

VALIDATOR = AgentProfile(
    name="validator", domain="verification", posts="confirmed", phase="validate",
    system=("You are the VALIDATION specialist - the 'no proof, no report' gate. Go through the UNVERIFIED leads "
            "on the shared blackboard and, for each concrete one, reproduce it deterministically with "
            "verify_finding (build the request + the matching claim). Keep ONLY the ones it returns CONFIRMED, "
            "with their evidence. Explicitly discard every lead that does not confirm. Do not run new recon."),
    tool_names=["verify_finding", "http_request", "decode_jwt", "tamper_jwt", "make_poc", *_CONSULT],
)

# ---- REPORT phase (confirmed findings only) ----

REPORTER = AgentProfile(
    name="reporter", domain="reporting", posts="notes", phase="report",
    system=("You are the REPORTING specialist. Synthesise ONLY the CONFIRMED findings on the shared blackboard "
            "into one professional report. Do not run new scans and do not add unverified leads. Call "
            "write_report once with every confirmed finding - severity, category/CWE, reproduction, PoC, impact, "
            "remediation. If nothing was confirmed, write a report that says so plainly."),
    tool_names=["write_report", "consult_knowledge"],
)

# Each inner list runs in PARALLEL; the outer list runs in SEQUENCE.
PHASES: list[list[AgentProfile]] = [
    [RUNTIME_RECON, CODE_AUDIT],                      # recon: DAST + SAST in parallel
    [INJECTION, CLIENT_SIDE, ACCESS_CONTROL, AUTH],   # exploit: one specialist per vuln class in parallel
    [VALIDATOR],                                       # validation gate (deterministic verifier)
    [REPORTER],                                         # report from confirmed findings only
]

# Back-compat: the old 3-profile PIPELINE some callers import.
PIPELINE = [RUNTIME_RECON, INJECTION, REPORTER]
