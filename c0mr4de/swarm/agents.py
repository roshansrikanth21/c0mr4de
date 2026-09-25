"""Specialist agent profiles for the swarm. Each is a role prompt + a scoped
subset of tools. They run as ordinary AgentLoops but with a focused mandate
and only the tools that role needs - so recon doesn't try to exploit and the
reporter just writes up what the others found."""
from __future__ import annotations

from dataclasses import dataclass

from c0mr4de.tools import build_default_registry
from c0mr4de.tools.base import ToolRegistry


@dataclass
class AgentProfile:
    name: str
    system: str
    tool_names: list[str]

    def registry(self) -> ToolRegistry:
        full = build_default_registry()
        scoped = ToolRegistry()
        for n in self.tool_names:
            t = full.get(n)
            if t:
                scoped.register(t)
        return scoped


RECON = AgentProfile(
    name="recon",
    system=(
        "You are the RECON specialist in a pentest swarm. Your ONLY job is to map the target's attack "
        "surface for the exploitation specialist who runs after you: enumerate endpoints and paths, "
        "fingerprint the tech stack, identify parameters, auth mechanism, tokens/cookies, and any "
        "non-prod/admin surface. Do NOT exploit anything - just discover and clearly summarise what you "
        "found and which spots look most promising to attack. Be thorough but fast; issue real tool calls."
    ),
    tool_names=["crawl", "probe", "fuzz_paths", "fuzz_param", "http_request", "browser_navigate",
                "browser_storage", "whatweb", "nmap", "subfinder", "nuclei_scan", "consult_knowledge"],
)

EXPLOIT = AgentProfile(
    name="exploit",
    system=(
        "You are the EXPLOITATION specialist in a pentest swarm. The recon specialist has already mapped "
        "the target - use its findings (given to you) instead of re-enumerating. Find and exploit real "
        "vulnerabilities, CHAIN them where useful, and capture any secret/flag/admin access. For each "
        "vuln state severity and how it chains. Confirm exploits by actually running them - do not claim "
        "a bypass you didn't demonstrate. Issue real tool calls; don't write code in a block."
    ),
    tool_names=["http_request", "decode_jwt", "tamper_jwt", "fuzz_param", "browser_navigate",
                "browser_storage", "browser_eval", "sqlmap", "nikto", "oob_start", "oob_poll",
                "consult_knowledge"],
)

REPORT = AgentProfile(
    name="report",
    system=(
        "You are the REPORTING specialist in a pentest swarm. Synthesise ALL findings from the recon and "
        "exploitation specialists (given to you) into ONE professional report. Do not run new scans. Call "
        "write_report once with every confirmed finding - severity, category/CWE, steps to reproduce, PoC, "
        "impact, remediation. Be accurate: only report what was actually confirmed."
    ),
    tool_names=["write_report", "consult_knowledge"],
)

# ordered phases of the default engagement
PIPELINE = [RECON, EXPLOIT, REPORT]
