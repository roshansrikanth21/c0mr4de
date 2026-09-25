"""Shared blackboard - the swarm's common memory. Each specialist agent
reads what the others have found and writes its own results here, so recon
informs exploitation and nothing gets redone."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Blackboard:
    target: str
    objective: str
    notes: list[dict] = field(default_factory=list)      # {agent, text}
    findings: list[dict] = field(default_factory=list)    # {agent, text} - confirmed/interesting hits

    def note(self, agent: str, text: str) -> None:
        if text and text.strip():
            self.notes.append({"agent": agent, "text": text.strip()})

    def finding(self, agent: str, text: str) -> None:
        if text and text.strip():
            self.findings.append({"agent": agent, "text": text.strip()[:1200]})

    def brief(self, max_chars: int = 2000) -> str:
        """A compact briefing of what's known so far, injected into the next
        agent's task. Kept small to stay under free-tier token limits."""
        lines = [f"TARGET: {self.target}", f"OBJECTIVE: {self.objective}"]
        if self.findings:
            lines.append("\nCONFIRMED FINDINGS so far:")
            for f in self.findings[-8:]:
                lines.append(f"  - [{f['agent']}] {f['text'][:220]}")
        if self.notes:
            lines.append("\nRECON / NOTES so far:")
            for n in self.notes[-8:]:
                lines.append(f"  - [{n['agent']}] {n['text'][:220]}")
        return "\n".join(lines)[-max_chars:]
