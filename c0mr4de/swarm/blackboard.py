"""Shared blackboard - the hivemind's common, STRUCTURED memory.

Specialists do not chat with each other (that burns tokens and compounds errors);
they read and write typed entries here. A coordinator fans work out across
specialists, each posts structured results, and the blackboard de-duplicates and
tracks verification state so the report is built only from CONFIRMED findings.

Thread-safe: specialists in a phase run concurrently (real speedup on hosted
backends; a single local model serializes at the model, which is fine)."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


def _norm(text: str) -> str:
    return " ".join((text or "").lower().split())


@dataclass
class Blackboard:
    target: str
    objective: str
    notes: list[dict] = field(default_factory=list)       # {agent, text}       - recon/intel
    surface: list[dict] = field(default_factory=list)      # {agent, text}       - attack-surface items
    leads: list[dict] = field(default_factory=list)        # {agent, text}       - UNVERIFIED candidate vulns
    confirmed: list[dict] = field(default_factory=list)    # {agent, text}       - verifier-CONFIRMED only
    gaps: list[dict] = field(default_factory=list)         # {agent, text}       - "recon, dig here" feedback
    _seen: set = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _gap_cursor: int = 0

    def _add(self, bucket: list, agent: str, text: str, cap: int = 1200) -> bool:
        text = (text or "").strip()
        if not text:
            return False
        key = _norm(text)[:200]
        with self._lock:
            if key in self._seen:          # dedup across all specialists
                return False
            self._seen.add(key)
            bucket.append({"agent": agent, "text": text[:cap]})
        return True

    # typed posts
    def note(self, agent: str, text: str) -> bool:
        return self._add(self.notes, agent, text)

    def surface_item(self, agent: str, text: str) -> bool:
        return self._add(self.surface, agent, text)

    def lead(self, agent: str, text: str) -> bool:
        return self._add(self.leads, agent, text)

    def confirm(self, agent: str, text: str) -> bool:
        return self._add(self.confirmed, agent, text)

    def gap(self, agent: str, text: str) -> bool:
        return self._add(self.gaps, agent, text)

    def counts(self) -> dict:
        with self._lock:
            return {"surface": len(self.surface), "leads": len(self.leads),
                    "confirmed": len(self.confirmed), "gaps": len(self.gaps)}

    def new_gaps(self) -> list[dict]:
        """Gaps posted since the last call. The coordinator uses this to run ONE
        bounded focused-recon round per batch of gaps (no unbounded A<->B cycle)."""
        with self._lock:
            fresh = self.gaps[self._gap_cursor:]
            self._gap_cursor = len(self.gaps)
            return list(fresh)

    @staticmethod
    def gaps_brief(items: list[dict]) -> str:
        return ("FOCUSED RECON REQUEST from the exploitation specialists - find these and add them to the "
                "attack surface:\n" + "\n".join(f"  - {g['text']}" for g in items))

    def brief(self, max_chars: int = 2200) -> str:
        """A compact, structured briefing injected into the next specialist's task.
        Kept small on purpose - a weak/free-tier model must stay under its TPM."""
        with self._lock:
            lines = [f"TARGET: {self.target}", f"OBJECTIVE: {self.objective}"]
            if self.surface:
                lines.append("\nATTACK SURFACE (from recon):")
                lines += [f"  - [{s['agent']}] {s['text'][:200]}" for s in self.surface[-8:]]
            if self.confirmed:
                lines.append("\nCONFIRMED vulnerabilities (verified - safe to report):")
                lines += [f"  - [{c['agent']}] {c['text'][:220]}" for c in self.confirmed[-8:]]
            if self.leads:
                lines.append("\nUNVERIFIED leads (must be verified before reporting):")
                lines += [f"  - [{l['agent']}] {l['text'][:200]}" for l in self.leads[-8:]]
            if self.notes:
                lines.append("\nNOTES:")
                lines += [f"  - [{n['agent']}] {n['text'][:160]}" for n in self.notes[-5:]]
        return "\n".join(lines)[-max_chars:]
