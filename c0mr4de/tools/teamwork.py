"""Hivemind teamwork: let a specialist feed a request back to an earlier phase.

This is the BOUNDED version of 'one agent's output is another's input, and vice
versa'. An exploitation specialist that is blocked because recon did not surface
what it needs calls note_gap(...). The coordinator runs ONE focused recon round to
fill the gap, then re-runs exploitation. It is bounded (a capped number of rounds),
so there is no A-waits-B-waits-A deadlock - the thing an unbounded cycle would cause.
"""
from __future__ import annotations

from c0mr4de.tools.base import Tool


def note_gap(detail: str) -> str:
    detail = (detail or "").strip()
    if not detail:
        return "note_gap needs a specific thing to recon, e.g. 'enumerate /admin endpoints'."
    return f"GAP NOTED (recon requested): {detail[:300]}"


TOOLS = [
    Tool(
        name="note_gap",
        description=(
            "Ask the RECON specialists to find something you need that the shared attack surface is missing "
            "(e.g. 'enumerate admin endpoints', 'find the login form parameters', 'resolve the API host'). The "
            "coordinator runs one focused recon round to fill it, then you get another exploitation pass. Use this "
            "only when you are genuinely blocked because recon did not surface what you need - not for routine work."
        ),
        parameters={"type": "object", "properties": {
            "detail": {"type": "string", "description": "the specific thing recon should find"}},
            "required": ["detail"]},
        fn=note_gap,
    ),
]
