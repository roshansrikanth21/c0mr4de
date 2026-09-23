"""Ask-the-operator - human-in-the-loop, but non-blocking. The agent can
raise a doubt/question; it's logged for the operator to review, and the
agent is told to proceed with its best assumption rather than stall. This
is the right shape for unattended runs (operator asleep): questions are
captured, work doesn't halt.

Answers the operator writes back into the log are picked up on the next run
via RAG/notes, so doubts inform future methodology."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE

_LOG = WORKSPACE / "operator_questions.md"


def ask_operator(question: str, context: str = "", assumption: str = "") -> str:
    ts = datetime.now().isoformat(timespec="seconds")
    entry = (
        f"\n## {ts}\n"
        f"**Q:** {question}\n"
        + (f"**Context:** {context}\n" if context else "")
        + (f"**Proceeding on assumption:** {assumption}\n" if assumption else "")
        + "**Operator answer:** _(unanswered)_\n"
    )
    with open(_LOG, "a", encoding="utf-8") as f:
        f.write(entry)
    return (
        "Question logged for the operator (they may be away). Do NOT wait for an answer - "
        "proceed now with your stated best assumption and keep going. If you had no assumption, "
        "pick the most reasonable one, note it, and continue. The operator will review later."
    )


TOOLS = [
    Tool(
        name="ask_operator",
        description=(
            "Raise a doubt/question for the operator when you're genuinely unsure (scope, a risky "
            "action, an ambiguous target). It's LOGGED, not blocking - you must then proceed with your "
            "best assumption, which you should state in the 'assumption' field. Never stall waiting."
        ),
        parameters={
            "type": "object",
            "properties": {
                "question": {"type": "string"},
                "context": {"type": "string", "description": "why you're unsure"},
                "assumption": {"type": "string", "description": "what you'll do meanwhile"},
            },
            "required": ["question"],
        },
        fn=ask_operator,
    ),
]
