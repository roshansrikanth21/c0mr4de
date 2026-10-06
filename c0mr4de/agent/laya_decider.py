"""Laya - a local, calibrated System-1 decision engine for supervision.

convaiinnovations/laya (HF) is a non-autoregressive decision model: give it a
state + typed questions and it returns calibrated probabilities in one ~33ms
forward pass, locally, free, and it NEVER generates text (nothing to hallucinate
or parse). That is exactly the shape foreman's Jev has - so this is the free,
local "openjev" for c0mr4de's supervisor: answer "complete? off-track? stuck?
needs-human?" as calibrated yes/no instead of spending Groq TPM on an LLM call.

Optional dependency: `pip install laya` (a ~400MB checkpoint downloads on first
use). Everything here is guarded - if laya isn't installed, `available()` is False
and the supervisor falls back to the LLM/heuristic path. Zero-shot accuracy is
modest; fine-tuning laya on your own past pentest decisions is where it jumps
(their Kaggle notebook does the loop). This adapter targets the documented
Router API (Router().predict(state, {q: {type: 'noul'|'choice'|'score', ...}})).
"""
from __future__ import annotations

import functools


@functools.lru_cache(maxsize=1)
def available() -> bool:
    try:
        import laya  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


@functools.lru_cache(maxsize=1)
def _router():
    from laya import Router
    return Router()


# The supervisory questions, as Laya "noul" (yes/no) typed questions. Calibrated
# probability that the answer is "yes" comes back per question.
_QUESTIONS = {
    "complete": {"type": "noul", "instructions":
                 "Is the security task finished - a vulnerability found AND demonstrated, "
                 "or a genuinely clean result reached only after inputs were actually tested?"},
    "off_track": {"type": "noul", "instructions":
                  "Is the agent working outside the stated mission or scope?"},
    "stuck": {"type": "noul", "instructions":
              "Is the agent stuck - repeating actions or making no real progress?"},
    "needs_human": {"type": "noul", "instructions":
                    "Does the situation need a human decision (risky/destructive action, "
                    "or ambiguous scope)?"},
}


def assess(task: str, recent_text: str) -> dict | None:
    """Return calibrated probabilities {complete, off_track, stuck, needs_human} in
    [0,1], or None if laya isn't available / errored. Local, free, ~33ms."""
    if not available():
        return None
    try:
        state = f"MISSION: {task[:1500]}\n\nRECENT AGENT ACTIVITY:\n{recent_text[:4000]}"
        res = _router().predict(state, _QUESTIONS)
        ans = res.get("answers", {})
        out = {}
        for k in _QUESTIONS:
            v = ans.get(k, {})
            # 'noul' returns the probability the answer is yes
            out[k] = float(v.get("noul", v.get("probability", 0.0)))
        return out
    except Exception:  # noqa: BLE001 - never let the decider break a run
        return None
