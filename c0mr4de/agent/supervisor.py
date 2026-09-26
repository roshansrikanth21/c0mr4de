"""A lightweight semantic supervisor for the agent loop.

Inspired by thruwire/foreman's idea — an independent watcher above the working
agent that asks "is it stuck? looping? off-track? done?" and steers or stops —
but WITHOUT foreman's dependencies (no TypeSafe Jev model, no Codex/OpenCode
workers). It runs on cheap deterministic signals over c0mr4de's own step log,
with an optional LLM completion check using the loop's existing backend.

Why deterministic-first: the failure modes we actually observed are mechanical —
the same tool called twice with no change (loop), or a tool erroring/unavailable
and being retried (stuck). Those are caught reliably and for free; we don't need
a model to tell us the agent repeated itself. The LLM check is opt-in for the
softer "are we done / off the mission?" judgment.
"""
from __future__ import annotations

_ERR_MARKERS = ("error", "not available", "unavailable", "timed out", "could not launch",
                "not on path", "no response", "not installed")


def _is_error(result: str) -> bool:
    low = (result or "").lower()
    return any(m in low for m in _ERR_MARKERS)


def _all_errors(step_log) -> bool:
    return bool(step_log.tool_results) and all(_is_error(r) for r in step_log.tool_results)


class Supervisor:
    """Reviews the step log after each step; may return a steer/stop directive.

    Conservative by design: it only intervenes on clear, repeated signals and is
    capped at `max_interventions` so it never fights a legitimately busy run."""

    def __init__(self, max_interventions: int = 3):
        self.max_interventions = max_interventions
        self.used = 0

    def review(self, log: list) -> tuple[str, str] | None:
        """Return (action, message) or None. action in {'steer', 'stop'}."""
        if self.used >= self.max_interventions or len(log) < 2:
            return None
        last, prev = log[-1], log[-2]

        # LOOP: identical tool call(s) two steps running, with no new information.
        if last.tool_calls and last.tool_calls == prev.tool_calls:
            self.used += 1
            return ("steer",
                    "SUPERVISOR: you repeated the exact same tool call(s) with no change and no new "
                    "result. Stop looping — change the inputs, try a DIFFERENT tool, or if you've "
                    "already confirmed there's nothing there, move on and write_report with what you have.")

        # STUCK: the tools in the last two steps all errored / were unavailable.
        if _all_errors(last) and _all_errors(prev):
            self.used += 1
            return ("steer",
                    "SUPERVISOR: the tools you're calling keep failing or are unavailable here. Do NOT "
                    "retry the same failing tool — switch to one that works (http_request, fuzz_paths, "
                    "consult_knowledge) or a different approach, and note the tool gap in your report.")

        # THRASH: three straight steps that ran tools but produced only errors.
        if len(log) >= 3 and all(_all_errors(s) for s in log[-3:]):
            self.used += 1
            return ("stop",
                    "SUPERVISOR: three straight steps produced only tool errors — no progress is being "
                    "made. Stop probing now and write_report with what you have and the tool gaps you hit.")
        return None


def assess_completion(backend, task: str, recent_text: str) -> dict:
    """OPTIONAL semantic check (foreman-style typed questions) using the loop's own
    backend. Returns {'complete': bool, 'off_track': bool, 'reason': str}. Best-effort:
    any parsing/backend failure yields a neutral verdict so it never breaks a run."""
    import json
    prompt = (
        "You are a supervisor over a pentest agent. Based ONLY on the mission and the agent's recent "
        "output, answer as compact JSON with keys complete (bool), off_track (bool), reason (short):\n"
        f"MISSION: {task[:500]}\nRECENT: {recent_text[:1200]}\n"
        'Reply with ONLY the JSON object, e.g. {"complete": false, "off_track": false, "reason": "..."}')
    try:
        resp = backend.generate("You output only compact JSON.", [{"role": "user", "content": prompt}], tools=[])
        raw = resp.text[resp.text.find("{"): resp.text.rfind("}") + 1]
        d = json.loads(raw)
        return {"complete": bool(d.get("complete")), "off_track": bool(d.get("off_track")),
                "reason": str(d.get("reason", ""))[:200]}
    except Exception:  # noqa: BLE001
        return {"complete": False, "off_track": False, "reason": ""}
