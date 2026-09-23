"""Auto-save an engagement to the vault after a run, so c0mr4de builds a
growing memory of targets + the sequences that worked, and can reuse a
methodology when it meets the same tech stack instead of starting over."""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VAULT = REPO / "pentest-vault"

# crude stack fingerprint from tool outputs, so entries are indexed by stack
_STACK_HINTS = {
    "Next.js": ["next-action", "next.js", "_next/", "__next"],
    "React": ["react", "root\">", "data-reactroot"],
    "nginx": ["server: nginx", "nginx/"],
    "Express/Node": ["x-powered-by: express", "express"],
    "PHP": ["x-powered-by: php", ".php"],
    "WordPress": ["wp-content", "wp-json", "wordpress"],
    "Django": ["csrftoken", "django"],
    "Flask": ["werkzeug", "flask"],
    "Juice Shop": ["juice", "juiceshop", "/rest/products"],
}


def _fingerprint_stack(blob: str) -> list[str]:
    low = blob.lower()
    return [name for name, hints in _STACK_HINTS.items() if any(h in low for h in hints)]


def save_engagement(loop, target: str, vault_dir: Path = VAULT) -> Path:
    steps_md, blob = [], []
    for s in loop.log:
        if s.assistant_text:
            blob.append(s.assistant_text)
        for call, result in zip(s.tool_calls, s.tool_results):
            steps_md.append(f"{len(steps_md)+1}. `{call}` -> {result[:160].strip()}")
            blob.append(result)
    stack = _fingerprint_stack("\n".join(blob)) or ["(unfingerprinted)"]

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target.replace("https://", "").replace("http://", ""))[:50]
    path = vault_dir / f"{safe}-{date.today().isoformat()}.md"
    body = (
        f"# Engagement: {target} - {date.today().isoformat()}\n\n"
        f"**Tech stack (auto-fingerprinted):** {', '.join(stack)}\n"
        f"**Backend:** {loop.backend.name}\n"
        f"**Steps taken:** {len(steps_md)}\n\n"
        f"## Sequence\n" + ("\n".join(steps_md) if steps_md else "(no tool calls)") + "\n\n"
        f"## Reuse note\n"
        f"If you meet a `{stack[0]}` target again, recall this sequence before starting from scratch.\n"
    )
    path.write_text(body, encoding="utf-8")
    return path
