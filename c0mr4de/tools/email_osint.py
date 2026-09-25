"""Email OSINT - the 'behind the email' step: given an email, find which
platforms/services it's registered on (Holehe checks 120+ sites via their
password-reset/registration signals, non-intrusively - no email is sent to
the target). Every hit becomes a graph node linked to the email, so it
correlates with usernames/profiles found by the other OSINT tools.

Matches the operator's workflow: email -> what's registered to it -> seed
known info -> correlate into the Maltego graph.

Public-source only, for authorized investigation / CTF."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sysconfig

from c0mr4de.tools.base import Tool
from c0mr4de.tools.osint import _add_edge, _add_node


def _holehe_bin() -> str | None:
    on_path = shutil.which("holehe")
    if on_path:
        return on_path
    # pip console script isn't always on PATH (esp. git-bash on Windows) - find it in Scripts
    scripts = sysconfig.get_path("scripts")
    for name in ("holehe.exe", "holehe"):
        p = os.path.join(scripts, name)
        if os.path.exists(p):
            return p
    return None


def email_osint(email: str) -> str:
    binary = _holehe_bin()
    if binary is None:
        return ("holehe not available. Install it: `pip install holehe`. It's the 'behind the email' "
                "step - which sites an email is registered on. Meanwhile pivot on the username with "
                "username_search and google_dork the email.")
    _add_node(f"email:{email}", "email", email)
    try:
        # --only-used: only sites where the email IS registered; -C would add CSV, we parse stdout
        r = subprocess.run([binary, email, "--only-used", "--no-color"],
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return f"holehe timed out on {email} (many sites rate-limit) — partial or none."
    except Exception as exc:  # noqa: BLE001
        return f"holehe error: {exc}"

    used = []
    for line in r.stdout.splitlines():
        line = line.strip()
        # holehe marks a hit with [+] <domain>
        m = re.match(r"\[\+\]\s+([\w.-]+)", line)
        if m:
            site = m.group(1)
            used.append(site)
            node = f"account:{site}:{email}"
            _add_node(node, "profile", f"{site} (email)")
            _add_edge(f"email:{email}", node, "registered")

    if not used:
        return (f"holehe: no confirmed registrations surfaced for {email} (many sites rate-limit / hide this). "
                f"Try username pivots and dorks instead.")
    return (f"'behind the email' for {email} — {len(used)} site(s) where it's registered:\n"
            + "\n".join(f"  [+] {s}" for s in used)
            + "\nAdded to the graph, linked to the email. Now pivot: derive a likely username, run "
              "username_search, dork the email, and add_osint_note anything you infer — then render_osint_graph.")


TOOLS = [
    Tool(
        name="email_osint",
        description=("'Behind the email' - given an email address, find which platforms/services it's "
                     "registered on (Holehe, 120+ sites, non-intrusive). The starting move for people-OSINT "
                     "from an email; results link into the OSINT graph. Use, then pivot to usernames/dorks."),
        parameters={"type": "object", "properties": {"email": {"type": "string"}}, "required": ["email"]},
        fn=email_osint,
    ),
]
