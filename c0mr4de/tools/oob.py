"""Out-of-band (OAST) detection via interactsh - the way to catch BLIND
vulnerabilities the other tools can't: blind SSRF, blind RCE, blind XXE,
blind SQLi, and anything else that makes the server call out but returns
nothing in the response.

Flow for the agent:
  1. oob_start()  -> get a unique callback domain (e.g. abc.oast.fun)
  2. inject that domain into a payload (SSRF url, header, XXE entity, ...)
     and send it with http_request
  3. oob_poll()   -> if the target's server called back, you'll see the
     interaction (DNS/HTTP/SMTP) with source IP + timestamp = confirmed blind vuln

Runs a persistent interactsh-client (native or Docker image) and streams
its JSON interactions. Degrades to a clear message if unavailable."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time

from c0mr4de.tools.base import Tool

_IMAGE = "projectdiscovery/interactsh-client:latest"
_state = {"proc": None, "domain": None, "interactions": [], "reader": None}
_lock = threading.Lock()
_DOMAIN_RE = re.compile(r"[a-z0-9]+\.(?:oast\.\w+|interact\.sh)", re.IGNORECASE)


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _img_present() -> bool:
    try:
        r = subprocess.run(["docker", "images", "-q", _IMAGE], capture_output=True, text=True, timeout=8)
        return bool(r.stdout.strip())
    except Exception:  # noqa: BLE001
        return False


def _cmd() -> list[str] | None:
    extra = ["-json", "-poll-interval", "3"]  # poll the OAST server every 3s so callbacks surface fast
    if _have("interactsh-client"):
        return ["interactsh-client", *extra]
    if _have("docker") and _img_present():
        return ["docker", "run", "--rm", "-i", _IMAGE, *extra]
    return None


def _reader(proc):
    for line in iter(proc.stdout.readline, ""):
        line = line.strip()
        if not line:
            continue
        # the payload domain is printed on startup (not JSON); interactions are JSON
        if _state["domain"] is None:
            m = _DOMAIN_RE.search(line)
            if m and not line.startswith("{"):
                _state["domain"] = m.group(0)
                continue
        if line.startswith("{"):
            try:
                d = json.loads(line)
                with _lock:
                    _state["interactions"].append({
                        "protocol": d.get("protocol", "?"),
                        "source": d.get("remote-address", d.get("remote_address", "?")),
                        "time": d.get("timestamp", ""),
                        "id": d.get("unique-id", d.get("full-id", "")),
                    })
            except json.JSONDecodeError:
                pass


def oob_start() -> str:
    if _state["proc"] and _state["proc"].poll() is None and _state["domain"]:
        return f"OOB session already active. Callback domain: {_state['domain']}\nInject it into payloads, then oob_poll()."
    cmd = _cmd()
    if cmd is None:
        return ("interactsh-client not available. Install it (github.com/projectdiscovery/interactsh) or pull "
                "the image (projectdiscovery/interactsh-client). Blind-vuln detection is unavailable without it.")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as exc:  # noqa: BLE001
        return f"ERROR launching interactsh-client: {exc}"
    _state.update({"proc": proc, "domain": None, "interactions": []})
    t = threading.Thread(target=_reader, args=(proc,), daemon=True)
    t.start()
    _state["reader"] = t
    for _ in range(30):  # wait up to ~9s for the domain to be issued
        if _state["domain"]:
            break
        time.sleep(0.3)
    if not _state["domain"]:
        return "OOB client started but no callback domain yet — retry oob_start() shortly, or check connectivity to interact.sh."
    return (f"OOB session active. Callback domain: {_state['domain']}\n"
            f"Inject it into payloads (e.g. http://{_state['domain']}/x as an SSRF url, or an XXE entity), "
            f"send with http_request, then call oob_poll() to see if the server called back.")


def oob_poll() -> str:
    if not _state["domain"]:
        return "No OOB session — call oob_start() first."
    with _lock:
        hits = list(_state["interactions"])
    if not hits:
        return f"No interactions yet on {_state['domain']}. If you've sent a payload, give it a few seconds and poll again."
    lines = [f"{len(hits)} OOB interaction(s) on {_state['domain']} — the target's server called back (blind vuln confirmed):"]
    for h in hits[-20:]:
        lines.append(f"  [{h['protocol'].upper()}] from {h['source']}  {h['time']}")
    return "\n".join(lines)


TOOLS = [
    Tool(
        name="oob_start",
        description=("Start an out-of-band (interactsh) session and get a unique callback domain. Inject it into "
                     "payloads to detect BLIND vulns (blind SSRF/RCE/XXE/SQLi) - vulns where the server calls out "
                     "but returns nothing. Then send the payload and use oob_poll."),
        parameters={"type": "object", "properties": {}, "required": []},
        fn=oob_start,
    ),
    Tool(
        name="oob_poll",
        description="Check whether the target's server made an out-of-band callback to your interactsh domain (confirms a blind vulnerability). Call after sending a payload containing the callback domain.",
        parameters={"type": "object", "properties": {}, "required": []},
        fn=oob_poll,
    ),
]
