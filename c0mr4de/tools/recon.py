"""Recon tools - thin wrappers around the kali-mcp Docker image Roshan
already has built (see memory: ctf-pentest-setup). Each tool shells out
to `docker run --rm kali-mcp <cmd>` so nothing here needs the container
running persistently."""
from __future__ import annotations

import shlex
import subprocess

from c0mr4de.tools.base import Tool

_TIMEOUT = 180


def _run_in_kali(cmd: str) -> str:
    full = ["docker", "run", "--rm", "--network", "host", "kali-mcp", "sh", "-c", cmd]
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {_TIMEOUT}s running: {cmd}"
    except FileNotFoundError:
        return "ERROR: docker not found on PATH, or kali-mcp image not built. See README setup."
    output = result.stdout + result.stderr
    return output[:8000] if output else "(no output)"


def nmap(target: str, flags: str = "-sV -T4 --top-ports 100") -> str:
    return _run_in_kali(f"nmap {flags} {shlex.quote(target)}")


def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: str = "") -> str:
    ext_flag = f"-x {shlex.quote(extensions)}" if extensions else ""
    return _run_in_kali(f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} {ext_flag} -q")


def ffuf(url_with_fuzz: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    return _run_in_kali(f"ffuf -u {shlex.quote(url_with_fuzz)} -w {shlex.quote(wordlist)} -mc all -s")


def whatweb(url: str) -> str:
    return _run_in_kali(f"whatweb {shlex.quote(url)}")


TOOLS = [
    Tool(
        name="nmap",
        description="Scan a target for open ports and service versions. Use before anything else on a new target.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "flags": {"type": "string", "description": "nmap flags, default is a fast top-100 version scan"},
            },
            "required": ["target"],
        },
        fn=nmap,
    ),
    Tool(
        name="gobuster_dir",
        description="Brute-force directories/files on a web server.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "extensions": {"type": "string", "description": "comma-separated, e.g. php,html,txt"},
            },
            "required": ["url"],
        },
        fn=gobuster_dir,
    ),
    Tool(
        name="ffuf",
        description="Fast web fuzzer. Put FUZZ in the URL where the wordlist should be substituted, e.g. https://target/FUZZ",
        parameters={
            "type": "object",
            "properties": {
                "url_with_fuzz": {"type": "string"},
                "wordlist": {"type": "string"},
            },
            "required": ["url_with_fuzz"],
        },
        fn=ffuf,
    ),
    Tool(
        name="whatweb",
        description="Fingerprint the tech stack (CMS, frameworks, server) behind a URL.",
        parameters={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        fn=whatweb,
    ),
]
