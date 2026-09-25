"""ProjectDiscovery recon tools - katana (crawler) and httpx (prober).

katana spiders an app to map its real endpoint surface (far better than a
wordlist fuzzer); httpx probes URLs for status/title/tech/TLS. Both prefer a
native binary, fall back to the official Docker image, and degrade to a clear
message if neither exists."""
from __future__ import annotations

import shutil
import subprocess

from c0mr4de.tools.base import Tool

_KATANA_IMG = "projectdiscovery/katana:latest"
_HTTPX_IMG = "projectdiscovery/httpx:latest"
_TIMEOUT = 180


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _img_present(img: str) -> bool:
    try:
        r = subprocess.run(["docker", "images", "-q", img], capture_output=True, text=True, timeout=8)
        return bool(r.stdout.strip())
    except Exception:  # noqa: BLE001
        return False


def _run(binary: str, image: str, flags: list[str], install_hint: str) -> str:
    if _have(binary):
        cmd = [binary, *flags]
    elif _have("docker") and _img_present(image):
        from c0mr4de.tools.dockerutil import ADD_HOST, docker_target
        # rewrite localhost targets so the container can reach the host
        flags = [docker_target(f) for f in flags]
        cmd = ["docker", "run", "--rm", *ADD_HOST, image, *flags]
    else:
        return f"{binary} not available. Install it or pull the image ({image}). {install_hint}"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"{binary} timed out after {_TIMEOUT}s — narrow the scope."
    except FileNotFoundError:
        return f"ERROR: could not launch {binary}."
    return r.stdout, r.stderr  # type: ignore[return-value]


def crawl(url: str, depth: int = 2) -> str:
    """Spider a web app to discover its real endpoints (katana). Headless off
    by default for speed; raises depth for deeper coverage."""
    out = _run("katana", _KATANA_IMG,
               ["-u", url, "-d", str(depth), "-jc", "-silent", "-timeout", "8"],
               "Meanwhile use fuzz_paths for shallow discovery.")
    if isinstance(out, str):
        return out
    stdout, stderr = out
    urls = [l.strip() for l in stdout.splitlines() if l.strip().startswith("http")]
    if not urls:
        return f"katana crawled {url}: no additional endpoints found." + (f"\n{stderr[-200:]}" if stderr.strip() else "")
    uniq = list(dict.fromkeys(urls))
    head = "\n".join(f"  {u}" for u in uniq[:60])
    more = f"\n  ... (+{len(uniq)-60} more)" if len(uniq) > 60 else ""
    return f"katana found {len(uniq)} endpoints on {url}:\n{head}{more}"


def probe(url: str) -> str:
    """Probe a URL with httpx: status, title, tech stack, server, TLS."""
    out = _run("httpx", _HTTPX_IMG,
               ["-u", url, "-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-no-color"],
               "Meanwhile use whatweb / http_request.")
    if isinstance(out, str):
        return out
    stdout, stderr = out
    lines = [l.strip() for l in stdout.splitlines() if l.strip()]
    if not lines:
        return f"httpx probe of {url}: no response." + (f"\n{stderr[-200:]}" if stderr.strip() else "")
    return "httpx:\n" + "\n".join(f"  {l}" for l in lines[:20])


TOOLS = [
    Tool(
        name="crawl",
        description=("Spider a web app with katana to discover its real endpoint surface (links, JS routes, "
                     "forms) - far better than wordlist fuzzing. Use early in recon. depth 1-3."),
        parameters={"type": "object", "properties": {"url": {"type": "string"}, "depth": {"type": "integer"}},
                    "required": ["url"]},
        fn=crawl,
    ),
    Tool(
        name="probe",
        description="Probe a URL with httpx for status, page title, tech stack, web server and TLS info.",
        parameters={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        fn=probe,
    ),
]
