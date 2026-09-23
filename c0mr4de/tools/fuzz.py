"""Native fuzzing - no Docker/kali needed. Pure httpx, so path/filename
discovery works even when the container tools are down (which is exactly
what blocked the path-traversal run: right technique, couldn't find the
`secret_flag.txt` filename because ffuf needed Docker)."""
from __future__ import annotations

import httpx

from c0mr4de.tools.base import Tool

# Small, high-signal built-in wordlists. Intentionally compact so it's fast
# and stays inside a weak model's context if the results are fed back.
_PATHS = [
    "admin", "login", "api", "api/health", "robots.txt", "sitemap.xml", ".env",
    "config", "config.json", "config.php", "backup", "backup.zip", ".git/config",
    "debug", "test", "dev", "status", "metrics", "swagger", "swagger.json",
    "graphql", "phpinfo.php", "server-status", ".htaccess", "wp-admin", "uploads",
]
_FILES = [
    "flag.txt", "flag", "secret.txt", "secret", "secret_flag.txt", "secrets.txt",
    "config.txt", "config.json", ".env", "passwd", "etc/passwd", "index.txt",
    "readme.txt", "backup.txt", "users.txt", "db.txt", "database.txt", "key.txt",
    "private.txt", "admin.txt", "credentials.txt",
]

_WORDLISTS = {"paths": _PATHS, "files": _FILES}


def _hits(pairs):
    lines = []
    for label, status, length in pairs:
        marker = "<<<" if status not in (404,) else ""
        lines.append(f"  {status}  len={length:<6} {label} {marker}")
    return "\n".join(lines)


def fuzz_paths(base_url: str, wordlist: str = "paths") -> str:
    words = _WORDLISTS.get(wordlist, _PATHS)
    base = base_url.rstrip("/")
    pairs = []
    with httpx.Client(timeout=8, follow_redirects=False) as c:
        for w in words:
            try:
                r = c.get(f"{base}/{w}")
                pairs.append((f"/{w}", r.status_code, len(r.content)))
            except httpx.HTTPError:
                pairs.append((f"/{w}", 0, 0))
    interesting = [p for p in pairs if p[1] not in (0, 404)]
    return f"fuzzed {len(words)} paths on {base}. Interesting (non-404):\n{_hits(interesting) or '  (none)'}"


def fuzz_param(url_with_fuzz: str, wordlist: str = "files") -> str:
    """Substitute each wordlist entry for the literal token FUZZ in the URL.
    Great for a `file=` param: fuzz_param('http://t/view?file=../FUZZ', 'files')."""
    if "FUZZ" not in url_with_fuzz:
        return "ERROR: put the literal token FUZZ in the URL where the wordlist should go."
    words = _WORDLISTS.get(wordlist, _FILES)
    pairs = []
    with httpx.Client(timeout=8, follow_redirects=False) as c:
        for w in words:
            url = url_with_fuzz.replace("FUZZ", w)
            try:
                r = c.get(url)
                pairs.append((w, r.status_code, len(r.content)))
            except httpx.HTTPError:
                pairs.append((w, 0, 0))
    interesting = [p for p in pairs if p[1] not in (0, 404)]
    return (
        f"fuzzed {len(words)} values into FUZZ. Non-404 responses (check the biggest/oddest for a hit):\n"
        f"{_hits(interesting) or '  (none)'}\n"
        f"TIP: fetch the interesting one with http_request to read its full body."
    )


TOOLS = [
    Tool(
        name="fuzz_paths",
        description="Brute-force common paths/files on a base URL to discover hidden endpoints (no Docker needed). wordlist: 'paths' or 'files'.",
        parameters={
            "type": "object",
            "properties": {"base_url": {"type": "string"}, "wordlist": {"type": "string"}},
            "required": ["base_url"],
        },
        fn=fuzz_paths,
    ),
    Tool(
        name="fuzz_param",
        description="Fuzz a parameter value: put the token FUZZ in the URL and this substitutes each wordlist entry. Use for path traversal (file=../FUZZ), IDOR (id=FUZZ), etc. wordlist: 'files' or 'paths'.",
        parameters={
            "type": "object",
            "properties": {"url_with_fuzz": {"type": "string"}, "wordlist": {"type": "string"}},
            "required": ["url_with_fuzz"],
        },
        fn=fuzz_param,
    ),
]
