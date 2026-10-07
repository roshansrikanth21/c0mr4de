"""Native fuzzing - no Docker/kali needed. Pure httpx, so path/filename
discovery works even when the container tools are down (which is exactly
what blocked the path-traversal run: right technique, couldn't find the
`secret_flag.txt` filename because ffuf needed Docker)."""
from __future__ import annotations

import secrets

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

# A result whose body length is within this many bytes of a baseline (known-
# nonexistent) response is treated as the same canned answer, not a real hit.
_LEN_TOLERANCE = 32


def _hits(pairs):
    lines = []
    for label, status, length in pairs:
        marker = "<<<" if status not in (404,) else ""
        lines.append(f"  {status}  len={length:<6} {label} {marker}")
    return "\n".join(lines)


def _probe(c, url):
    try:
        r = c.get(url)
        return r.status_code, len(r.content)
    except httpx.HTTPError:
        return 0, 0


def _calibrate(c, make_url):
    """Learn how the target answers a resource that CANNOT exist, by probing two
    random tokens. Returns (signatures, blanket_status): `signatures` is the set of
    (status, length) the server returns for nothing-here, and `blanket_status` is a
    non-404 status it returns uniformly for random paths (e.g. a WAF that 403s
    everything, or a soft-404 that 200s an error page) - the signal that any probe
    sharing it is noise, not a discovery. Without this, a blanket-403 WAF makes
    EVERY path look 'interesting' (the real false positive this fixes)."""
    sigs = set()
    for _ in range(2):
        sigs.add(_probe(c, make_url(f"c0mr4de-{secrets.token_hex(12)}")))
    statuses = {s for s, _ in sigs}
    only = next(iter(statuses)) if len(statuses) == 1 else None
    blanket = only if only not in (None, 0, 404) else None
    return sigs, blanket


def _is_noise(status, length, sigs) -> bool:
    """True if this (status, length) matches a baseline nothing-here response."""
    if status in (0, 404):
        return True
    return any(status == bs and abs(length - bl) <= _LEN_TOLERANCE for bs, bl in sigs)


def fuzz_paths(base_url: str, wordlist: str = "paths") -> str:
    words = _WORDLISTS.get(wordlist, _PATHS)
    base = base_url.rstrip("/")
    with httpx.Client(timeout=8, follow_redirects=False) as c:
        sigs, blanket = _calibrate(c, lambda tok: f"{base}/{tok}")
        pairs = [(f"/{w}", *_probe(c, f"{base}/{w}")) for w in words]
    interesting = [p for p in pairs if not _is_noise(p[1], p[2], sigs)]
    header = f"fuzzed {len(words)} paths on {base}."
    if blanket is not None:
        header += (f"\nWARNING: this server returns a blanket {blanket} for random nonexistent paths "
                   f"(baseline={sorted(sigs)}) - likely a WAF/catch-all. A {blanket} here does NOT confirm "
                   f"a path exists; such responses are filtered out below, not reported as discoveries.")
    return f"{header}\nInteresting (differs from the nothing-here baseline):\n{_hits(interesting) or '  (none)'}"


def fuzz_param(url_with_fuzz: str, wordlist: str = "files") -> str:
    """Substitute each wordlist entry for the literal token FUZZ in the URL.
    Great for a `file=` param: fuzz_param('http://t/view?file=../FUZZ', 'files')."""
    if "FUZZ" not in url_with_fuzz:
        return "ERROR: put the literal token FUZZ in the URL where the wordlist should go."
    words = _WORDLISTS.get(wordlist, _FILES)
    with httpx.Client(timeout=8, follow_redirects=False) as c:
        sigs, blanket = _calibrate(c, lambda tok: url_with_fuzz.replace("FUZZ", tok))
        pairs = [(w, *_probe(c, url_with_fuzz.replace("FUZZ", w))) for w in words]
    interesting = [p for p in pairs if not _is_noise(p[1], p[2], sigs)]
    header = f"fuzzed {len(words)} values into FUZZ."
    if blanket is not None:
        header += (f"\nWARNING: a random nonexistent value also returns {blanket} (baseline={sorted(sigs)}) "
                   f"- the endpoint answers everything the same way, so a {blanket} does NOT confirm a hit. "
                   f"Such responses are filtered out below.")
    return (
        f"{header}\nResponses that differ from the nothing-here baseline (check the biggest/oddest for a hit):\n"
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
