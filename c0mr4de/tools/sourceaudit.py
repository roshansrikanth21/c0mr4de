"""Static source audit (Vulnhuntr-style candidate surfacing).

Finds files where remote user input can plausibly reach a dangerous sink, per
vuln class (SQLi, command-injection/RCE, file-inclusion, XSS, deserialization,
SSRF). This is the DETERMINISTIC haystack-reduction step: it flags CANDIDATE
flows - a file that reads user input AND calls a dangerous sink for that class.
It does NOT prove a real dataflow or exploitability; the agent then reads the
full functions, traces input->sink across files, and confirms against the
matching playbook before reporting (same confirm-before-reporting discipline as
the runtime injection tests). Detection-only, read-only.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from c0mr4de.tools.base import Tool

_EXTS = {".py", ".php", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".go"}
_SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "vendor", "dist", "build",
              "__pycache__", ".next", "site-packages", ".cache", "migrations"}
_MAX_BYTES = 400_000

# a file is a candidate only if it ALSO reads remote user input
_INPUT = re.compile(
    r"""request\.(args|form|values|json|data|files|cookies|headers|GET|POST)"""
    r"""|\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"""
    r"""|req\.(query|body|params|cookies|headers)"""
    r"""|self\.get_argument|flask\.request|params\[|getParameter\s*\(""",
    re.I,
)

# sinks per vuln class, ranked most-dangerous first (order = severity for sorting)
_SINKS: list[tuple[str, re.Pattern]] = [
    ("Command injection / RCE", re.compile(
        r"""os\.system|subprocess\.(?:call|run|Popen|check_output)[^)\n]*shell\s*=\s*True"""
        r"""|\beval\s*\(|\bexec\s*\(|child_process|\.exec(?:Sync)?\s*\(|shell_exec|passthru|\bpopen\s*\(|Runtime\.getRuntime""", re.I)),
    ("Deserialization", re.compile(
        r"""pickle\.loads|cPickle\.loads|yaml\.load\s*\(|marshal\.loads|\bunserialize\s*\(|ObjectInputStream|Marshal\.load""", re.I)),
    ("SQL injection", re.compile(
        r"""\.execute\s*\(|\.executemany\s*\(|cursor\.execute|\.raw\s*\(|mysqli_query|->query\s*\(|db\.(?:query|execute)|sequelize\.query""", re.I)),
    ("SSRF", re.compile(
        r"""requests\.(?:get|post|request|head)\s*\(|urllib\.request\.urlopen|httpx\.(?:get|post)|\bfetch\s*\(|axios\.(?:get|post)""", re.I)),
    ("File inclusion / path traversal", re.compile(
        r"""\binclude(?:_once)?\s*\(|\brequire(?:_once)?\s*\(|send_file|sendFile|fs\.(?:readFile|createReadStream)|file_get_contents|\bopen\s*\(""", re.I)),
    ("XSS", re.compile(
        r"""render_template_string|\.innerHTML|dangerouslySetInnerHTML|\|\s*safe\b|Markup\(|document\.write|\becho\s+\$_""", re.I)),
]


def _lines_matching(text: str, pat: re.Pattern, limit: int = 4) -> list[str]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if pat.search(line):
            out.append(f"{i}: {line.strip()[:160]}")
            if len(out) >= limit:
                break
    return out


def audit_source(path: str = ".", only: str = "", max_files: int = 500) -> str:
    """Static source audit: find files where remote user input can reach a dangerous
    sink (SQLi, command-injection/RCE, file-inclusion, XSS, deserialization, SSRF).
    path: a repo directory (relative to cwd or absolute). only: restrict to one class
    name substring (e.g. 'sql', 'command', 'xss'). Surfaces CANDIDATES to confirm -
    it does not prove exploitability; trace the real dataflow and check the matching
    playbook before reporting."""
    root = Path(path).expanduser()
    if not root.exists():
        return f"ERROR: {path} does not exist."
    if root.is_file():
        files = [root]
    else:
        files = []
        for f in root.rglob("*"):
            if not f.is_file() or f.suffix.lower() not in _EXTS:
                continue
            if any(part in _SKIP_DIRS for part in f.parts):
                continue
            files.append(f)
            if len(files) >= max_files:
                break

    candidates = []
    scanned = 0
    for f in files:
        try:
            if f.stat().st_size > _MAX_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        if not _INPUT.search(text):
            continue                       # no user input in this file -> not a source
        inp = _lines_matching(text, _INPUT)
        for rank, (cls, pat) in enumerate(_SINKS):
            if only and only.lower() not in cls.lower():
                continue
            sink = _lines_matching(text, pat)
            if sink:
                rel = str(f.relative_to(root)) if root.is_dir() else f.name
                candidates.append((rank, cls, rel, inp, sink))

    if not candidates:
        return (f"audit_source: scanned {scanned} source files under {path}. No file both "
                f"reads user input and calls a flagged sink. (Does not rule out logic/auth "
                f"bugs, or flows split across files - read key handlers manually.)")

    candidates.sort(key=lambda c: c[0])
    out = [f"audit_source: scanned {scanned} files, {len(candidates)} CANDIDATE flow(s) "
           f"(input + dangerous sink in the same file). Ranked most-dangerous first.",
           "Each is a LEAD - read the full functions, trace input->sink (may cross files), "
           "and confirm with the matching playbook BEFORE reporting. Not proof of exploitability.", ""]
    for _, cls, rel, inp, sink in candidates[:40]:
        out.append(f"[{cls}]  {rel}")
        out.append("  user input:")
        out += [f"    {l}" for l in inp]
        out.append("  reaches sink:")
        out += [f"    {l}" for l in sink]
        out.append("")
    if len(candidates) > 40:
        out.append(f"... and {len(candidates) - 40} more (narrow with only=<class>).")
    return "\n".join(out)


def semgrep_scan(path: str, config: str = "auto", max_findings: int = 40) -> str:
    """Run Semgrep (real SAST rules) over a repo and return findings ranked by severity.
    Deeper than audit_source's regex pass - actual dataflow/semantic rules. Still SAST,
    so each hit is a CANDIDATE: triage it with the surrounding code before reporting
    (the research consensus is an LLM-with-code-context triage cuts SAST false positives
    88-99%). config 'auto' pulls the rule registry (needs network); use 'p/default' or a
    local ruleset offline."""
    if shutil.which("semgrep") is None:
        return "semgrep not installed. Install with: pip install semgrep (or pipx install semgrep)."
    root = Path(path).expanduser()
    if not root.exists():
        return f"ERROR: {path} does not exist."
    try:
        r = subprocess.run(["semgrep", "scan", "--config", config, "--json", "--quiet",
                            "--timeout", "30", str(root)], capture_output=True, text=True, timeout=420)
    except subprocess.TimeoutExpired:
        return "semgrep timed out - narrow the path or use a lighter --config."
    except FileNotFoundError:
        return "ERROR: could not launch semgrep."
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return f"semgrep produced no parseable JSON. stderr: {(r.stderr or '')[:300]}"
    results = data.get("results", [])
    if not results:
        return (f"semgrep: no findings under {path} (config={config}). Does not rule out "
                "logic/auth bugs - semgrep only catches what its rules cover.")
    rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    results.sort(key=lambda x: rank.get(x.get("extra", {}).get("severity", "INFO"), 3))
    out = [f"semgrep: {len(results)} finding(s) under {path} (config={config}), most-severe first.",
           "SAST CANDIDATES - triage each with the surrounding code and confirm exploitability "
           "before reporting; SAST has false positives.", ""]
    for res in results[:max_findings]:
        sev = res.get("extra", {}).get("severity", "INFO")
        rel = res.get("path", "?")
        line = res.get("start", {}).get("line", "?")
        rule = str(res.get("check_id", "?")).split(".")[-1]
        msg = (res.get("extra", {}).get("message", "") or "").strip().replace("\n", " ")[:170]
        out.append(f"[{sev}] {rel}:{line}  {rule}")
        out.append(f"    {msg}")
    if len(results) > max_findings:
        out.append(f"... +{len(results) - max_findings} more (raise max_findings or narrow config).")
    return "\n".join(out)


TOOLS = [
    Tool(
        name="audit_source",
        description=(
            "Static source-code audit. Scans a repo for files where remote user input "
            "(request params, $_GET/$_POST, req.query, etc.) can reach a dangerous sink, "
            "grouped by vuln class (SQL injection, command-injection/RCE, file-inclusion, "
            "XSS, deserialization, SSRF), ranked most-dangerous first. This is the "
            "candidate-surfacing step - it flags LEADS, it does NOT prove exploitability. "
            "After it returns, read the full functions (read_file), trace the real "
            "input->sink dataflow (it can cross files), check the matching playbook, and "
            "only then report, marking verified only if you genuinely confirmed the flow. "
            "path is a repo dir (relative or absolute); only= restricts to one class."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "repo directory or file to audit"},
                "only": {"type": "string", "description": "optional vuln-class filter, e.g. 'sql', 'command', 'xss'"},
            },
            "required": ["path"],
        },
        fn=audit_source,
    ),
    Tool(
        name="semgrep_scan",
        description=(
            "Run Semgrep (real SAST rules, deeper than audit_source's regex pass) over a repo; "
            "returns findings ranked by severity. Each is a SAST CANDIDATE - triage with the "
            "surrounding code and confirm exploitability before reporting (SAST has false "
            "positives). config 'auto' pulls the rule registry (needs network); use a local "
            "ruleset offline. Pair with audit_source for coverage."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "repo directory to scan"},
                "config": {"type": "string", "description": "semgrep ruleset, default 'auto'"},
            },
            "required": ["path"],
        },
        fn=semgrep_scan,
    ),
]
