"""File read/write for the agent's own workspace (reports, scratch
notes, downloaded JS bundles to inspect). Sandboxed to a single
workspace directory - the agent can't touch arbitrary paths on the host."""
from __future__ import annotations

import re
from pathlib import Path

from c0mr4de.tools.base import Tool

WORKSPACE = Path("./workspace").resolve()
WORKSPACE.mkdir(exist_ok=True)


def _safe_path(relative: str) -> Path:
    p = (WORKSPACE / relative).resolve()
    if WORKSPACE not in p.parents and p != WORKSPACE:
        raise ValueError(f"path escapes workspace: {relative}")
    return p


def _looks_binary(data: bytes) -> bool:
    sample = data[:8000]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    text = bytes(range(32, 127)) + b"\n\r\t\b"
    nontext = sum(1 for b in sample if b not in text)
    return (nontext / len(sample)) > 0.15


def read_file(path: str) -> str:
    p = _safe_path(path)
    if not p.exists():
        return f"ERROR: {path} does not exist in workspace"
    data = p.read_bytes()
    if _looks_binary(data):
        markers = sorted(set(re.findall(rb"[-A-Za-z0-9_.]{4,}", data[:4000])), key=len, reverse=True)[:10]
        marker_str = ", ".join(m.decode("ascii", "replace") for m in markers) or "none found"
        return (
            f"BINARY FILE ({len(data)} bytes) - this is not text, do not decode it as UTF-8 or "
            "eyeball it for readable fields.\n"
            f"ASCII-ish fragments present (may just be format magic bytes, not meaningful data): {marker_str}\n"
            f"First 256 bytes (hex): {data[:256].hex(' ')}\n"
            "IMPORTANT: a short ASCII string sitting next to high-entropy bytes in a binary format is "
            "very often a MODE/TYPE MARKER (e.g. 'this blob is encrypted'), not a label followed by a "
            "plaintext value. Do not report bytes adjacent to such a marker as an extracted secret/"
            "password/credential - that is not evidence of anything without actually parsing the "
            "format. If you need to know this file's real structure, say so explicitly rather than "
            "guessing from a raw byte dump."
        )
    return data.decode("utf-8", errors="replace")[:20000]


def write_file(path: str, content: str) -> str:
    p = _safe_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} chars to {path}"


def list_workspace(subdir: str = ".") -> str:
    p = _safe_path(subdir)
    if not p.exists():
        return f"ERROR: {subdir} does not exist"
    return "\n".join(str(f.relative_to(WORKSPACE)) for f in sorted(p.rglob("*")) if f.is_file()) or "(empty)"


TOOLS = [
    Tool(
        name="read_file",
        description="Read a file from the agent's workspace (relative path). Binary files are "
                    "detected and returned as a hex preview + warning instead of garbled text.",
        parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        fn=read_file,
    ),
    Tool(
        name="write_file",
        description="Write a file into the agent's workspace, e.g. saving a report or scratch notes. Creates directories as needed.",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
        fn=write_file,
    ),
    Tool(
        name="list_workspace",
        description="List files currently saved in the agent's workspace.",
        parameters={"type": "object", "properties": {"subdir": {"type": "string"}}, "required": []},
        fn=list_workspace,
    ),
]
