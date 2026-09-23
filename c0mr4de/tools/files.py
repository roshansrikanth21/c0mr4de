"""File read/write for the agent's own workspace (reports, scratch
notes, downloaded JS bundles to inspect). Sandboxed to a single
workspace directory - the agent can't touch arbitrary paths on the host."""
from __future__ import annotations

from pathlib import Path

from c0mr4de.tools.base import Tool

WORKSPACE = Path("./workspace").resolve()
WORKSPACE.mkdir(exist_ok=True)


def _safe_path(relative: str) -> Path:
    p = (WORKSPACE / relative).resolve()
    if WORKSPACE not in p.parents and p != WORKSPACE:
        raise ValueError(f"path escapes workspace: {relative}")
    return p


def read_file(path: str) -> str:
    p = _safe_path(path)
    if not p.exists():
        return f"ERROR: {path} does not exist in workspace"
    return p.read_text(encoding="utf-8", errors="replace")[:20000]


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
        description="Read a file from the agent's workspace (relative path).",
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
