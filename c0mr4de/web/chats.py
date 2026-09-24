"""Persistent conversations for the UI - so you can start a new chat, revisit
old ones, and use c0mr4de like a real assistant instead of one-shot runs.
Stored as JSON files under workspace/chats/. Simple, inspectable, no DB."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from c0mr4de.tools.files import WORKSPACE

CHATS = WORKSPACE / "chats"
CHATS.mkdir(parents=True, exist_ok=True)


def _path(chat_id: str) -> Path:
    return CHATS / f"{chat_id}.json"


def list_chats() -> list[dict]:
    out = []
    for f in CHATS.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            out.append({"id": d["id"], "title": d.get("title", "untitled"), "updated": d.get("updated", 0)})
        except Exception:  # noqa: BLE001
            continue
    return sorted(out, key=lambda c: c["updated"], reverse=True)


def new_chat() -> dict:
    cid = uuid.uuid4().hex[:12]
    doc = {"id": cid, "title": "new session", "created": time.time(), "updated": time.time(), "turns": []}
    _path(cid).write_text(json.dumps(doc), encoding="utf-8")
    return doc


def get_chat(chat_id: str) -> dict | None:
    p = _path(chat_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def append_turn(chat_id: str, role: str, content: str, events: list | None = None) -> None:
    doc = get_chat(chat_id)
    if doc is None:
        return
    doc["turns"].append({"role": role, "content": content, "events": events or [], "ts": time.time()})
    doc["updated"] = time.time()
    # title from the first user message
    if role == "user" and doc.get("title") in (None, "new session", "untitled"):
        doc["title"] = (content[:48] + "…") if len(content) > 48 else content
    _path(chat_id).write_text(json.dumps(doc), encoding="utf-8")


def prior_context(chat_id: str, max_chars: int = 1200) -> str:
    """A short recap of what happened earlier in this chat, injected so a
    follow-up run has continuity without replaying the whole tool history."""
    doc = get_chat(chat_id)
    if not doc or not doc["turns"]:
        return ""
    lines = []
    for t in doc["turns"][-6:]:
        if t["role"] == "user":
            lines.append(f"[you earlier] {t['content'][:200]}")
        elif t["role"] == "summary":
            lines.append(f"[c0mr4de earlier] {t['content'][:300]}")
    recap = "\n".join(lines)
    return recap[-max_chars:]
