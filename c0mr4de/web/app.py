"""Minimalistic local web UI for c0mr4de.

- Chat interface, drag-drop file/image upload.
- Uploaded images are OCR'd automatically (EasyOCR) so their text is fed
  to the agent - "read what's in my screenshot".
- The agent's steps stream live to the browser over Server-Sent Events.

Run:  python -m c0mr4de.web.app   (then open http://127.0.0.1:8800)
Uses config/config.yaml for the backend, same as the CLI.
"""
from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

import yaml
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from c0mr4de.agent.backends import build_backend
from c0mr4de.agent.loop import AgentLoop
from c0mr4de.tools import build_default_registry
from c0mr4de.tools.files import WORKSPACE
from c0mr4de.tools.ocr import ocr_image
from c0mr4de.web import chats

REPO = Path(__file__).resolve().parent.parent.parent
STATIC = Path(__file__).resolve().parent / "static"
UPLOADS = WORKSPACE / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="c0mr4de")


def _load_backend():
    cfg = yaml.safe_load((REPO / "config" / "config.yaml").read_text())
    return build_backend(cfg["backend"])


@app.get("/")
def index():
    return FileResponse(str(STATIC / "index.html"))


@app.post("/upload")
async def upload(file: UploadFile):
    dest = UPLOADS / file.filename
    dest.write_bytes(await file.read())
    is_image = dest.suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif")
    extracted = ocr_image(str(dest)) if is_image else ""
    return {"path": str(dest), "is_image": is_image, "ocr": extracted}


# --- conversation management ---
@app.get("/chats")
def chats_list():
    return chats.list_chats()


@app.post("/chats/new")
def chats_new():
    return chats.new_chat()


@app.get("/chats/{chat_id}")
def chats_get(chat_id: str):
    return chats.get_chat(chat_id) or {"error": "not found"}


@app.get("/run")
def run(task: str, chat_id: str = ""):
    """Stream the agent's steps as Server-Sent Events, within a conversation."""
    events: queue.Queue = queue.Queue()
    collected: list = []

    def on_event(kind, data):
        events.put({"kind": kind, "data": data})
        if kind in ("thought", "tool_call", "tool_result", "final", "finding"):
            collected.append({"kind": kind, "data": data})

    def worker():
        try:
            if chat_id:
                chats.append_turn(chat_id, "user", task)
            recap = chats.prior_context(chat_id) if chat_id else ""
            full_task = f"{task}\n\n[earlier in this session]\n{recap}" if recap else task
            backend = _load_backend()
            registry = build_default_registry()
            loop = AgentLoop(backend=backend, tools=registry, verbose=False, on_event=on_event)
            events.put({"kind": "backend", "data": {"name": backend.name, "tools": registry.names()}})
            result = loop.run(full_task)
            if chat_id:
                chats.append_turn(chat_id, "summary", result, collected)
        except Exception as exc:  # noqa: BLE001
            events.put({"kind": "error", "data": {"text": str(exc)}})
        finally:
            events.put({"kind": "done", "data": {}})

    threading.Thread(target=worker, daemon=True).start()

    def stream():
        while True:
            ev = events.get()
            yield f"data: {json.dumps(ev)}\n\n"
            if ev["kind"] == "done":
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def main():
    import uvicorn

    print("c0mr4de UI on http://127.0.0.1:8800")
    uvicorn.run(app, host="127.0.0.1", port=8800, log_level="warning")


if __name__ == "__main__":
    main()
