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
import re
import threading
from pathlib import Path

import yaml
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import httpx
from fastapi import Body

from c0mr4de import stats
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


@app.delete("/chats/{chat_id}")
def chats_delete(chat_id: str):
    return {"deleted": chats.delete_chat(chat_id)}


@app.post("/chats/{chat_id}/rename")
def chats_rename(chat_id: str, title: str = Body(..., embed=True)):
    return {"renamed": chats.rename_chat(chat_id, title)}


@app.get("/stats")
def stats_get():
    return stats.snapshot()


@app.get("/auth")
def auth_status():
    from c0mr4de import auth
    return {"hosts": auth.status()}


@app.post("/auth")
def auth_set(host: str = Body(..., embed=True), cookie: str = Body("", embed=True),
             header: str = Body("", embed=True)):
    from c0mr4de import auth
    hdrs = {}
    if header:
        k, _, v = header.partition(":")
        hdrs[k.strip()] = v.strip()
    h = auth.set_auth(host, cookie=cookie, headers=hdrs)
    return {"set": h, "hosts": auth.status()}


@app.post("/auth/clear")
def auth_clear(host: str = Body("", embed=True)):
    from c0mr4de import auth
    auth.clear_auth(host or None)
    return {"hosts": auth.status()}


@app.get("/scope")
def scope_get():
    from c0mr4de import scope
    return {"brief": scope.brief()}


@app.post("/scope")
def scope_set(in_scope: str = Body("", embed=True), out_scope: str = Body("", embed=True),
              focus: str = Body("", embed=True)):
    from c0mr4de import scope
    scope.set_scope(in_scope=[s for s in in_scope.split(",") if s.strip()],
                    out_of_scope=[s for s in out_scope.split(",") if s.strip()], focus=focus)
    return {"brief": scope.brief()}


@app.post("/scope/clear")
def scope_clear():
    from c0mr4de import scope
    scope.clear_scope()
    return {"brief": ""}


# known free-tier limits, shown in settings (informational)
_LIMITS = {
    "groq": "free: ~8k tokens/min, ~200k tokens/day (per model)",
    "gemini": "free: generous TPM, limited requests/day (varies by model)",
    "ollama": "local: no quota — bound only by your hardware",
    "anthropic": "paid: usage-billed, no hard cap",
}


def _limit_for(name: str) -> str:
    for k, v in _LIMITS.items():
        if k in name.lower():
            return v
    return "unknown"


@app.get("/settings")
def settings_get():
    cfg = yaml.safe_load((REPO / "config" / "config.yaml").read_text())
    b = cfg["backend"]
    members = b.get("chain", [b]) if b.get("type") == "rotating" else [b]
    out = []
    for m in members:
        name = m.get("model", m.get("type", "?"))
        base = m.get("base_url", m.get("host", "local"))
        reachable = None
        try:
            if m.get("type") == "ollama":
                httpx.get((m.get("host", "http://localhost:11434")) + "/api/tags", timeout=3)
                reachable = True
            elif m.get("base_url"):
                # /models is a cheap auth-checked probe on OpenAI-compatible providers
                r = httpx.get(m["base_url"].rstrip("/") + "/models",
                              headers={"Authorization": f"Bearer {m.get('api_key','')}"}, timeout=5)
                reachable = r.status_code == 200
        except Exception:  # noqa: BLE001
            reachable = False
        out.append({"model": name, "endpoint": base, "limits": _limit_for(name + " " + base),
                    "reachable": reachable, "key_set": bool(m.get("api_key"))})
    registry = build_default_registry()
    return {"mode": b.get("type", "single"), "chain": out, "tools": registry.names(),
            "tool_count": len(registry.names())}


# active runs, keyed by chat_id, so a Stop button can cancel them
_cancel: dict[str, threading.Event] = {}


@app.post("/stop/{chat_id}")
def stop_run(chat_id: str):
    ev = _cancel.get(chat_id)
    if ev:
        ev.set()
        return {"stopping": True}
    return {"stopping": False}


def _extract_target(text: str) -> str:
    m = re.search(r"https?://[^\s'\"]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", text or "")
    return m.group(0) if m else text[:60]


@app.get("/run")
def run(task: str, chat_id: str = "", mode: str = "agent"):
    """Stream steps as SSE. mode='agent' (single loop) or 'swarm' (recon->exploit->report)."""
    events: queue.Queue = queue.Queue()
    collected: list = []
    cancel = threading.Event()
    if chat_id:
        _cancel[chat_id] = cancel

    def on_event(kind, data):
        events.put({"kind": kind, "data": data})
        if kind in ("thought", "tool_call", "tool_result", "final", "finding", "agent_start", "agent_done"):
            collected.append({"kind": kind, "data": data})

    def worker():
        try:
            if chat_id:
                chats.append_turn(chat_id, "user", task)
            backend = _load_backend()
            events.put({"kind": "backend", "data": {"name": backend.name}})
            if mode == "swarm":
                from c0mr4de.swarm.orchestrator import Swarm
                bb = Swarm(backend=backend, on_event=on_event, should_stop=cancel.is_set).run(
                    _extract_target(task), task)
                result = f"Swarm complete — {len(bb.findings)} finding(s) across recon/exploit/report."
                events.put({"kind": "final", "data": {"text": result}})
            else:
                recap = chats.prior_context(chat_id) if chat_id else ""
                full_task = f"{task}\n\n[earlier in this session]\n{recap}" if recap else task
                registry = build_default_registry()
                loop = AgentLoop(backend=backend, tools=registry, verbose=False,
                                 on_event=on_event, should_stop=cancel.is_set)
                result = loop.run(full_task)
            if chat_id:
                chats.append_turn(chat_id, "summary", result, collected)
        except Exception as exc:  # noqa: BLE001
            events.put({"kind": "error", "data": {"text": str(exc)}})
        finally:
            _cancel.pop(chat_id, None)
            events.put({"kind": "done", "data": {}})

    threading.Thread(target=worker, daemon=True).start()

    def stream():
        while True:
            ev = events.get()
            yield f"data: {json.dumps(ev)}\n\n"
            if ev["kind"] == "done":
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/osint/latest")
def osint_latest():
    """Path of the most recent OSINT graph, for the UI to embed."""
    d = WORKSPACE / "osint"
    files = sorted(d.glob("*.html"), key=lambda f: f.stat().st_mtime, reverse=True) if d.exists() else []
    return {"graph": f"/osint-files/{files[0].name}" if files else None}


_OSINT_DIR = WORKSPACE / "osint"
_OSINT_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/osint-files", StaticFiles(directory=str(_OSINT_DIR)), name="osint")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def main():
    import uvicorn

    print("c0mr4de UI on http://127.0.0.1:8800")
    uvicorn.run(app, host="127.0.0.1", port=8800, log_level="warning")


if __name__ == "__main__":
    main()
