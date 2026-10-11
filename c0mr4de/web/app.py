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

from c0mr4de import roles, stats
from c0mr4de.agent.backends import build_backend
from c0mr4de.agent.loop import AgentLoop
from c0mr4de.agent.prompts import SYSTEM_PROMPT
from c0mr4de.tools import build_default_registry
from c0mr4de.tools.files import WORKSPACE
from c0mr4de.tools.ocr import ocr_image
from c0mr4de.web import chats

REPO = Path(__file__).resolve().parent.parent.parent
STATIC = Path(__file__).resolve().parent / "static"
UPLOADS = WORKSPACE / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="c0mr4de")

# Where the live model choice is stored. Separate from config.yaml so switching
# models in the UI never rewrites the hand-maintained (and gitignored) config.
_STATE = REPO / "config" / "runtime.json"


def _read_cfg() -> dict:
    return yaml.safe_load((REPO / "config" / "config.yaml").read_text())


def _active_model_name(cfg: dict) -> str | None:
    """The preset the UI last selected, else the config's default, else None."""
    try:
        name = json.loads(_STATE.read_text()).get("active_model")
        if name:
            return name
    except Exception:  # noqa: BLE001
        pass
    return cfg.get("active_model")


def _active_backend_cfg(cfg: dict) -> dict:
    """Resolve the backend config block to build from: the active named preset
    under `models:`, falling back to the legacy single `backend:` block."""
    models = cfg.get("models") or {}
    name = _active_model_name(cfg)
    if name and name in models:
        return models[name]
    return cfg["backend"]


def _load_backend():
    return build_backend(_active_backend_cfg(_read_cfg()))


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
def chats_new(role: str = Body("general", embed=True)):
    return chats.new_chat(role=role if role in roles.ROLES else "general")


@app.post("/chats/{chat_id}/role")
def chats_set_role(chat_id: str, role: str = Body(..., embed=True)):
    if role not in roles.ROLES:
        return {"error": f"unknown role: {role}"}
    ok = chats.set_role(chat_id, role)
    return {"set": ok, "role": role, "digest": roles.role_digest(role, build_default_registry())}


@app.get("/roles")
def roles_list():
    reg = build_default_registry()
    return {"roles": [roles.role_digest(n, reg) for n in roles.role_names()]}


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
    "ollama": "local: no quota - bound only by your hardware",
    "anthropic": "paid: usage-billed, no hard cap",
}


def _limit_for(name: str) -> str:
    for k, v in _LIMITS.items():
        if k in name.lower():
            return v
    return "unknown"


@app.get("/models")
def models_list():
    """Named model presets from config.yaml `models:`, plus which one is active."""
    cfg = _read_cfg()
    models = cfg.get("models") or {}
    active = _active_model_name(cfg)
    return {"active": active if active in models else None,
            "models": [{"name": n, "type": m.get("type"),
                        "model": m.get("model", m.get("type", "?")),
                        "endpoint": m.get("base_url", m.get("host", "local"))}
                       for n, m in models.items()]}


@app.post("/models/active")
def models_set(name: str = Body(..., embed=True)):
    """Switch the active model. Takes effect on the next run - no restart."""
    cfg = _read_cfg()
    if name not in (cfg.get("models") or {}):
        return {"error": f"unknown model: {name}"}
    _STATE.write_text(json.dumps({"active_model": name}), encoding="utf-8")
    return {"ok": True, "active": name}


@app.get("/settings")
def settings_get():
    cfg = _read_cfg()
    b = _active_backend_cfg(cfg)
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
            # This chat's role scopes the toolset and the methodology focus.
            doc = chats.get_chat(chat_id) if chat_id else None
            role = (doc or {}).get("role", "general")
            events.put({"kind": "role", "data": {"name": role, "label": roles.get_role(role)["label"]}})
            if mode == "swarm":
                from c0mr4de.swarm.orchestrator import Swarm
                bb = Swarm(backend=backend, on_event=on_event, should_stop=cancel.is_set).run(
                    _extract_target(task), task)
                result = f"Swarm complete - {len(bb.findings)} finding(s) across recon/exploit/report."
                events.put({"kind": "final", "data": {"text": result}})
            else:
                recap = chats.prior_context(chat_id) if chat_id else ""
                full_task = f"{task}\n\n[earlier in this session]\n{recap}" if recap else task
                registry = roles.filter_registry(build_default_registry(), role)
                focus = roles.role_focus(role)
                sys_prompt = f"{SYSTEM_PROMPT}\n\n## Active role: {role}\n{focus}" if focus else SYSTEM_PROMPT
                loop = AgentLoop(backend=backend, tools=registry, verbose=False,
                                 on_event=on_event, should_stop=cancel.is_set, system_prompt=sys_prompt)
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


_REPORT_RE = re.compile(r"^report-[^/\\]+\.md$")


def _safe_report_path(name: str) -> Path:
    if not _REPORT_RE.match(name):
        raise ValueError("invalid report name")
    p = (WORKSPACE / name).resolve()
    if p.parent != WORKSPACE.resolve() or not p.is_file():
        raise ValueError("not found")
    return p


@app.get("/reports")
def reports_list():
    files = sorted(WORKSPACE.glob("report-*.md"), key=lambda f: f.stat().st_mtime, reverse=True)
    return [{"name": f.name, "mtime": f.stat().st_mtime, "size": f.stat().st_size} for f in files]


@app.get("/reports/{name}")
def reports_get(name: str):
    try:
        p = _safe_report_path(name)
    except ValueError:
        return {"error": "not found"}
    return {"name": name, "content": p.read_text(encoding="utf-8", errors="replace")}


@app.get("/reports/{name}/download")
def reports_download(name: str):
    try:
        p = _safe_report_path(name)
    except ValueError:
        return {"error": "not found"}
    return FileResponse(str(p), media_type="text/markdown", filename=name)


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
