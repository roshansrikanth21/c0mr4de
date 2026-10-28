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
import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path

import yaml
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import httpx
from fastapi import Body

from c0mr4de import modelscan, roles, stats
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


def _runtime_state() -> dict:
    try:
        return json.loads(_STATE.read_text())
    except Exception:  # noqa: BLE001
        return {}


def _active_model_name(cfg: dict) -> str | None:
    """The model the UI last selected (discovered or preset), else the config's
    default, else None."""
    st = _runtime_state()
    return st.get("active_name") or st.get("active_model") or cfg.get("active_model")


def _active_backend_cfg(cfg: dict) -> dict:
    """Resolve the backend block to build from: the selected model's saved
    backend (any discovered or preset model), then a named `models:` preset,
    then the legacy single `backend:` block."""
    st = _runtime_state()
    if isinstance(st.get("active_backend"), dict):
        return st["active_backend"]
    name = cfg.get("active_model")
    models = cfg.get("models") or {}
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
    """Models actually available on THIS device - discovered live (Ollama +
    local OpenAI-compatible servers) plus any config.yaml presets - and which
    one is active. Re-scans on every call, so it reflects the current machine."""
    cfg = _read_cfg()
    found = modelscan.discover_models(cfg)
    active = _active_model_name(cfg)
    return {"active": active,
            "models": [{"name": e["name"], "label": e["label"], "source": e["source"],
                        "type": e["backend"].get("type"), "model": e["backend"].get("model", "?"),
                        "endpoint": e["endpoint"], "detail": e.get("detail", "")}
                       for e in found]}


@app.post("/models/active")
def models_set(name: str = Body(..., embed=True)):
    """Switch the active model to any discovered or preset model. Its backend is
    saved so the choice survives; takes effect on the next run - no restart."""
    cfg = _read_cfg()
    entry = modelscan.find_entry(name, cfg)
    if not entry:
        return {"error": f"model not found on this device: {name}"}
    _STATE.write_text(json.dumps({"active_name": name, "active_backend": entry["backend"]}),
                      encoding="utf-8")
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


# --- system / setup status: what's configured, what's missing, how to fix it ---

_PROVIDER_LINKS = {
    "opencode.ai": ("OpenCode Zen", "https://opencode.ai/auth"),
    "z.ai": ("Z.ai (GLM)", "https://z.ai/manage-apikey/apikey-list"),
    "nvidia.com": ("NVIDIA NIM", "https://build.nvidia.com"),
    "deepseek.com": ("DeepSeek", "https://platform.deepseek.com/api_keys"),
    "openrouter.ai": ("OpenRouter", "https://openrouter.ai/keys"),
    "featherless.ai": ("Featherless", "https://featherless.ai"),
    "groq.com": ("Groq", "https://console.groq.com/keys"),
    "googleapis.com": ("Google AI Studio", "https://aistudio.google.com/apikey"),
}


def _provider_for(base_url: str):
    for host, (name, link) in _PROVIDER_LINKS.items():
        if host in (base_url or ""):
            return name, link
    return "this provider", None


def _is_local_url(url: str) -> bool:
    return any(h in (url or "") for h in ("localhost", "127.0.0.1", "[::1]"))


def _has_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _docker_up_fast() -> bool:
    """Docker reachability bounded to 3s so /system stays snappy. envcheck's own
    _docker_up uses a longer timeout for the CLI doctor; here responsiveness wins."""
    import shutil
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=3).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _probe_backend(b: dict):
    """(reachable, {todo, link}) for the active backend."""
    try:
        if b.get("type") == "ollama":
            httpx.get((b.get("host", "http://localhost:11434")) + "/api/tags", timeout=3)
            return True, {}
        if b.get("base_url"):
            r = httpx.get(b["base_url"].rstrip("/") + "/models",
                          headers={"Authorization": f"Bearer {b.get('api_key', '')}"}, timeout=6)
            if r.status_code == 200:
                return True, {}
            prov, link = _provider_for(b["base_url"])
            return False, {"todo": f"The {prov} endpoint returned HTTP {r.status_code} - check the api_key "
                                   f"in config.yaml for this model.", "link": link}
    except Exception:  # noqa: BLE001
        pass
    if b.get("type") == "ollama":
        return False, {"todo": "Ollama isn't reachable. Run `ollama serve`, then `ollama pull "
                               f"{b.get('model', 'qwen2.5-coder:7b')}`.", "link": "https://ollama.com/download"}
    prov, link = _provider_for(b.get("base_url", ""))
    return False, {"todo": f"Can't reach {prov}. Add or fix the api_key for this model in config.yaml, "
                           f"or start its local server.", "link": link}


_sys_cache: dict = {"t": 0.0, "data": None}


@app.get("/system")
def system_status(fresh: bool = False):
    """Everything the operator needs to see at a glance: what's configured, what's
    missing, exactly how to fix each gap (with links), and where c0mr4de is working.
    Cached for a few seconds so the page-load probe and opening the panel don't both
    re-run the slow reachability checks; the panel's 'recheck' passes fresh=1."""
    import shutil
    import time
    from concurrent.futures import ThreadPoolExecutor

    if not fresh and _sys_cache["data"] is not None and (time.time() - _sys_cache["t"]) < 12:
        return _sys_cache["data"]

    from c0mr4de.tools.envcheck import _ollama_up
    cfg = _read_cfg()
    b = _active_backend_cfg(cfg)
    active = _active_model_name(cfg)
    # the three slow probes (model reachability, ollama, docker) run concurrently and
    # bounded, so the whole endpoint answers in a few seconds even when nothing is up.
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_reach, f_ol, f_dk = ex.submit(_probe_backend, b), ex.submit(_ollama_up), ex.submit(_docker_up_fast)
        reach, why = f_reach.result()
        ol, dk = f_ol.result(), f_dk.result()
    checks = [{
        "label": f"Active model - {active or '(none set)'}",
        "level": "ok" if reach else "error",
        "detail": f"{b.get('type')} - {b.get('base_url') or b.get('host') or 'local'}",
        "todo": None if reach else why.get("todo"), "link": None if reach else why.get("link"),
    }]
    # hosted presets missing an api key
    for name, m in (cfg.get("models") or {}).items():
        if m.get("type") in ("openai_compatible", "anthropic"):
            base, key = m.get("base_url", ""), str(m.get("api_key", "")).strip()
            if not _is_local_url(base) and key in ("", "...", "<your-key>", "YOUR_KEY"):
                prov, link = _provider_for(base)
                checks.append({"label": f"Preset '{name}' - no API key", "level": "warn",
                               "detail": f"{prov} model, key not set",
                               "todo": f"Get a key from {prov}, then set it under models.{name}.api_key in config.yaml.",
                               "link": link})
    checks.append({"label": "Ollama (local models)", "level": "ok" if ol else "warn",
                   "detail": "running" if ol else "not running",
                   "todo": None if ol else "Run `ollama serve` (and `ollama pull qwen2.5-coder:7b`).",
                   "link": None if ol else "https://ollama.com/download"})
    checks.append({"label": "Docker (containerized recon tools)", "level": "ok" if dk else "warn",
                   "detail": "running" if dk else "not running",
                   "todo": None if dk else "Start Docker Desktop to run katana/naabu/nuclei from images (optional - native installs also work).",
                   "link": None if dk else "https://www.docker.com/products/docker-desktop/"})
    for tool, hint, link in [
        ("nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "https://github.com/projectdiscovery/nuclei"),
        ("nmap", "Install nmap for port/service scanning.", "https://nmap.org/download"),
        ("sqlmap", "pip install sqlmap-dev, or clone the repo.", "https://sqlmap.org"),
        ("semgrep", "pip install semgrep (for source-audit).", "https://semgrep.dev"),
        ("interactsh-client", "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest (blind/OOB vulns).", "https://github.com/projectdiscovery/interactsh"),
    ]:
        ok = shutil.which(tool) is not None
        checks.append({"label": tool, "level": "ok" if ok else "warn",
                       "detail": "installed" if ok else "not found (optional)",
                       "todo": None if ok else hint, "link": None if ok else link})
    pw = _has_playwright()
    checks.append({"label": "Playwright (execution-confirmed XSS)", "level": "ok" if pw else "warn",
                   "detail": "installed" if pw else "not installed",
                   "todo": None if pw else "pip install playwright && playwright install chromium",
                   "link": None if pw else "https://playwright.dev/python/docs/intro"})
    summary = {lvl: sum(1 for c in checks if c["level"] == lvl) for lvl in ("ok", "warn", "error")}
    result = {"checks": checks, "summary": summary,
              "paths": {"workspace": str(WORKSPACE), "repo": str(REPO),
                        "config": str(REPO / "config" / "config.yaml")},
              "active_model": active, "reachable": reach}
    _sys_cache.update(t=time.time(), data=result)
    return result


@app.post("/reveal")
def reveal(path: str = Body(..., embed=True)):
    """Open a c0mr4de-produced file or folder in the OS file explorer. Scoped to the
    workspace/repo so the UI can only reveal c0mr4de's own paths."""
    p = Path(path)
    if not p.is_absolute():
        p = WORKSPACE / path
    try:
        p = p.resolve()
    except Exception:  # noqa: BLE001
        return {"error": "bad path"}
    roots = [WORKSPACE.resolve(), REPO.resolve()]
    if not any(str(p) == str(r) or str(p).startswith(str(r) + os.sep) for r in roots):
        return {"error": "path is outside the c0mr4de workspace"}
    if not p.exists():
        return {"error": "path not found"}
    try:
        if sys.platform == "win32":
            if p.is_file():
                subprocess.Popen(["explorer", "/select,", str(p)])
            else:
                subprocess.Popen(["explorer", str(p)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", str(p)] if p.is_file() else ["open", str(p)])
        else:
            subprocess.Popen(["xdg-open", str(p.parent if p.is_file() else p)])
        return {"ok": True, "path": str(p)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


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
            if mode in ("hivemind", "swarm"):
                from c0mr4de.swarm.orchestrator import Hivemind
                bb = Hivemind(on_event=on_event, should_stop=cancel.is_set).run(
                    _extract_target(task), task)
                c = bb.counts()
                result = (f"Hivemind complete - {c['confirmed']} CONFIRMED finding(s), "
                          f"{c['leads']} unverified lead(s), {c['surface']} surface item(s). "
                          f"Only confirmed findings were written to the report.")
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


@app.post("/verify")
def verify_route(payload: dict = Body(...)):
    """Deterministically verify one finding and return the structured verdict.
    Runs the hard-signal check in code (no model) - CONFIRMED only when proven."""
    from c0mr4de.verifier import parse_http_request, verify
    base = payload.get("base_scheme") or "https"
    try:
        raw = (payload.get("request") or "").strip()
        if raw:
            req = parse_http_request(raw, base)
        elif (payload.get("url") or "").strip():
            req = {"method": (payload.get("method") or "GET").upper(), "url": payload["url"],
                   "headers": payload.get("headers") or {}, "body": payload.get("body") or ""}
        else:
            return {"error": "provide `request` (a raw HTTP request) or `url`."}
        ctrl = (parse_http_request(payload["control_request"], base)
                if (payload.get("control_request") or "").strip() else None)
    except ValueError as exc:
        return {"error": f"could not parse the request: {exc}"}
    vd = verify(payload.get("claim") or "auto", req, point=payload.get("point") or "",
                control_request=ctrl, field_name=payload.get("field") or "", value=payload.get("value") or "",
                victim_marker=payload.get("victim_marker") or "")
    return vd.to_dict()


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
