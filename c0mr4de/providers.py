"""Model provider registry + key store for the setup UI.

The operator pastes a key once per provider in the web UI; it's saved to a
gitignored config/providers.json (config.yaml stays hand-maintained, comments and
all). Configured providers become selectable model presets everywhere - the model
dropdown, backend resolution, the hivemind heavy-chain - by being merged into the
cfg `models:` map. Keys are also picked up from the usual env vars if present.

Nothing here edits config.yaml. Nothing leaves the machine except the reachability
probe (a /models call to the provider you configured).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

_REPO = Path(__file__).resolve().parent.parent
_KEYS = _REPO / "config" / "providers.json"

# id -> provider spec. `role` drives the recommended rotating chain order.
PROVIDERS: dict[str, dict] = {
    "groq": {
        "name": "Groq", "role": "fastest · free", "rank": 1,
        "blurb": "~1.4s/step. Free tier (per-min + daily cap). Best speed.",
        "type": "openai_compatible", "base_url": "https://api.groq.com/openai/v1",
        "model": "openai/gpt-oss-120b", "env": "GROQ_API_KEY",
        "get_key": "https://console.groq.com/keys", "prefix": "gsk_"},
    "cerebras": {
        "name": "Cerebras", "role": "fastest · free", "rank": 2,
        "blurb": "As fast as Groq, separate cap. Great complement.",
        "type": "openai_compatible", "base_url": "https://api.cerebras.ai/v1",
        "model": "llama-3.3-70b", "env": "CEREBRAS_API_KEY",
        "get_key": "https://cloud.cerebras.ai/", "prefix": "csk-"},
    "gemini": {
        "name": "Google Gemini", "role": "free · capable", "rank": 3,
        "blurb": "Free Flash tier, solid quality, generous limits.",
        "type": "openai_compatible", "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash", "env": "GEMINI_API_KEY",
        "get_key": "https://aistudio.google.com/apikey", "prefix": ""},
    "deepinfra": {
        "name": "DeepInfra", "role": "cheap · reliable", "rank": 4,
        "blurb": "Paid but cheap + uncapped + fast. The 'just works' option.",
        "type": "openai_compatible", "base_url": "https://api.deepinfra.com/v1/openai",
        "model": "deepseek-ai/DeepSeek-V3", "env": "DEEPINFRA_API_KEY",
        "get_key": "https://deepinfra.com/dash/api_keys", "prefix": ""},
    "openrouter": {
        "name": "OpenRouter", "role": "free + paid · many models", "rank": 5,
        "blurb": "One key, hundreds of models incl. free variants.",
        "type": "openai_compatible", "base_url": "https://openrouter.ai/api/v1",
        "model": "deepseek/deepseek-chat", "env": "OPENROUTER_API_KEY",
        "get_key": "https://openrouter.ai/keys", "prefix": "sk-or-"},
    "opencode": {
        "name": "OpenCode Zen", "role": "free · deepseek", "rank": 6,
        "blurb": "Free DeepSeek variant (rotates). OpenAI-compatible.",
        "type": "openai_compatible", "base_url": "https://opencode.ai/zen/v1",
        "model": "deepseek-v4-flash-free", "env": "OPENCODE_API_KEY", "prefix": ""},
    "nvidia": {
        "name": "NVIDIA NIM", "role": "free · slow", "rank": 7,
        "blurb": "Capable but queued (~1-2 min/call). Overflow, not primary.",
        "type": "openai_compatible", "base_url": "https://integrate.api.nvidia.com/v1",
        "model": "openai/gpt-oss-20b", "env": "NVIDIA_API_KEY",
        "get_key": "https://build.nvidia.com", "prefix": "nvapi-"},
    "anthropic": {
        "name": "Anthropic Claude", "role": "best · paid", "rank": 8,
        "blurb": "Top reasoning/tool-use. Pay per token.",
        "type": "anthropic", "base_url": "", "model": "claude-sonnet-5",
        "env": "ANTHROPIC_API_KEY", "get_key": "https://console.anthropic.com/settings/keys", "prefix": "sk-ant-"},
}


def _load() -> dict:
    try:
        return json.loads(_KEYS.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def key_for(pid: str) -> str:
    """Saved key (providers.json) or the provider's env var, else ''."""
    saved = _load().get(pid, "")
    if saved:
        return saved
    env = PROVIDERS.get(pid, {}).get("env", "")
    return os.environ.get(env, "") if env else ""


def save_key(pid: str, key: str) -> None:
    if pid not in PROVIDERS:
        raise ValueError(f"unknown provider {pid}")
    data = _load()
    key = (key or "").strip()
    if key:
        data[pid] = key
    else:
        data.pop(pid, None)
    _KEYS.parent.mkdir(parents=True, exist_ok=True)
    _KEYS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _preset(pid: str) -> dict:
    p = PROVIDERS[pid]
    cfg = {"type": p["type"], "model": p["model"]}
    if p["type"] == "openai_compatible":
        cfg["base_url"] = p["base_url"]
        cfg["api_key"] = key_for(pid)
    else:  # anthropic
        cfg["api_key"] = key_for(pid)
    return cfg


def provider_presets() -> dict[str, dict]:
    """{provider_id: backend-cfg} for every provider that has a key - ready to be
    merged into cfg['models'] so they're selectable + resolvable everywhere."""
    return {pid: _preset(pid) for pid in PROVIDERS if key_for(pid)}


def merge_presets(cfg: dict) -> dict:
    """Add configured provider presets to cfg['models'] without clobbering any
    hand-defined config.yaml preset of the same name."""
    models = cfg.setdefault("models", {}) if isinstance(cfg, dict) else {}
    for name, block in provider_presets().items():
        models.setdefault(name, block)
    return cfg


def masked(key: str) -> str:
    if not key:
        return ""
    return (key[:4] + "…" + key[-4:]) if len(key) > 10 else "set"


def test_reachable(pid: str, timeout: float = 8.0) -> bool:
    p = PROVIDERS.get(pid)
    key = key_for(pid)
    if not p or not key:
        return False
    try:
        if p["type"] == "anthropic":
            r = httpx.get("https://api.anthropic.com/v1/models",
                          headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, timeout=timeout)
            return r.status_code == 200
        r = httpx.get(p["base_url"].rstrip("/") + "/models",
                      headers={"Authorization": f"Bearer {key}"}, timeout=timeout)
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def status(probe: bool = False) -> list[dict]:
    """Provider cards for the UI: spec + whether a key is set (+ optional live probe)."""
    out = []
    for pid, p in sorted(PROVIDERS.items(), key=lambda kv: kv[1]["rank"]):
        k = key_for(pid)
        out.append({
            "id": pid, "name": p["name"], "role": p["role"], "blurb": p["blurb"],
            "get_key": p.get("get_key", ""), "model": p["model"],
            "configured": bool(k), "key_masked": masked(k),
            "from_env": bool(not _load().get(pid) and k),
            "reachable": (test_reachable(pid) if (probe and k) else None),
        })
    return out
