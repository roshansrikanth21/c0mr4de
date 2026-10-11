"""Local model discovery: the UI picker must reflect what is actually installed
on the device (Ollama + local OpenAI-compatible servers), merged with config
presets and de-duplicated, fail fast on closed ports, and never raise."""
import httpx

import c0mr4de.modelscan as ms


class _Resp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def json(self):
        return self._data


def _boom(*a, **k):
    raise RuntimeError("unreachable")


def _open(monkeypatch):
    # pretend every probed port is listening, so scans reach the HTTP layer
    monkeypatch.setattr(ms, "_port_open", lambda *a, **k: True)


def test_closed_ports_skip_http_entirely(monkeypatch):
    # nothing listening -> the socket gate rejects every probe, httpx is never called
    monkeypatch.setattr(ms, "_port_open", lambda *a, **k: False)
    monkeypatch.setattr(httpx, "get", _boom)  # would raise if called
    cfg = {"models": {"my-preset": {"type": "ollama", "model": "x", "host": "http://localhost:11434"}}}
    out = ms.discover_models(cfg)
    # presets still shown; no discovered models, and no exception
    assert [e["name"] for e in out] == ["my-preset"]


def test_presets_always_included_even_when_servers_error(monkeypatch):
    _open(monkeypatch)
    monkeypatch.setattr(httpx, "get", _boom)
    cfg = {"models": {"my-preset": {"type": "ollama", "model": "x", "host": "http://localhost:11434"}}}
    out = ms.discover_models(cfg)
    assert any(e["name"] == "my-preset" and e["source"] == "preset" for e in out)


def test_discovers_installed_ollama_models(monkeypatch):
    _open(monkeypatch)

    def fake_get(url, **k):
        if url.endswith("/api/tags"):
            return _Resp({"models": [{"name": "qwen2.5-coder:32b", "size": 19_000_000_000},
                                     {"name": "llama3:8b", "size": 4_700_000_000}]})
        raise RuntimeError("no oai here")
    monkeypatch.setattr(httpx, "get", fake_get)
    out = ms.discover_models({})
    labels = {e["label"] for e in out if e["source"] == "ollama"}
    assert {"qwen2.5-coder:32b", "llama3:8b"} <= labels
    e = next(x for x in out if x["label"] == "qwen2.5-coder:32b")
    assert e["backend"] == {"type": "ollama", "model": "qwen2.5-coder:32b",
                            "host": "http://localhost:11434"}
    assert "GB" in e["detail"]


def test_discovers_local_openai_server(monkeypatch):
    _open(monkeypatch)

    def fake_get(url, **k):
        if url.endswith("/api/tags"):
            raise RuntimeError("no ollama")
        if url.endswith("/v1/models") and ":1234" in url:
            return _Resp({"data": [{"id": "local-model-x"}]})
        return _Resp({}, status=404)
    monkeypatch.setattr(httpx, "get", fake_get)
    out = ms.discover_models({})
    e = next(x for x in out if x["source"] == "openai" and x["label"] == "local-model-x")
    assert e["backend"]["type"] == "openai_compatible"
    assert e["backend"]["base_url"].endswith(":1234/v1")


def test_preset_wins_over_duplicate_discovered(monkeypatch):
    _open(monkeypatch)

    def fake_get(url, **k):
        if url.endswith("/api/tags"):
            return _Resp({"models": [{"name": "dup:latest", "size": 1}]})
        raise RuntimeError("x")
    monkeypatch.setattr(httpx, "get", fake_get)
    cfg = {"models": {"preset-dup": {"type": "ollama", "model": "dup:latest",
                                     "host": "http://localhost:11434"}}}
    dups = [e for e in ms.discover_models(cfg) if e["backend"].get("model") == "dup:latest"]
    assert len(dups) == 1 and dups[0]["source"] == "preset"


def test_ollama_shim_does_not_double_list(monkeypatch):
    # Ollama up: /api/tags and its :11434/v1 shim report the same model. The
    # model must appear ONCE (from the native scan), not twice.
    _open(monkeypatch)

    def fake_get(url, **k):
        if url.endswith("/api/tags"):
            return _Resp({"models": [{"name": "qwen2.5-coder:32b", "size": 1}]})
        if ":11434" in url and url.endswith("/v1/models"):
            return _Resp({"data": [{"id": "qwen2.5-coder:32b"}]})
        raise RuntimeError("closed")
    monkeypatch.setattr(httpx, "get", fake_get)
    hits = [e for e in ms.discover_models({}) if e["label"] == "qwen2.5-coder:32b"]
    assert len(hits) == 1 and hits[0]["source"] == "ollama"


def test_find_entry_resolves_name(monkeypatch):
    monkeypatch.setattr(ms, "_port_open", lambda *a, **k: False)
    cfg = {"models": {"p": {"type": "ollama", "model": "m", "host": "http://h"}}}
    assert ms.find_entry("p", cfg)["label"] == "p"
    assert ms.find_entry("nope", cfg) is None
