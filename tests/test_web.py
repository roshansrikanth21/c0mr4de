"""Tests for the web UI's system/setup endpoints.

/system reports what's configured and what's missing (model reachability, keys,
tools) plus where c0mr4de works; /reveal opens one of those paths in the OS file
explorer and MUST refuse anything outside the workspace/repo. subprocess.Popen is
patched so no real Explorer window opens during the test run."""
from fastapi.testclient import TestClient

import c0mr4de.web.app as webapp

client = TestClient(webapp.app)


def test_system_shape():
    r = client.get("/system")
    assert r.status_code == 200
    d = r.json()
    assert set(d) >= {"checks", "summary", "paths", "active_model", "reachable"}
    # summary counts partition the checks exactly
    s = d["summary"]
    assert s["ok"] + s["warn"] + s["error"] == len(d["checks"])
    for c in d["checks"]:
        assert c["level"] in ("ok", "warn", "error")
        assert c["label"] and "detail" in c
        # anything not OK must tell the operator how to fix it
        if c["level"] != "ok":
            assert c.get("todo")
    for k in ("workspace", "repo", "config"):
        assert d["paths"][k]


def test_system_active_model_check_first():
    # the active-model check is always the first row so the blocking issue is on top
    checks = client.get("/system").json()["checks"]
    assert checks[0]["label"].startswith("Active model")


def test_reveal_rejects_outside_workspace(monkeypatch):
    called = []
    monkeypatch.setattr(webapp.subprocess, "Popen", lambda *a, **k: called.append(a))
    j = client.post("/reveal", json={"path": "C:/Windows/System32"}).json()
    assert "error" in j and "outside" in j["error"]
    assert not called  # never shells out for a rejected path


def test_reveal_rejects_missing_path(monkeypatch):
    called = []
    monkeypatch.setattr(webapp.subprocess, "Popen", lambda *a, **k: called.append(a))
    target = str(webapp.WORKSPACE / "definitely_not_here_xyz.md")
    j = client.post("/reveal", json={"path": target}).json()
    assert j.get("error") == "path not found"
    assert not called


def test_reveal_opens_workspace(monkeypatch):
    called = []
    monkeypatch.setattr(webapp.subprocess, "Popen", lambda *a, **k: called.append(a))
    webapp.WORKSPACE.mkdir(parents=True, exist_ok=True)
    j = client.post("/reveal", json={"path": str(webapp.WORKSPACE)}).json()
    assert j.get("ok") is True
    assert called  # shelled out exactly once to the explorer


def test_reveal_relative_path_resolves_under_workspace(monkeypatch):
    # a bare filename is resolved against WORKSPACE (how the reports "open" button calls it)
    monkeypatch.setattr(webapp.subprocess, "Popen", lambda *a, **k: None)
    webapp.WORKSPACE.mkdir(parents=True, exist_ok=True)
    f = webapp.WORKSPACE / "report-xyztest.md"
    f.write_text("# test", encoding="utf-8")
    try:
        j = client.post("/reveal", json={"path": "report-xyztest.md"}).json()
        assert j.get("ok") is True
    finally:
        f.unlink(missing_ok=True)
