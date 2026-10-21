"""Deterministic verifier tests. The whole point of the verifier is that it
CONFIRMS only on a hard signal and refuses to upgrade anything else, so these
tests assert both directions: real signals -> CONFIRMED, and the classic false
positives (blanket 403, reflection without execution, identical IDOR bodies, a
JWT whose signature IS verified) -> NOT confirmed.

HTTP is faked by patching c0mr4de.tools.web._request (which the verifier's thin
wrapper re-imports on each call) and, for the single-hop redirect path,
httpx.request. No real network, and no real 5s timing waits (the fake returns
instantly, so the time-based SQLi threshold is never met)."""
import re

import httpx
import pytest

import c0mr4de.verifier as v


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": "text/html", **(headers or {})}

    @property
    def url(self):
        return "http://t/"

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308)


def patch_req(monkeypatch, fn):
    monkeypatch.setattr("c0mr4de.tools.web._request", fn)


def _q(url, name):
    import urllib.parse as up
    return up.parse_qs(up.urlparse(url).query).get(name, [""])[0]


# ---------- parser ----------

def test_parse_relative_and_absolute():
    r = v.parse_http_request("GET /a?x=1 HTTP/1.1\nHost: h.com\n\n")
    assert r["url"] == "https://h.com/a?x=1" and r["method"] == "GET"
    r2 = v.parse_http_request('POST https://h.com/p HTTP/1.1\nContent-Type: application/json\n\n{"a":1}')
    assert r2["url"] == "https://h.com/p" and r2["body"] == '{"a":1}'


def test_parse_requires_host_or_absolute():
    with pytest.raises(ValueError):
        v.parse_http_request("GET /a HTTP/1.1\n\n")


def test_parse_http2_authority_pseudo_header():
    r = v.parse_http_request("GET /x?q=1 HTTP/2\n:authority: h.com\n:scheme: https\n\n")
    assert r["url"] == "https://h.com/x?q=1"
    assert ":authority" not in r["headers"] and "" not in r["headers"]  # no bogus empty-named header


def test_parse_body_without_blank_line():
    r = v.parse_http_request('POST /api HTTP/1.1\nHost: h.com\nContent-Type: application/json\n{"a":1}')
    assert r["url"] == "https://h.com/api" and r["body"] == '{"a":1}'


def test_json_array_body_errors_not_crash(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text="x"))
    req = {"method": "POST", "url": "http://t/api", "headers": {}, "body": "[1,2,3]"}
    assert v.verify("sqli", req, point="json:field").verdict == "ERROR"  # degrades, does not crash


# ---------- SQLi ----------

def test_sqli_error_based_confirmed(monkeypatch):
    def fake(url, method="GET", hdrs=None, body=""):
        val = _q(url, "id")
        if val.endswith("'") and "1'='1" not in val and "1'='2" not in val:
            return FakeResp(text="Warning: mysql_fetch - you have an error in your SQL syntax near ''")
        return FakeResp(text="normal product page, stable content")
    patch_req(monkeypatch, fake)
    req = {"method": "GET", "url": "http://t/item?id=5", "headers": {}, "body": ""}
    verdict = v.verify("sqli", req, point="id")
    assert verdict.verdict == "CONFIRMED" and verdict.technique == "sqli"
    assert verdict.reproduction  # a curl is produced


def test_sqli_safe_target_unconfirmed(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text="identical stable content every time"))
    req = {"method": "GET", "url": "http://t/item?id=5", "headers": {}, "body": ""}
    assert v.verify("sqli", req, point="id").verdict == "UNCONFIRMED"


def test_blanket_403_is_not_confirmed(monkeypatch):
    """The amrita case: every path returns an identical 403. Must NOT confirm."""
    patch_req(monkeypatch, lambda *a, **k: FakeResp(status=403, text="Forbidden"))
    req = {"method": "GET", "url": "http://t/item?id=5", "headers": {}, "body": ""}
    assert v.verify("sqli", req, point="id").verdict == "UNCONFIRMED"
    assert v.verify("xss", req, point="id").verdict == "UNCONFIRMED"


# ---------- XSS ----------

def test_xss_executed_confirmed(monkeypatch):
    def fake(url, method="GET", hdrs=None, body=""):
        return FakeResp(text=f"<html>search: {_q(url, 'q')}</html>")  # reflects raw
    patch_req(monkeypatch, fake)
    monkeypatch.setattr("c0mr4de.tools.browser.confirm_xss_exec", lambda url: True)
    req = {"method": "GET", "url": "http://t/s?q=x", "headers": {}, "body": ""}
    assert v.verify("xss", req, point="q").verdict == "CONFIRMED"


def test_xss_reflected_but_not_executed_unconfirmed(monkeypatch):
    def fake(url, method="GET", hdrs=None, body=""):
        return FakeResp(text=f"<html>search: {_q(url, 'q')}</html>")
    patch_req(monkeypatch, fake)
    monkeypatch.setattr("c0mr4de.tools.browser.confirm_xss_exec", lambda url: False)
    req = {"method": "GET", "url": "http://t/s?q=x", "headers": {}, "body": ""}
    assert v.verify("xss", req, point="q").verdict == "UNCONFIRMED"


# ---------- open redirect ----------

def test_open_redirect_confirmed(monkeypatch):
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        nxt = _q(url, "next")
        if "c0mr4de-redirect.example.net" in nxt:
            return FakeResp(status=302, headers={"location": nxt})
        return FakeResp(status=200, text="ok")
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/go?next=/home", "headers": {}, "body": ""}
    assert v.verify("open_redirect", req, point="next").verdict == "CONFIRMED"


def test_open_redirect_onhost_unconfirmed(monkeypatch):
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        return FakeResp(status=302, headers={"location": "/dashboard"})  # stays on-host
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/go?next=/home", "headers": {}, "body": ""}
    assert v.verify("open_redirect", req, point="next").verdict == "UNCONFIRMED"


def test_open_redirect_reflected_without_3xx_unconfirmed(monkeypatch):
    # a Location header echoed on a 200 is NOT a redirect - must not confirm
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        return FakeResp(status=200, headers={"location": _q(url, "next")})
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/go?next=/home", "headers": {}, "body": ""}
    assert v.verify("open_redirect", req, point="next").verdict == "UNCONFIRMED"


# ---------- IDOR ----------

def test_idor_victim_marker_confirmed(monkeypatch):
    # the victim's own datum comes back under your session and is absent from your control
    def fake(url, method="GET", hdrs=None, body=""):
        if "id=2" in url:
            return FakeResp(text='{"id":2,"name":"Bob","email":"bob@victim.com"}')
        if "id=1" in url:
            return FakeResp(text='{"id":1,"name":"Alice","email":"alice@me.com"}')
        return FakeResp(status=404, text="nf")
    patch_req(monkeypatch, fake)
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    control = {"method": "GET", "url": "http://t/u?id=1", "headers": {}, "body": ""}
    assert v.verify("idor", target, control_request=control, victim_marker="bob@victim.com").verdict == "CONFIRMED"


def test_idor_differing_bodies_without_marker_is_inconclusive(monkeypatch):
    # THE key false-positive fix: volatile content (a changing timestamp) makes two bodies
    # differ, but without a victim marker that is a LEAD, never a CONFIRMED.
    seq = {"n": 0}

    def fake(url, method="GET", hdrs=None, body=""):
        seq["n"] += 1
        return FakeResp(text=f'{{"id":1,"name":"Alice","generated_at":{seq["n"]}000}}')  # differs every call
    patch_req(monkeypatch, fake)
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    control = {"method": "GET", "url": "http://t/u?id=1", "headers": {}, "body": ""}
    assert v.verify("idor", target, control_request=control).verdict == "INCONCLUSIVE"


def test_idor_marker_absent_unconfirmed(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text='{"id":1,"name":"Alice","email":"alice@me.com"}'))
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    control = {"method": "GET", "url": "http://t/u?id=1", "headers": {}, "body": ""}
    assert v.verify("idor", target, control_request=control, victim_marker="bob@victim.com").verdict == "UNCONFIRMED"


def test_idor_identical_bodies_unconfirmed(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text='{"id":1,"name":"Alice","data":"xyz"}'))
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    control = {"method": "GET", "url": "http://t/u?id=1", "headers": {}, "body": ""}
    assert v.verify("idor", target, control_request=control).verdict == "UNCONFIRMED"


def test_idor_without_control_is_inconclusive(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text='{"id":2,"name":"Bob","notes":"plenty of data"}'))
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    assert v.verify("idor", target).verdict == "INCONCLUSIVE"


def test_idor_denied_target_unconfirmed(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(status=403, text="Forbidden"))
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    assert v.verify("idor", target).verdict == "UNCONFIRMED"


def test_idor_empty_json_object_not_record_like(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text="{}"))  # soft-deny / empty object
    target = {"method": "GET", "url": "http://t/u?id=2", "headers": {}, "body": ""}
    assert v.verify("idor", target).verdict == "UNCONFIRMED"


# ---------- JWT ----------

_TOK = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.SIG"  # {"alg":"HS256"} . {"role":"user"} . SIG


def _tok_in(hdrs):
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", (hdrs or {}).get("Authorization", ""))
    return m.group(0) if m else ""


_AUTHED = '{"user":"me","role":"admin","data":"real authenticated content"}'   # record-like


def test_jwt_signature_not_verified_confirmed(monkeypatch):
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        t = _tok_in(headers or {})
        sig = t.split(".")[2] if t.count(".") == 2 else ""
        if set(sig) == {"A"}:          # corrupted signature -> rejected (server does check sigs)
            return FakeResp(status=401, text="bad signature")
        return FakeResp(status=200, text=_AUTHED)   # original + tampered-payload-with-orig-sig accepted
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/me", "headers": {"Authorization": f"Bearer {_TOK}"}, "body": ""}
    assert v.verify("jwt", req, field_name="role", value="admin").verdict == "CONFIRMED"


def test_jwt_verified_is_unconfirmed(monkeypatch):
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        # only the EXACT original token is accepted; any payload/sig change -> rejected
        return FakeResp(status=200, text=_AUTHED) if _tok_in(headers or {}) == _TOK else FakeResp(status=401, text="bad")
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/me", "headers": {"Authorization": f"Bearer {_TOK}"}, "body": ""}
    assert v.verify("jwt", req, field_name="role", value="admin").verdict == "UNCONFIRMED"


def test_jwt_302_to_login_is_not_accepted(monkeypatch):
    # no-follow: a bad token answered with 302->/login must read as REJECTED, not the 200
    # the login page would give if followed. Previously this produced a false CONFIRMED.
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        if _tok_in(headers or {}) == _TOK:
            return FakeResp(status=200, text=_AUTHED)
        return FakeResp(status=302, headers={"location": "/login"})
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/me", "headers": {"Authorization": f"Bearer {_TOK}"}, "body": ""}
    assert v.verify("jwt", req, field_name="role", value="admin").verdict == "UNCONFIRMED"


def test_jwt_accepts_any_signature_inconclusive(monkeypatch):
    def fake(method, url, headers=None, content=None, timeout=None, follow_redirects=None):
        return FakeResp(status=200, text=_AUTHED)  # accepts even a garbage sig -> no real auth
    monkeypatch.setattr(httpx, "request", fake)
    req = {"method": "GET", "url": "http://t/me", "headers": {"Authorization": f"Bearer {_TOK}"}, "body": ""}
    assert v.verify("jwt", req, field_name="role", value="admin").verdict == "INCONCLUSIVE"


# ---------- dispatch / input validation ----------

def test_auto_finds_sqli(monkeypatch):
    def fake(url, method="GET", hdrs=None, body=""):
        val = _q(url, "id")
        if val.endswith("'") and "1'='1" not in val and "1'='2" not in val:
            return FakeResp(text="ORA-00933: sql syntax error")
        return FakeResp(text="stable page")
    patch_req(monkeypatch, fake)
    req = {"method": "GET", "url": "http://t/x?id=1", "headers": {}, "body": ""}
    assert v.verify("auto", req, point="id").verdict == "CONFIRMED"


def test_unknown_claim_errors():
    req = {"method": "GET", "url": "http://t/", "headers": {}, "body": ""}
    assert v.verify("telepathy", req).verdict == "ERROR"


def test_missing_point_errors():
    req = {"method": "GET", "url": "http://t/?x=1", "headers": {}, "body": ""}
    assert v.verify("sqli", req).verdict == "ERROR"


def test_point_not_found_errors(monkeypatch):
    patch_req(monkeypatch, lambda *a, **k: FakeResp(text="x"))
    req = {"method": "GET", "url": "http://t/?x=1", "headers": {}, "body": ""}
    assert v.verify("sqli", req, point="nope").verdict == "ERROR"


def test_body_param_injection_locates(monkeypatch):
    captured = {}

    def fake(url, method="GET", hdrs=None, body=""):
        captured["body"] = body
        return FakeResp(text="stable")
    patch_req(monkeypatch, fake)
    req = {"method": "POST", "url": "http://t/login", "headers": {}, "body": "user=a&pass=b"}
    v.verify("sqli", req, point="pass")
    assert "pass=" in captured["body"]  # the pass field was the one mutated
