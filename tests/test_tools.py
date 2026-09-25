"""Tests for the newer modules - scope, auth, worklog, burp parsing.
Pure logic, no network. Run: python tests/test_tools.py"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from c0mr4de import auth, scope  # noqa: E402
from c0mr4de.tools.burp import burp_import  # noqa: E402
from c0mr4de.tools.worklog import worklog, read_worklog  # noqa: E402


def test_scope_blocks_out_of_scope():
    scope.clear_scope()
    scope.set_scope(in_scope=["example.com"], out_of_scope=["admin.example.com"], focus="IDOR")
    assert scope.check("http://example.com/x") == "in"
    assert scope.check("http://app.example.com/x") == "in"        # subdomain of in-scope IS in scope
    assert scope.check("http://unrelated.org/x") == "unknown"     # scope set, host not covered
    assert scope.check("http://admin.example.com/x") == "out"     # explicitly out (out beats in)
    assert "IDOR" in scope.brief() and "example.com" in scope.brief()
    scope.clear_scope()
    assert scope.check("http://anything.com") == "in"  # no scope -> nothing blocked
    assert scope.brief() == ""


def test_auth_host_scoped():
    auth.clear_auth()
    auth.set_auth("app.example.com", cookie="sid=abc", headers={"X-Tok": "1"})
    a = auth.for_url("https://app.example.com:8443/path")  # port stripped
    assert a["cookie"] == "sid=abc" and a["headers"]["X-Tok"] == "1"
    assert auth.for_url("https://sub.app.example.com/") ["cookie"] == "sid=abc"  # parent-domain match
    assert auth.for_url("https://other.com/") == {}   # not leaked to other hosts
    assert "app.example.com" in auth.status()
    auth.clear_auth()


def test_worklog_roundtrip():
    worklog("test.target", "vulnerability", "IDOR on /api/x - CWE-639")
    worklog("test.target", "endpoint", "/api/admin")
    out = read_worklog("test.target")
    assert "IDOR on /api/x" in out and "/api/admin" in out
    bad = worklog("test.target", "not-a-category", "x")
    assert "ERROR" in bad


def test_burp_import_parses_export(tmp_path=None):
    req = base64.b64encode(
        b"GET /api/orders?id=5 HTTP/1.1\r\nHost: shop.test\r\nAuthorization: Bearer z\r\n\r\n").decode()
    xml = (
        '<?xml version="1.0"?><items>'
        f'<item><url>https://shop.test/api/orders?id=5</url><method>GET</method>'
        f'<status>200</status><request base64="true">{req}</request></item>'
        '</items>'
    )
    d = Path(__file__).resolve().parent.parent / "workspace"
    d.mkdir(exist_ok=True)
    f = d / "_test_burp.xml"
    f.write_text(xml, encoding="utf-8")
    out = burp_import(str(f))
    assert "shop.test" in out and "id" in out and "auth material" in out.lower()
    assert "BENCH" not in out  # sanity
    p = burp_import(str(f), only_params=True)
    assert "id" in p


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
