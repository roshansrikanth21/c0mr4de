"""Tests for the newer modules - scope, auth, worklog, burp parsing.
Pure logic, no network. Run: python tests/test_tools.py"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from c0mr4de import auth, scope  # noqa: E402
from c0mr4de.memory.writeup_prep import prepare  # noqa: E402
from c0mr4de.surface import AttackSurface  # noqa: E402
from c0mr4de.surface.analyze import prioritize  # noqa: E402
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


def test_writeup_prep_cleans_and_dedupes():
    import tempfile
    long = "Detailed writeup body describing the payload and the recovered flag. " * 6
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "web").mkdir()
        (root / "crypto").mkdir()
        (root / ".git").mkdir()
        (root / "web" / "sqli.md").write_text(
            "# SQLi\n\n![img](x.png)\n\n" + long, encoding="utf-8")
        (root / "crypto" / "rsa.md").write_text("# RSA\n\n" + long, encoding="utf-8")
        (root / "crypto" / "rsa-dup.md").write_text("# RSA\n\n" + long, encoding="utf-8")  # dupe
        (root / "web" / "stub.md").write_text("# TODO\nWIP\n", encoding="utf-8")            # too small
        (root / ".git" / "secret.md").write_text("# nope\n\n" + long, encoding="utf-8")     # skipped dir
        out = root / "_out"
        s = prepare(root, out, source_label="t")
        assert s["kept"] == 2 and s["skipped_dupe"] == 1 and s["skipped_small"] == 1
        assert s["by_category"].get("web") == 1 and s["by_category"].get("crypto") == 1
        produced = sorted(p.name for p in out.glob("*.md"))
        assert len(produced) == 2 and "web_sqli.md" in produced       # single .md ext, no double ext
        assert sum(p.startswith("crypto_") for p in produced) == 1    # dedupe left exactly one crypto file
        body = (out / "web_sqli.md").read_text(encoding="utf-8")
        assert "img" not in body and "category: web" in body  # image stripped, provenance kept


def test_knowledge_graph_links_by_wikilink_and_concept():
    import tempfile
    from c0mr4de.memory.graph import KnowledgeGraph
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "ssrf.md").write_text("# SSRF\n\nServer-side request forgery via url param. See [[recon]].", encoding="utf-8")
        (root / "engagement.md").write_text("# Target X\n\nFound SSRF then chained to account takeover.", encoding="utf-8")
        (root / "recon.md").write_text("# Recon\n\nSubdomain enumeration methodology.", encoding="utf-8")
        g = KnowledgeGraph().build([root])
        # wikilink edge ssrf -> recon, and both docs share the SSRF concept
        assert ("ssrf", "recon", "links") in g.edges
        assert "SSRF" in g.nodes and g.nodes["SSRF"] == "concept"
        rel = {n for n, k, d in g.related("SSRF")}
        assert "ssrf" in rel and "engagement" in rel   # both mention SSRF -> connected via the concept
        # topic match on a concept term, and account-takeover concept present
        assert g._match("server-side request forgery") == "SSRF"


def test_surface_parses_messy_output_and_prioritizes():
    s = AttackSurface("acme.com")
    # subfinder plain lines (with noise the parser must skip)
    s.ingest_subfinder("[INF] enumerating\napi.acme.com\nadmin.acme.com\nblog.acme.com\n")
    # naabu json + plain, incl. a dangerous port
    s.ingest_naabu('{"host":"api.acme.com","ip":"10.0.0.5","port":6379}\nadmin.acme.com:443\n')
    # httpx json (one exposed .git endpoint on a WordPress host) + plain line
    s.ingest_httpx('{"url":"https://admin.acme.com/.git/config","status_code":200,"tech":["WordPress"],"title":"Index"}\n'
                   'https://blog.acme.com [200] [Blog] [Nginx]\n')
    # nuclei jsonl finding
    s.ingest_nuclei('{"template-id":"CVE-2021-1234","info":{"name":"RCE","severity":"critical"},"matched-at":"https://admin.acme.com/.git/config"}\n')

    st = s.stats()
    assert st["hosts"] >= 3 and st["endpoints"] >= 2 and st["findings"] == 1
    assert 6379 in s.hosts["api.acme.com"].ports  # redis captured
    assert "10.0.0.5" in s.hosts["api.acme.com"].ips

    ranked = prioritize(s)
    assert ranked, "should flag weak points"
    top = ranked[0]
    # the .git endpoint on WordPress with a critical nuclei hit must rank first
    assert top["ref"] == "https://admin.acme.com/.git/config"
    reasons = " ".join(top["reasons"]).lower()
    assert ".git" in reasons and "critical" in reasons


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
