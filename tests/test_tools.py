"""Tests for the newer modules - scope, auth, worklog, burp parsing.
Pure logic, no network. Run: python tests/test_tools.py"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from c0mr4de import auth, scope  # noqa: E402
from c0mr4de.memory.writeup_prep import prepare  # noqa: E402
from c0mr4de.reportgen import generate_report, sanitize_text  # noqa: E402
from c0mr4de.surface import AttackSurface  # noqa: E402
from c0mr4de.surface.analyze import prioritize  # noqa: E402
from c0mr4de.tools.burp import burp_import  # noqa: E402
from c0mr4de.tools.webrecon import _analyze  # noqa: E402
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


def test_laya_dataset_extracts_severity_and_vuln():
    from c0mr4de.memory.laya_dataset import _parse_report
    report = (
        "### F-01 — Public-read S3 objects\n**Severity:** High if enumerable / Medium\n"
        "Impact: anyone can download PII.\n\n"
        "### F-06 — Positive controls (keep these)\n- SSO, encrypted bucket, WAF.\n")
    d = _parse_report(report, "rep")
    sev = [x for x in d if x["question"]["type"] == "score"]
    noul = [x for x in d if x["question"]["type"] == "noul"]
    assert any(x["answer"] == "high" for x in sev)                 # headline severity taken
    ans = {x["state"][:6]: x["answer"] for x in noul}
    assert ans.get("F-01 —") == "yes" and ans.get("F-06 —") == "no"  # positive control = negative example


def test_sanitize_text_strips_dashes_and_curly_quotes():
    assert sanitize_text("auth bypass — full takeover") == "auth bypass - full takeover"
    assert sanitize_text("affects versions 10–20") == "affects versions 10-20"   # digit range -> plain hyphen
    assert sanitize_text("it’s a “classic” bug…") == "it's a \"classic\" bug..."
    assert sanitize_text(None) == ""
    assert sanitize_text(42) == "42"


def test_generate_report_structure_and_no_em_dashes():
    findings = [
        {"title": "Reflected XSS — search box", "severity": "high", "category": "XSS / CWE-79",
         "description": "User input is reflected unescaped — a classic bug.",
         "steps_to_reproduce": "1. Go to /search\n2. Submit <script>", "proof_of_concept": "GET /search?q=<script>",
         "impact": "Session theft", "remediation": "Encode output"},
        {"title": "Missing rate limit", "severity": "low", "category": "A04", "description": "No throttling."},
    ]
    report = generate_report(target="example.com", findings=findings,
                             summary="Overview — two issues found.", positives="SSO is used — good.")
    assert "—" not in report and "–" not in report            # the whole ask: zero em/en dashes
    assert "’" not in report and "“" not in report            # and no curly quotes either
    assert "# Penetration Test Report" in report                       # default profile
    assert "## Executive Summary" in report and "## Scope" in report
    assert "## Methodology" in report and "## Findings Summary" in report
    assert "## Detailed Findings" in report and "## Appendix" in report
    assert "### Finding 1: Reflected XSS - search box" in report       # severity-sorted: high before low
    assert report.index("Finding 1") < report.index("Finding 2")
    assert "| HIGH |" in report or "HIGH" in report                    # severity surfaced in the summary table

    va = generate_report(target="example.com", findings=findings, report_type="vulnerability_assessment")
    assert "# Vulnerability Assessment Report" in va
    assert "coverage" in va.lower() or "scanning" in va.lower()         # VA-flavored methodology text


def test_xss_content_type_gate_avoids_false_positive():
    # A JSON API reflecting the payload verbatim is NOT exploitable (a browser
    # doesn't execute script from application/json) - found this as a real false
    # positive ("likely reflected XSS") before the content-type gate was added.
    def send_json(val):
        return 200, f'{{"q": "{val}"}}'
    notes = _analyze(send_json, '{"q": "x"}', 10, "x", content_type="application/json")
    assert not any("XSS" in n or "reflect" in n for n in notes)
    # The exact same raw reflection on real HTML must still be flagged.
    def send_html(val):
        return 200, f"<div>{val}</div>"
    notes2 = _analyze(send_html, "<div>x</div>", 10, "x", content_type="text/html; charset=utf-8")
    assert any("XSS" in n for n in notes2)


def test_sqli_boolean_diff_noise_floor():
    # _analyze's internal call order is: 0=error-probe, 1=base2(noise baseline),
    # 2=TRUE-payload, 3=FALSE-payload, 4+=timing/XSS probes (length irrelevant
    # there) - a dict keyed by call index is robust to that, unlike a fixed-length
    # iterator (which raised StopIteration mid-test on the first draft of this).
    import itertools

    # A page with large natural response-length variance (random filler, ads,
    # timestamps) must NOT trip the boolean-diff heuristic just because TRUE/FALSE
    # payload bodies differ - the diff must clearly exceed the page's own noise.
    # Found this as a real false positive before the noise-floor fix.
    noisy_pattern = {0: 250, 1: 250, 2: 80, 3: 260}  # noise=|250-14|=236; diff=|80-260|=180 < 236*3
    noisy_counter = itertools.count()
    def send_noisy(val):
        return 200, "x" * noisy_pattern.get(next(noisy_counter), 50)
    notes = _analyze(send_noisy, "x" * 14, 14, "orig")
    assert not any("SQLi" in n for n in notes)

    # A STABLE page (low natural noise) with a real boolean-based diff must still fire.
    stable_pattern = {0: 14, 1: 14, 2: 500, 3: 10}  # noise=0; diff=|500-10|=490 > 40
    stable_counter = itertools.count()
    def send_stable(val):
        return 200, "x" * stable_pattern.get(next(stable_counter), 14)
    notes2 = _analyze(send_stable, "x" * 14, 14, "orig")
    assert any("SQLi (blind)" in n for n in notes2)


def test_extract_surface_finds_links_forms_params():
    from c0mr4de.tools.web import extract_surface
    html = ('<html><body><a href="/catalog?searchTerm=x">c</a>'
            '<a href="https://evil.com/x">ext</a>'
            '<a href="mailto:a@b.com">m</a>'
            '<form action="/login" method="post"><input name="user"><input name="pass"></form>'
            '</body></html>')
    s = extract_surface(html, "https://shop.test/home")
    assert "https://shop.test/catalog" in s["links"]           # same-host link, query stripped
    assert all("evil.com" not in l for l in s["links"])          # off-host dropped
    assert "searchTerm" in s["params"] and "user" in s["params"] and "pass" in s["params"]
    assert s["forms"] and s["forms"][0]["action"].endswith("/login") and s["forms"][0]["method"] == "POST"


def test_extract_surface_unescapes_amp_entity_in_href():
    # Found on a real crawl: an href written as the HTML-correct "?a=1&amp;flowName=2"
    # was parsed WITHOUT unescaping first, so "amp;flowName" became a bogus param
    # name - a real crawl of m1rage.amritacybernation.com surfaced a batch of
    # "?amp;client_id", "?amp;scope" etc. entries that were this bug, not real params.
    from c0mr4de.tools.web import extract_surface
    html = '<a href="/x?a=1&amp;flowName=signup&amp;client_id=42">link</a>'
    s = extract_surface(html, "https://example.com/")
    assert "flowName" in s["params"] and "client_id" in s["params"]
    assert not any("amp" in p for p in s["params"])
    assert s["param_urls"][0] == "https://example.com/x?a=1&flowName=signup&client_id=42"


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


def test_read_file_flags_binary_instead_of_garbling_it(tmp_path=None):
    # Regression: a binary .seb (Safe Exam Browser) config starts with a short ASCII
    # mode marker ("pswd") immediately followed by encrypted bytes. The old
    # read_text(errors="replace") mis-decoded that into mojibake that LOOKED like a
    # readable password sitting right after "pswd", and the agent reported it as a
    # confirmed cleartext-credential finding. It was ciphertext, not a password.
    import os
    from c0mr4de.tools.files import WORKSPACE, read_file

    binary = b"\x00\x01pswd" + os.urandom(200) + b"\xff\xfe\x00\x01"
    target = WORKSPACE / "_test_binary_seb.bin"
    target.write_bytes(binary)
    try:
        out = read_file("_test_binary_seb.bin")
    finally:
        target.unlink(missing_ok=True)
    assert "BINARY FILE" in out
    assert "do not decode it as UTF-8" in out
    assert "not evidence of anything without actually parsing the format" in out
    # must NOT hand back a plausible-looking decoded string for the model to eyeball
    assert "�" not in out  # no raw UTF-8-replace mojibake leaking through


def test_report_findings_default_to_unverified():
    # Regression: write_report previously rendered every finding as a flat assertion
    # with no confidence signal, so a model's unconfirmed claim (e.g. "the plaintext
    # password was extracted") read exactly as authoritative as a tool-confirmed one.
    findings = [
        {"title": "Claimed cleartext password", "severity": "critical", "category": "Info disclosure",
         "description": "A model-asserted finding with no verified flag set."},
        {"title": "Execution-confirmed XSS", "severity": "high", "category": "XSS",
         "description": "Confirmed via confirm_xss_exec.", "verified": True},
    ]
    report = generate_report(target="example.com", findings=findings)
    assert "UNVERIFIED - based on static or manual analysis" in report
    assert "VERIFIED - confirmed by a deterministic tool" in report
    # the unverified finding's own detail section must carry the warning (not just
    # exist somewhere else in the doc). Locate sections by their "Finding N:" headers
    # without assuming order - the verified HIGH now sorts above the unverified
    # "critical" (which caps to the unverified tier), which is the intended ranking.
    unv_start = report.index("Claimed cleartext password", report.index("## Detailed Findings"))
    sec_from = report.rindex("### Finding", 0, unv_start)
    nxt = report.find("### Finding", unv_start)
    unv_section = report[sec_from:nxt] if nxt != -1 else report[sec_from:]
    assert "UNVERIFIED" in unv_section
    assert "No - unconfirmed" in report  # summary table column


def test_request_rechecks_scope_across_redirects():
    # Regression: _request followed httpx auto-redirects without re-checking scope, so a
    # 3xx from an in-scope host to an out-of-scope one (real case: an app's "Sign up with
    # Google" button -> accounts.google.com) sent our traffic, incl. payloads, off-scope.
    import httpx as _httpx
    from c0mr4de.tools import web
    scope.clear_scope()
    scope.set_scope(in_scope=["example.com"], out_of_scope=["accounts.google.com"])
    calls = []

    def fake_request(method, url, **kw):
        calls.append(url)
        if "example.com" in url:
            return _httpx.Response(302, headers={"location": "https://accounts.google.com/signin"})
        return _httpx.Response(200, text="SHOULD NOT BE REACHED")

    orig = web.httpx.request
    web.httpx.request = fake_request
    try:
        raised = False
        try:
            web._request("http://example.com/login")
        except PermissionError:
            raised = True
        assert raised, "a redirect to an out-of-scope host must raise, not be followed"
        assert not any("accounts.google.com" in c for c in calls), \
            "no HTTP request may be sent to the out-of-scope redirect target"
    finally:
        web.httpx.request = orig
        scope.clear_scope()


def test_audit_source_flags_vuln_not_clean(tmp_path=None):
    import tempfile
    from pathlib import Path
    from c0mr4de.tools.sourceaudit import audit_source
    d = Path(tempfile.mkdtemp())
    (d / "vuln.py").write_text(
        "import os\nfrom flask import request\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    cursor.execute('SELECT * FROM items WHERE name=' + q)\n"
        "    os.system('ping ' + request.args.get('host'))\n")
    (d / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    out = audit_source(str(d))
    assert "SQL injection" in out and "vuln.py" in out          # true positive: SQLi flagged
    assert "Command injection" in out                           # true positive: RCE flagged
    assert "clean.py" not in out                                # true negative: clean file silent
    assert "Not proof of exploitability" in out                 # honest framing, not a confirmed finding
    # ranked most-dangerous first: command injection before SQLi
    assert out.index("Command injection") < out.index("SQL injection")


def test_make_poc_builds_reproducible_curl():
    from c0mr4de.tools.poc import make_poc
    # GET: payload injected (url-encoded) into the query param
    g = make_poc("https://t.com/item?id=1", param="id", payload="1' OR SLEEP(5)-- -",
                 observe="~5s delay vs baseline")
    assert g.startswith("PoC")
    assert "curl -i -s" in g and "t.com/item?id=1" in g
    assert "SLEEP" in g.upper()                                  # payload present (encoded and/or raw)
    assert "~5s delay vs baseline" in g                          # observe note carried through
    # POST with explicit body + auth header
    p = make_poc("https://t.com/login", method="POST", body="u=admin'--", headers='{"Cookie":"s=abc"}')
    assert "-X POST" in p and "--data" in p and "Cookie: s=abc" in p


def test_build_registry_includes_new_tools():
    from c0mr4de.tools import build_default_registry
    names = build_default_registry().names()
    for t in ("make_poc", "katana_crawl", "gau_urls", "tlsx_sans", "dnsx_resolve", "audit_source",
              "semgrep_scan", "env_report"):
        assert t in names, f"{t} not registered"


def test_unverified_severity_is_capped():
    """An unverified finding must not keep an urgent (critical/high) rating - that
    inflation is what a blanket-403 WAF produced. It caps to the policy tier and
    the detail section explains the downgrade. A verified finding is never capped,
    and a low finding is left alone (the cap only lowers, never raises)."""
    from c0mr4de.reportgen import _UNVERIFIED_SEVERITY_CAP
    findings = [
        {"title": "Blanket 403 paths", "severity": "high", "category": "x",
         "description": "403 on /flag.txt - unconfirmed."},                      # unverified -> capped
        {"title": "Confirmed SQLi", "severity": "critical", "category": "x",
         "description": "timing-confirmed.", "verified": True},                   # verified -> kept
        {"title": "Weak header", "severity": "low", "category": "x",
         "description": "missing HSTS."},                                         # below cap -> kept
    ]
    report = generate_report(target="t.com", findings=findings)
    capped = report[report.index("### Finding"):]
    # the once-HIGH unverified finding now shows the cap tier, not HIGH, in its header row
    blanket = report[report.index("Blanket 403 paths"):]
    assert f"| **Severity** | {_UNVERIFIED_SEVERITY_CAP.upper()} |" in capped
    assert "claimed severity was HIGH" in blanket
    assert "capped" in blanket.lower()
    # verified critical keeps CRITICAL and gets no cap note
    crit = report[report.index("### Finding"):]
    assert "| **Severity** | CRITICAL |" in crit
    # low stays low (cap only lowers critical/high, never raises low/info)
    assert "| **Severity** | LOW |" in report


def test_fuzz_baseline_filters_blanket_responses():
    """fuzz_paths/_param must treat a response that matches a known-nonexistent
    baseline as noise, not a discovery - the blanket-403 false positive fix."""
    from c0mr4de.tools import fuzz

    class _Resp:
        def __init__(self, status, body):
            self.status_code, self.content = status, body

    # server that 403s EVERYTHING with a fixed 24-byte body (the WAF case)
    blanket_body = b"x" * 24
    sigs = {(403, 24)}
    assert fuzz._is_noise(403, 24, sigs) is True            # matches baseline -> noise
    assert fuzz._is_noise(404, 0, sigs) is True             # 404 is always noise
    assert fuzz._is_noise(200, 5000, sigs) is False         # a real, differing hit survives

    class _BlanketClient:
        def get(self, url):
            return _Resp(403, blanket_body)

    sigs2, blanket = fuzz._calibrate(_BlanketClient(), lambda tok: f"http://t/{tok}")
    assert blanket == 403 and sigs2 == {(403, 24)}

    class _RealClient:
        def get(self, url):
            # random calibration tokens 404; a genuine path returns a 200 w/ real body
            return _Resp(404, b"") if "c0mr4de-" in url else _Resp(200, b"y" * 900)

    sigs3, blanket3 = fuzz._calibrate(_RealClient(), lambda tok: f"http://t/{tok}")
    assert blanket3 is None and fuzz._is_noise(200, 900, sigs3) is False


def test_threatintel_pure_parsers():
    """Summarizers/parsers are the testable core - no network needed."""
    from c0mr4de.tools import threatintel as ti
    # classify indicator types
    assert ti._classify("8.8.8.8") == "ip"
    assert ti._classify("example.com") == "domain"
    assert ti._classify("https://x.com/a") == "url"
    assert ti._classify("d41d8cd98f00b204e9800998ecf8427e") == "hash"   # md5
    # VirusTotal verdict from last_analysis_stats
    vt = ti._summarize_vt({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 6},
        "as_owner": "EvilCorp"}}}, "1.2.3.4")
    assert "MALICIOUS" in vt and "3 malicious" in vt and "EvilCorp" in vt
    clean = ti._summarize_vt({"data": {"attributes": {"last_analysis_stats":
             {"malicious": 0, "suspicious": 0, "harmless": 70}}}}, "good.com")
    assert "clean" in clean
    # AbuseIPDB high-abuse threshold
    hi = ti._summarize_abuseipdb({"data": {"abuseConfidenceScore": 88, "totalReports": 42,
                                           "countryCode": "RU", "isp": "X"}}, "9.9.9.9")
    assert "HIGH-ABUSE" in hi and "88%" in hi
    # crt.sh dedupes + strips wildcards + keeps only subdomains of the domain
    subs = ti._parse_crtsh([{"name_value": "*.a.example.com\na.example.com"},
                            {"name_value": "b.example.com"},
                            {"name_value": "evil.com"}], "example.com")
    assert subs == ["a.example.com", "b.example.com"]
    # OTX pulse count
    assert "0 threat pulses" in ti._summarize_otx({"pulse_info": {"count": 0}}, "x.com")
    assert "2 threat pulse" in ti._summarize_otx(
        {"pulse_info": {"count": 2, "pulses": [{"name": "APT-X"}]}}, "x.com")


def test_threatintel_graceful_without_keys():
    """Key-gated tools must degrade with a clear message, never crash, when no key."""
    import os
    from c0mr4de.tools import threatintel as ti
    envs = ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY")
    saved = {e: os.environ.pop(e, None) for e in envs}
    try:
        assert "VT_API_KEY" in ti.virustotal_lookup("8.8.8.8")
        assert "ABUSEIPDB_API_KEY" in ti.abuseipdb_check("8.8.8.8")
        assert "OTX_API_KEY" in ti.otx_indicator("example.com")
        # non-IP input is rejected before any network/key use
        assert "IP address" in ti.abuseipdb_check("not-an-ip")
    finally:
        for e, v in saved.items():
            if v is not None:
                os.environ[e] = v


def test_threatintel_tools_registered():
    from c0mr4de.tools import build_default_registry
    names = build_default_registry().names()
    for t in ("virustotal_lookup", "abuseipdb_check", "greynoise_check",
              "otx_indicator", "crt_sh", "urlscan_search"):
        assert t in names, f"{t} not registered"


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
