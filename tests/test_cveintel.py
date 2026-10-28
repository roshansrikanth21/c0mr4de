"""CVE-intelligence tool tests. The value is prioritisation - actively-exploited
(CISA KEV) and version-matched CVEs must rank first - and honest degradation, so
these assert ranking order, KEV token-matching (without over-matching on generic
words), and that lookups never touch the network here (NVD/KEV are monkeypatched)."""
import c0mr4de.tools.cveintel as C


def test_split_product_version():
    assert C._split_product_version("Apache HTTP Server 2.4.49") == ("Apache HTTP Server", "2.4.49")
    assert C._split_product_version("nginx 1.18.0") == ("nginx", "1.18.0")
    assert C._split_product_version("WordPress") == ("WordPress", "")
    assert C._split_product_version("jQuery 3.4.1") == ("jQuery", "3.4.1")


def test_cvss_prefers_v31_then_falls_back():
    v31 = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}
    assert C._cvss_of(v31) == (9.8, "CRITICAL")
    v2 = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}}         # v2 has no severity label
    assert C._cvss_of(v2) == (7.5, "HIGH")
    assert C._cvss_of({}) == (0.0, "UNKNOWN")


def _payload():
    return {"vulnerabilities": [
        {"cve": {"id": "CVE-LOW", "descriptions": [{"lang": "en", "value": "minor"}],
                 "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 2.6}}]}}},
        {"cve": {"id": "CVE-HIGH-EXPLOIT", "descriptions": [{"lang": "en", "value": "traversal in 2.4.49"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}}},
        {"cve": {"id": "CVE-CRIT", "descriptions": [{"lang": "en", "value": "rce"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}},
    ]}


def test_rank_exploited_first_then_versionmatch_then_cvss():
    kev = {"CVE-HIGH-EXPLOIT": {"ransomware": False}}
    ranked = C._rank(C._parse_nvd(_payload(), kev, version="2.4.49"))
    # KEV + version-match wins over the higher-CVSS non-exploited one
    assert ranked[0]["id"] == "CVE-HIGH-EXPLOIT"
    assert ranked[1]["id"] == "CVE-CRIT"      # 9.8 beats 2.6
    assert ranked[2]["id"] == "CVE-LOW"


def test_kev_matches_token_based_and_skips_generic():
    kev = {
        "CVE-A": {"vendor": "Apache", "product": "HTTP Server", "name": "traversal", "ransomware": False},
        "CVE-W": {"vendor": "WordPress", "product": "Core", "name": "rfi", "ransomware": True},
    }
    got = {c["id"] for c in C._kev_matches("Apache HTTP Server", kev)}
    assert "CVE-A" in got and "CVE-W" not in got
    # a purely generic product yields no matches (no over-matching on "server"/"web")
    assert C._kev_matches("Web Server", kev) == []
    # ransomware flag carried through
    wp = C._kev_matches("WordPress", kev)
    assert wp and wp[0]["ransomware"] is True


def test_fmt_hides_zero_cvss_for_kev_only():
    c = {"id": "CVE-X", "score": 0.0, "severity": "KEV", "kev": True, "ransomware": False,
         "version_match": False, "desc": "d"}
    out = C._fmt_cve(c)
    assert "CVSS 0.0" not in out and "KEV" in out and "EXPLOITED-IN-WILD" in out


def test_cve_lookup_mocked(monkeypatch):
    monkeypatch.setattr(C, "_load_kev", lambda force=False: {"CVE-HIGH-EXPLOIT": {"ransomware": False}})
    monkeypatch.setattr(C, "_nvd_search", lambda product, limit, kev_only=False: (_payload(), ""))
    out = C.cve_lookup("Apache HTTP Server", "2.4.49", limit=5)
    assert "actively exploited" in out and "CVE-HIGH-EXPLOIT" in out
    assert out.index("CVE-HIGH-EXPLOIT") < out.index("CVE-CRIT")   # exploited listed first


def test_cve_lookup_needs_product():
    assert "needs a product" in C.cve_lookup("")


def test_cve_for_surface_uses_local_kev(monkeypatch):
    from c0mr4de.tools import surface
    surface._SURFACE = surface.AttackSurface()                      # clean slate
    surface._SURFACE.add_endpoint("http://t/", status=200,
                                  tech=["Apache HTTP Server 2.4.49", "jQuery 1.12.4"],
                                  webserver="Apache", source="test")
    kev = {"CVE-AP": {"vendor": "Apache", "product": "HTTP Server", "name": "traversal", "ransomware": False},
           "CVE-JQ": {"vendor": "jQuery", "product": "jQuery", "name": "xss", "ransomware": False}}
    monkeypatch.setattr(C, "_load_kev", lambda force=False: kev)
    out = C.cve_for_surface()
    assert "CVE-AP" in out and "CVE-JQ" in out
    assert "actively-exploited" in out.lower()
    # the bare "Apache" (from webserver) must be de-duped against "Apache HTTP Server"
    assert out.count("=== Apache ===") == 0


def test_cve_for_surface_empty_surface(monkeypatch):
    from c0mr4de.tools import surface
    surface._SURFACE = surface.AttackSurface()
    assert "Run recon first" in C.cve_for_surface()


def test_tools_registered():
    from c0mr4de.tools import build_default_registry
    reg = build_default_registry()
    assert reg.get("cve_lookup") and reg.get("cve_for_surface")
