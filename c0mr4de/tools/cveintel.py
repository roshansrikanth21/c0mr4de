"""CVE intelligence: map a detected stack/version to known CVEs, PRIORITISED by
what is actually being exploited in the wild (CISA KEV), not a raw CVE dump.

This is the one genuinely-useful idea borrowed from hexstrike-ai, done c0mr4de's
way: it hangs off the recon/attack-surface the other tools already build, and it
produces LEADS to verify - never "confirmed" findings. A CVE matching a detected
product is a hypothesis; whether this target is actually vulnerable still has to be
proven by the exploit/validate specialists. Presence of a CVE != exploitable.

Sources, both keyless:
- NVD 2.0 API (services.nvd.nist.gov) - product/keyword -> CVEs + CVSS. Keyless is
  rate-limited (~5 req / 30s), so queries are capped, spaced, and fail soft.
- CISA KEV catalog (cisa.gov) - the set of CVEs with confirmed in-the-wild
  exploitation. One JSON, cached locally and refreshed daily. This is the signal
  that turns a CVE list into a priority list.

Pure _parse_*/_rank_*/_split_* helpers keep the logic testable without network.
"""
from __future__ import annotations

import json
import os
import re
import time

import httpx

from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE = WORKSPACE / "cve-cache" / "cisa_kev.json"
_KEV_TTL = 24 * 3600            # refresh the KEV catalog at most once a day
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,3})\b")
# tech strings that are too generic to yield a useful CVE search
_SKIP_TECH = {"html5", "javascript", "css", "http", "https", "cloudflare", "webpack", "font awesome"}


# ── stack string parsing ───────────────────────────────────────────────────────
def _split_product_version(tech: str) -> tuple[str, str]:
    """'Apache httpd 2.4.49' -> ('Apache httpd', '2.4.49'); 'WordPress' -> ('WordPress', '')."""
    tech = (tech or "").strip()
    m = _VERSION_RE.search(tech)
    if not m:
        return tech, ""
    product = tech[:m.start()].strip(" :/-")
    return (product or tech), m.group(1)


# ── CISA KEV (actively-exploited set) ───────────────────────────────────────────
def _load_kev(force: bool = False) -> dict:
    """{cve_id: {name, vendor, product, dueDate, ransomware}} from the CISA KEV
    catalog, cached to the workspace. Never raises - returns {} if unavailable."""
    try:
        fresh = _KEV_CACHE.exists() and (time.time() - _KEV_CACHE.stat().st_mtime) < _KEV_TTL
        if force or not fresh:
            r = httpx.get(_KEV_URL, timeout=30, follow_redirects=True)
            if r.status_code == 200 and "vulnerabilities" in r.text:
                _KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
                _KEV_CACHE.write_text(r.text, encoding="utf-8")
        data = json.loads(_KEV_CACHE.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - offline / parse error: KEV just becomes empty
        return {}
    out = {}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            out[cid] = {"name": v.get("vulnerabilityName", ""), "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""), "dueDate": v.get("dueDate", ""),
                        "ransomware": (v.get("knownRansomwareCampaignUse", "") or "").lower() == "known"}
    return out


# ── NVD parsing + ranking ───────────────────────────────────────────────────────
def _cvss_of(cve: dict) -> tuple[float, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData") or {}
            score = d.get("baseScore")
            sev = d.get("baseSeverity") or arr[0].get("baseSeverity") or ""
            if score is not None:
                if not sev:   # v2 has no baseSeverity field
                    sev = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else
                           "MEDIUM" if score >= 4 else "LOW")
                return float(score), sev.upper()
    return 0.0, "UNKNOWN"


def _desc_of(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return (d.get("value") or "").strip()
    return ""


def _parse_nvd(payload: dict, kev: dict, version: str = "") -> list[dict]:
    """NVD response -> list of normalized CVE dicts, annotated with KEV + version match."""
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cid = cve.get("id", "")
        if not cid:
            continue
        score, sev = _cvss_of(cve)
        desc = _desc_of(cve)
        in_kev = cid in kev
        ver_match = bool(version) and version in (desc + " " + json.dumps(cve.get("configurations", [])))
        out.append({"id": cid, "score": score, "severity": sev, "kev": in_kev,
                    "ransomware": bool(in_kev and kev[cid].get("ransomware")),
                    "version_match": ver_match, "desc": desc[:240]})
    return out


def _rank(cves: list[dict]) -> list[dict]:
    """Actively-exploited (KEV) first, then version-matched, then CVSS, then id."""
    return sorted(cves, key=lambda c: (not c["kev"], not c["version_match"], -c["score"], c["id"]))


def _fmt_cve(c: dict) -> str:
    flags = []
    if c["kev"]:
        flags.append("EXPLOITED-IN-WILD" + (" (ransomware)" if c["ransomware"] else ""))
    if c["version_match"]:
        flags.append("version-match")
    tag = ("  [" + ", ".join(flags) + "]") if flags else ""
    sev = f"CVSS {c['score']:.1f} {c['severity']}" if c["score"] > 0 else c["severity"]
    return f"  {c['id']}  {sev}{tag}\n    {c['desc']}"


# ── KEV product cross-reference (local, no network, no rate limit) ──────────────
_GENERIC_TOK = {"server", "http", "https", "web", "service", "services", "framework", "httpd",
                "the", "and", "app", "api", "js", "software", "manager", "suite", "core"}


def _kev_matches(product: str, kev: dict, limit: int = 8) -> list[dict]:
    """Actively-exploited CVEs whose KEV vendor/product matches the detected product.
    Local scan of the cached catalog - reliable and rate-limit-free, which is why it
    is the primary signal for the surface sweep."""
    toks = [t for t in re.split(r"[\s_/.\-]+", (product or "").lower()) if len(t) >= 3 and t not in _GENERIC_TOK]
    if not toks:
        return []
    out = []
    for cid, meta in kev.items():
        hay = (meta.get("vendor", "") + " " + meta.get("product", "") + " " + meta.get("name", "")).lower()
        if any(t in hay for t in toks):
            label = f"{meta.get('vendor', '')} {meta.get('product', '')}".strip()
            out.append({"id": cid, "score": 0.0, "severity": "KEV", "kev": True,
                        "ransomware": meta.get("ransomware", False), "version_match": False,
                        "desc": f"{label}: {meta.get('name', '')} [CISA KEV - actively exploited]".strip()[:240]})
    return out[:limit]


# ── NVD query ───────────────────────────────────────────────────────────────────
def _nvd_search(product: str, limit: int, kev_only: bool = False) -> tuple[dict | None, str]:
    """NVD keyword search by product. kev_only adds hasKevParam so only
    actively-exploited CVEs come back (reliable + relevant, unlike the default
    oldest-first keyword page)."""
    headers = {}
    key = os.environ.get("NVD_API_KEY") or ""
    if key:
        headers["apiKey"] = key
    params = {"keywordSearch": product, "resultsPerPage": min(max(limit * 4, 20), 40)}
    if kev_only:
        params["hasKev"] = ""        # valueless flag: restrict to the KEV catalog
    try:
        r = httpx.get(_NVD_URL, params=params, headers=headers, timeout=30, follow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return None, f"NVD unreachable ({type(exc).__name__})."
    if r.status_code in (403, 429):
        return None, "NVD rate-limited (keyless ~5 req/30s). Wait, or set NVD_API_KEY (free, raises the limit)."
    if r.status_code != 200:
        return None, f"NVD returned HTTP {r.status_code}."
    try:
        return r.json(), ""
    except Exception:  # noqa: BLE001
        return None, "NVD returned unparseable JSON."


def cve_lookup(product: str, version: str = "", limit: int = 8) -> str:
    """Known CVEs for a product (optionally a version), prioritising in-the-wild
    exploitation (CISA KEV) then CVSS. Passive - queries NVD + CISA, never touches
    the target. These are LEADS to verify, not confirmed vulnerabilities."""
    product = (product or "").strip()
    if not product:
        return "cve_lookup needs a product, e.g. cve_lookup(product='Apache HTTP Server', version='2.4.49')."
    term = f"{product} {version}".strip()
    kev = _load_kev()
    # 1. actively-exploited CVEs for the product, CVSS-enriched from NVD (hasKev)
    payload, err = _nvd_search(product, limit, kev_only=True)
    cves = _rank(_parse_nvd(payload, kev, version)) if payload is not None else []
    # 2. guarantee KEV coverage even if NVD is rate-limited or misses one (local catalog)
    have = {c["id"] for c in cves}
    cves += [c for c in _kev_matches(product, kev, limit) if c["id"] not in have]
    cves = _rank(cves)[:limit]
    if not cves:
        if err:
            return f"cve_lookup({term}): {err} No actively-exploited CVEs found locally either."
        return (f"cve_lookup({term}): no ACTIVELY-EXPLOITED CVEs for this product. That does not mean it is "
                f"safe - run nuclei_scan and the exploit specialists for non-KEV issues.")
    n_kev = sum(1 for c in cves if c["kev"])
    head = (f"CVEs for '{term}' ({len(cves)} shown" + (f", {n_kev} actively exploited in the wild" if n_kev else "") +
            "). LEADS to verify, not confirmed:")
    return head + "\n" + "\n".join(_fmt_cve(c) for c in cves)


# ── surface-wide correlation ────────────────────────────────────────────────────
def _surface_tech() -> list[str]:
    """Distinct product[/version] strings from the in-process attack surface:
    endpoint tech + webserver + host port-service strings."""
    try:
        from c0mr4de.tools.surface import _SURFACE
    except Exception:  # noqa: BLE001
        return []
    seen, out = set(), []
    def add(s):
        s = (s or "").strip()
        if s and s.lower() not in _SKIP_TECH and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    for e in _SURFACE.endpoints.values():
        for t in e.tech:
            add(t)
        add(e.webserver)
    for h in _SURFACE.hosts.values():
        for svc in h.ports.values():
            add(svc)
    return out


def cve_for_surface(max_products: int = 10) -> str:
    """Correlate the CURRENT attack surface (everything recon/import_scan has fed in)
    against ACTIVELY-EXPLOITED CVEs (CISA KEV), per detected product. Run after recon.
    Passive, local (no per-product NVD calls, so no rate-limit storm). Emits LEADS for
    the exploit specialists to verify - a matched CVE is a hypothesis, not a finding.
    For a CVSS-enriched deep dive on one product, use cve_lookup."""
    techs = _surface_tech()
    if not techs:
        return ("No technologies in the attack surface yet. Run recon first (crawl/probe/httpx "
                "-tech-detect, map_attack_surface, or import_scan), then re-run cve_for_surface.")
    kev = _load_kev()
    if not kev:
        return ("CISA KEV catalog unavailable (offline?). Use cve_lookup(product, version) per product "
                "once you have connectivity.")
    products = sorted({_split_product_version(t) for t in techs}, key=lambda pv: (pv[1] == "",))
    # drop a bare product ('Apache') when a more specific one ('Apache HTTP Server') is present
    _names = [p for p, _ in products]
    products = [(p, v) for (p, v) in products
                if not any(o.lower() != p.lower() and o.lower().startswith(p.lower() + " ") for o in _names)]
    products = products[:max_products]
    blocks, total, exploited = [], 0, 0
    checked = []
    for product, version in products:
        checked.append(product)
        cves = _kev_matches(product, kev, limit=6)
        if not cves:
            continue
        total += len(cves)
        exploited += len(cves)
        label = f"{product}" + (f" {version}" if version else "")
        blocks.append(f"=== {label} ===\n" + "\n".join(_fmt_cve(c) for c in cves))
    if not blocks:
        return (f"No ACTIVELY-EXPLOITED (CISA KEV) CVEs matched the {len(checked)} product(s) detected: "
                f"{', '.join(checked)}. That is good but not a clean bill - run nuclei_scan and the exploit "
                f"specialists for non-KEV issues, or cve_lookup a specific product for its full CVE history.")
    head = (f"Actively-exploited CVEs matching the attack surface ({len(checked)} product(s) checked): "
            f"{exploited} CISA-KEV lead(s) across {len(blocks)} product(s). These are exploited in the wild - "
            f"HIGH priority, but still verify this target is actually affected before reporting.\n")
    return head + "\n\n".join(blocks)


TOOLS = [
    Tool(
        name="cve_lookup",
        description=(
            "Known CVEs for a specific product and optional version (e.g. product='Apache httpd', "
            "version='2.4.49'), ranked by real-world exploitation (CISA KEV) then CVSS. Passive - "
            "queries NVD + CISA, never touches the target. Returns LEADS to verify, not confirmed bugs."
        ),
        parameters={"type": "object", "properties": {
            "product": {"type": "string"}, "version": {"type": "string"},
            "limit": {"type": "integer"}}, "required": ["product"]},
        fn=cve_lookup,
    ),
    Tool(
        name="cve_for_surface",
        description=(
            "Correlate the whole current attack surface (all detected tech/versions from recon) against "
            "known CVEs at once, prioritising actively-exploited ones (CISA KEV). Run after recon. Passive; "
            "emits leads for the exploit specialists to verify."
        ),
        parameters={"type": "object", "properties": {
            "max_products": {"type": "integer"}}, "required": []},
        fn=cve_for_surface,
    ),
]
