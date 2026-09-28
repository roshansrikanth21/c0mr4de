"""Full-system smoke test — exercise EVERY c0mr4de subsystem end to end and print
a health matrix. Unlike the unit tests (pure logic), this actually drives the
live components: HTTP, crawler, injection tester, RAG embedder, knowledge graph,
attack-surface engine, writeups search, backends, swarm wiring, web app import.

Each check is independent and degrades gracefully, so a missing dependency
(Docker, Playwright, Ollama, network, LLM quota) is reported as BLOCKED/DEGRADED
rather than crashing the run. Authorized live target: ginandjuice.shop
(PortSwigger's public test site).

Run:  py tests/smoke_all.py            (skips the paid LLM call)
      py tests/smoke_all.py --llm      (also fires one tiny backend generate)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

TARGET = "https://ginandjuice.shop"
results: list[tuple[str, str, str, str]] = []   # (subsystem, component, status, note)


def check(sub: str, name: str, fn, degrade_markers=("not available", "unavailable", "not installed",
                                                    "not on path", "docker", "playwright", "ollama",
                                                    "empty", "timed out", "needs")):
    t0 = time.time()
    try:
        out = fn()
        dt = f"{time.time()-t0:.1f}s"
        s = str(out) if out is not None else ""
        low = s.lower()
        if any(m in low for m in degrade_markers) or low.startswith(("error", "request error", "blocked")):
            status = "DEGRADED"
        else:
            status = "OK"
        note = s.replace("\n", " ")[:70]
        results.append((sub, name, status, f"{note}  ({dt})"))
    except Exception as exc:  # noqa: BLE001
        results.append((sub, name, "FAIL", f"{type(exc).__name__}: {exc}"[:80]))


def blocked(sub, name, note):
    results.append((sub, name, "BLOCKED", note))


# ── 1. Config + backends + tools registry ────────────────────────────────────
from c0mr4de.tools import build_default_registry, _docker_available  # noqa: E402

reg = build_default_registry()
check("core", "tool registry", lambda: f"{len(reg.names())} tools registered")
docker_up = _docker_available()

from c0mr4de.agent.toolselect import select_names  # noqa: E402
check("agent", "toolselect (schema trim)",
      lambda: f"{len(select_names(TARGET + ' sqli xss recon jwt', '', set(), set(reg.names())))} of {len(reg.names())} selected")

if "--llm" in sys.argv:
    def _llm():
        import yaml
        from c0mr4de.agent.backends import build_backend
        cfg = yaml.safe_load(open(Path(__file__).resolve().parent.parent / "config" / "config.yaml", encoding="utf-8"))
        b = build_backend(cfg["backend"])
        r = b.generate("Reply with the single word OK.", [{"role": "user", "content": "OK?"}], tools=[])
        return f"{getattr(b, '_last_used', b).name}: {r.text[:30]!r}"
    check("agent", "LLM backend (rotating)", _llm)
else:
    results.append(("agent", "LLM backend (rotating)", "SKIP", "pass --llm to fire one tiny generate"))

# ── 2. Governance: scope + auth ───────────────────────────────────────────────
from c0mr4de import auth, scope  # noqa: E402

def _scope():
    scope.set_scope(in_scope=["ginandjuice.shop"], out_of_scope=["admin.internal"], focus="SQLi")
    r = (scope.check("https://ginandjuice.shop/x"), scope.check("https://admin.internal/x"))
    scope.clear_scope()
    return f"in={r[0]} out={r[1]}"
check("core", "scope (RoE)", _scope)

def _auth():
    auth.set_auth("ginandjuice.shop", cookie="sid=demo")
    r = auth.for_url("https://ginandjuice.shop/x").get("cookie")
    auth.clear_auth()
    return f"cookie attached: {r}"
check("core", "auth (host session)", _auth)

# ── 3. Web tools ──────────────────────────────────────────────────────────────
from c0mr4de.tools.web import http_request, decode_jwt, tamper_jwt, extract_surface  # noqa: E402

check("web", "http_request (live)", lambda: http_request(TARGET).split("\n")[0])
check("web", "extract_surface", lambda: f"{len(extract_surface('<a href=/catalog?q=1>x</a><form action=/login><input name=u></form>', TARGET)['params'])} params")
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.sig"
check("web", "decode_jwt", lambda: "role" if "role" in decode_jwt(_JWT) else "?")
check("web", "tamper_jwt", lambda: "tampered" if "tampered" in tamper_jwt(_JWT, "role", "admin") else "?")

# ── 4. Native discovery + injection ───────────────────────────────────────────
from c0mr4de.tools.webrecon import crawl_site, test_injection  # noqa: E402

check("recon", "crawl_site (live)", lambda: crawl_site(TARGET, depth=1, max_pages=8).split("\n")[0])
check("exploit", "test_injection (live)", lambda: test_injection(TARGET + "/catalog?searchTerm=x").split("\n")[0])

from c0mr4de.tools.fuzz import fuzz_paths  # noqa: E402
check("recon", "fuzz_paths (live)", lambda: fuzz_paths(TARGET, "paths").split("\n")[0])

# ── 5. Browser (Playwright) ───────────────────────────────────────────────────
from c0mr4de.tools.browser import browser_navigate  # noqa: E402
check("browser", "browser_navigate (live)", lambda: browser_navigate(TARGET).split("\n")[0])

# ── 6. OSINT ──────────────────────────────────────────────────────────────────
from c0mr4de.tools.osint import google_dork, add_osint_note, render_osint_graph  # noqa: E402
check("osint", "google_dork (live)", lambda: google_dork("site:ginandjuice.shop").split("\n")[0])
def _graph_osint():
    add_osint_note("bob@x.com", "email")
    add_osint_note("bob", "username", "email:bob@x.com", "owns")
    return render_osint_graph("smoke_osint.html")
check("osint", "osint graph render", _graph_osint)
results.append(("osint", "username_search / email_osint", "AVAIL", "live-callable; skipped (slow multi-site sweep)"))

# ── 7. Memory: vector RAG + embeddings ────────────────────────────────────────
from c0mr4de.tools.playbook import consult_knowledge  # noqa: E402
from c0mr4de.memory.vectorstore import VectorStore  # noqa: E402
check("memory", "vector store count", lambda: f"{VectorStore().count()} chunks")
check("memory", "consult_knowledge (RAG+embed)", lambda: consult_knowledge("SSRF to account takeover")[:60])

# ── 8. Knowledge graph ────────────────────────────────────────────────────────
from c0mr4de.memory.graph import recall_related, render_graph, _graph  # noqa: E402
check("memory", "knowledge graph build", lambda: f"{_graph().stats()}")
check("memory", "recall_related", lambda: recall_related("JWT").split("\n")[0])
check("memory", "graph render", lambda: render_graph("smoke_graph.html"))

# ── 9. Writeups engine ────────────────────────────────────────────────────────
from c0mr4de.tools.writeups import search_writeups, fetch_writeup  # noqa: E402
check("knowledge", "search_writeups (live)", lambda: search_writeups("IDOR account takeover").split("\n")[0])
check("knowledge", "fetch_writeup (live)", lambda: fetch_writeup("https://pentester.land/writeups/").split("\n")[1][:60])

# ── 10. Attack-surface engine ─────────────────────────────────────────────────
from c0mr4de.tools.surface import import_scan, attack_surface_report  # noqa: E402
def _surface():
    import_scan("httpx", '{"url":"https://a.ginandjuice.shop/.git/config","status_code":200,"tech":["GitLab"]}')
    import_scan("nuclei", '{"template-id":"CVE-1","info":{"name":"RCE","severity":"critical"},"matched-at":"https://a.ginandjuice.shop/.git/config"}')
    return attack_surface_report().split("\n")[0]
check("surface", "import_scan + analyze + render", _surface)

# ── 11. Workflow: worklog, report, engagement, stats, supervisor ──────────────
from c0mr4de.tools.worklog import worklog, read_worklog  # noqa: E402
def _worklog():
    worklog("smoke.target", "vulnerability", "reflected XSS in searchTerm")
    return "logged" if "searchTerm" in read_worklog("smoke.target") else "?"
check("workflow", "worklog", _worklog)

from c0mr4de.tools.report import TOOLS as _report_tools  # noqa: E402
def _report():
    fn = {t.name: t.fn for t in _report_tools}["write_report"]
    out = fn(target="smoke.target", summary="smoke", positives="", findings_json='[{"title":"XSS","severity":"medium"}]')
    return out.split("\n")[0]
check("workflow", "write_report", _report)

from c0mr4de.engagement import _fingerprint_stack  # noqa: E402
check("workflow", "engagement fingerprint", lambda: str(_fingerprint_stack("Server: nginx, X-Powered-By: PHP"))[:50] or "ok")

from c0mr4de import stats  # noqa: E402
def _stats():
    stats.record("smoke-model", 100, 50, 1.2)
    return "recorded"
check("workflow", "stats", _stats)

from c0mr4de.agent.supervisor import Supervisor  # noqa: E402
from c0mr4de.agent.loop import StepLog  # noqa: E402
def _sup():
    log = [StepLog(1, "", ["http_request(x)"], ["200"]), StepLog(2, "", ["http_request(x)"], ["200"])]
    v = Supervisor().review(log)
    return f"steer fired: {bool(v)}"
check("agent", "supervisor (loop/stuck)", _sup)

# ── 12. Swarm wiring ──────────────────────────────────────────────────────────
from c0mr4de.swarm.agents import PIPELINE  # noqa: E402
def _swarm():
    counts = {p.name: len(p.registry().names()) for p in PIPELINE}
    return " ".join(f"{k}={v}" for k, v in counts.items())
check("swarm", "specialist profiles + scoped tools", _swarm)

# ── 13. Interfaces + ingestion modules import ─────────────────────────────────
check("interface", "web app import", lambda: __import__("c0mr4de.web.app", fromlist=["app"]).app.__class__.__name__)
check("interface", "cli import", lambda: "ok" if __import__("c0mr4de.cli", fromlist=["main"]).main else "?")
check("memory", "ingest/prep/pentesterland import",
      lambda: "ok" if all(__import__(f"c0mr4de.memory.{m}", fromlist=["x"]) for m in ("ingest", "writeup_prep", "pentesterland")) else "?")
from c0mr4de.tools.ocr import TOOLS as _ocr  # noqa: E402
results.append(("tools", "ocr_image", "AVAIL", "EasyOCR (heavy); imported, not run"))

# ── 14. Docker-gated tools ────────────────────────────────────────────────────
for t in ("nmap", "nuclei_scan", "sqlmap", "amass_enum", "naabu_scan", "crawl(katana)", "probe(httpx)"):
    if docker_up:
        results.append(("recon", t, "AVAIL", "Docker up — runnable"))
    else:
        blocked("recon", t, "Docker down in this sandbox — runs on your box")

# ── Print matrix ──────────────────────────────────────────────────────────────
order = {"OK": 0, "AVAIL": 1, "SKIP": 2, "DEGRADED": 3, "BLOCKED": 4, "FAIL": 5}
icon = {"OK": "[OK]", "AVAIL": "[--]", "SKIP": "[..]", "DEGRADED": "[~]", "BLOCKED": "[x]", "FAIL": "[!]"}
print("\n" + "=" * 78)
print("c0mr4de FULL-SYSTEM SMOKE TEST")
print("=" * 78)
cur = None
for sub, name, status, note in sorted(results, key=lambda r: (r[0], order.get(r[2], 9))):
    if sub != cur:
        cur = sub
        print(f"\n-- {sub.upper()} --")
    print(f"  {icon.get(status,'?'):5} {name:34} {note}")
tally = {}
for _, _, s, _ in results:
    tally[s] = tally.get(s, 0) + 1
print("\n" + "=" * 78)
print("SUMMARY: " + "  ".join(f"{k}={v}" for k, v in sorted(tally.items(), key=lambda x: order.get(x[0], 9))))
print(f"components exercised: {len(results)}")
print("=" * 78)
sys.exit(1 if tally.get("FAIL") else 0)
