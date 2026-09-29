# c0mr4de — Operator Runbook

How to run a real authorized engagement end to end, on your own machine. This is
the operational companion to the README (which explains *what* c0mr4de is). Every
command below is real and matches the CLI.

> **Rule zero — authorization.** Only point c0mr4de at targets you own or are
> contracted/authorized to test. Set the scope (Step 2) so out-of-scope hosts are
> hard-blocked. `test_injection`/`test_all_params` are detection-only and
> non-destructive, but they DO send live requests — treat them as active testing.

---

## 0. One-time setup (your box)

```bash
cd D:\c0mr4de
pip install -e ".[full,browser,osint,laya]"   # core + RAG/UI/OCR + browser + email OSINT + Laya
playwright install chromium                     # for the browser tools
ollama serve                                    # RAG embeddings + local fallback model (keep running)
ollama pull nomic-embed-text                    # embedder (once)
```

- **Config/keys** — copy `config/config.example.yaml` → `config/config.yaml` (gitignored) and set the
  rotating chain (Groq → Gemini → local). A paid/higher-TPM key removes the main ceiling; free works for
  bounded runs.
- **Docker recon tools** (nmap/nuclei/sqlmap/amass/naabu/katana/httpx) — start Docker Desktop and pull the
  images once (`docker pull projectdiscovery/nuclei` etc.). Without Docker, c0mr4de falls back to the native
  `crawl_site` / `test_all_params` / `fuzz_paths` (no Docker needed).
- **Ingest knowledge** (once, and whenever you add playbooks/writeups):
  ```bash
  py -m c0mr4de.cli ingest                                   # playbooks + Obsidian vault
  py -m c0mr4de.cli pentesterland --ingest                   # ~6,400 bug-bounty writeups by class
  py -m c0mr4de.cli graph                                     # build the knowledge graph
  ```
- **Health check** — confirm every subsystem before you rely on it:
  ```bash
  py tests/smoke_all.py --llm       # OK / DEGRADED / BLOCKED matrix; on your box Docker+Ollama flip to OK
  ```

---

## 1. Recon a target's surface

```bash
py -m c0mr4de.cli run "Map the attack surface of example.com" \
    --in-scope "example.com" --max-steps 12
```
Or drive the tools directly (fast, deterministic):
- `map_attack_surface(example.com, ports=true, vulns=true)` — subfinder+amass → httpx → naabu → nuclei →
  a prioritized "most likely vulnerable" report + interactive map in `workspace/surface/`.
- `import_scan(tool, output)` — already ran amass/nuclei/etc.? Paste the output; get the clean scored map.

## 2. Set the rules of engagement (scope + focus)

Pass these on any `run`/`swarm`. Out-of-scope hosts are hard-blocked by `http_request`.
```bash
--in-scope  "app.example.com,api.example.com"
--out-scope "admin.example.com,billing.example.com"
--focus     "IDOR, SSRF, access control, business logic"
```

## 3. Discover + test (the core loop)

```bash
py -m c0mr4de.cli run "Authorized pentest of https://app.example.com. Crawl for endpoints and params, \
test every input, find and demonstrate a vulnerability with a concrete PoC, then write_report." \
    --in-scope "app.example.com" --focus "SQLi, XSS, IDOR, access control" --max-steps 20 --save app.example.com
```
What it does under the hood: `crawl_site` (endpoints/params/forms) → `test_all_params` (SQLi/XSS across every
param + form) → `browser_navigate`/`browser_storage` (JS, tokens) → `decode_jwt`/`tamper_jwt` → `oob_start`/
`oob_poll` (blind bugs) → `consult_knowledge`/`recall_related`/`search_writeups` (methodology) → `write_report`.
The supervisor steers it off loops; the completion gate refuses a "clean" verdict until inputs were tested.

## 4. Authenticated testing

Hand it your session — the agent never logs in or harvests creds itself:
```bash
--auth-host "app.example.com" --auth-cookie "session=…; csrf=…"
# or a header:
--auth-host "app.example.com" --auth-header "Authorization: Bearer …"
```

## 5. Swarm (recon → exploit → report specialists)

```bash
py -m c0mr4de.cli swarm https://app.example.com \
    --objective "Find, exploit and chain vulns; capture any secret; report." \
    --in-scope "app.example.com" --max-steps 16
```

## 6. Web UI (optional)

```bash
py -m c0mr4de.web.app          # http://localhost:8800 — chat, live stream, stop, OSINT graph, settings
```

## 7. Report + after-action

- `write_report` saves a standard report to `workspace/report-<target>-<date>.md`.
- `--save <target>` auto-files the engagement (target + fingerprinted stack + sequence) to `pentest-vault/`.
- Grow the decision data for Laya fine-tuning:
  ```bash
  py -m c0mr4de.cli laya-dataset --sources pentest-vault path/to/report.md --out workspace/laya-decisions.jsonl
  ```
- Log the engagement to Notion (pentests) per your backup convention; general context → Obsidian.

---

## Free-tier survival (Groq)

- Tool-schema trimming is on by default (sends ~18 of 43 tools/request) — keeps you under the 8000 TPM ceiling.
- Empty reply mid-run = TPM/daily cap. The loop retries with a trimmed context, then reports cleanly.
- Daily cap (~200k TPD) is a hard wall — add the Gemini rung (already in the chain) or a paid key for long runs.
- Keep runs bounded: `--max-steps 12–20`, one target at a time.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `nuclei/amass/... not available` | Docker down | start Docker Desktop; or rely on native `crawl_site`/`test_all_params` |
| `consult_knowledge unavailable` | Ollama down | `ollama serve`; meanwhile use `recall_related` (graph, no embedder) |
| Run ends on empty reply | Groq TPM/daily cap | wait for reset, add Gemini/paid key, or fewer `--max-steps` |
| Target TCP-resets you (e.g. WAF) | edge WAF blocks your egress IP | run from your own machine on VPN/Tailscale, pace requests, prefer dev/test mirrors |
| Reports a vuln target as "clean" | shallow run | ensure it called `test_all_params`; the completion gate should catch this |

## Guardrails (built in — don't fight them)

- Scope is enforced server-side in `http_request`; set it every engagement.
- The agent won't create accounts or enter real credentials on its own.
- Injection testing is detection-only; confirm a lead (sqlmap / browser / OOB) before reporting impact.
- Report honestly: a clean result after real testing is a valid result — never fabricate a finding.
