# c0mr4de

An autonomous pentesting agent — built as production infrastructure, not a demo.
Scoped strictly to authorized security testing, CTF work, and learning how advanced
pentest reasoning chains actually work.

## What this actually is (read before you expect magic)

This is **not** a fine-tuned model. Training a model on pentest data needs GPU
compute this project's target hardware (a 4GB laptop GPU) doesn't have, and no
budget for that was approved. What "trained on Roshan's pentests" means here,
honestly:

- **`playbooks/`** — the actual methodology distilled from real, documented
  engagements (Haveloc payment-gate bypass, pixstech VA, M1rage recon, PINERP
  source audit). Concrete, step-by-step, with real findings as worked examples.
- **RAG, not fine-tuning.** These playbooks plus the Obsidian knowledge vault get
  embedded and retrieved at query time via `consult_knowledge`. The model's weights
  never change; it just gets handed the right procedure before it has to improvise.
- This is a real, working technique — production security copilots use exactly
  this pattern — but it has a ceiling: it makes a model *follow* known-good chains
  reliably, it doesn't make it *discover* genuinely novel bug classes the playbooks
  don't cover. Be honest with yourself about which one you're getting.

## Architecture

```
c0mr4de/
  agent/
    backends.py    — model-agnostic LLM interface: Ollama / Anthropic /
                      OpenAI-compatible, plus RotatingBackend (free-API failover)
    loop.py         — ReAct tool loop: RAG grounding, context trimming, nudges,
                      wrap-up-and-report near the step cap, live event streaming
    prompts.py       — system prompt (professional pentest methodology)
  tools/
    web.py            — http_request, decode_jwt, tamper_jwt; sqlmap/nikto (Docker)
    browser.py         — Playwright headless Chromium: navigate, read localStorage/
                          cookies, run JS, screenshot (reads tokens off live pages)
    fuzz.py             — native path/param fuzzer (fuzz_paths, fuzz_param) - no Docker
    recon.py             — nmap, gobuster, ffuf, whatweb (via kali-mcp Docker image)
    recon_stack.py        — reconftw + subfinder wrappers
    osint.py               — username_search (~20 platforms), google_dork, and a
                              Maltego-style interactive graph (render_osint_graph)
    ocr.py                  — EasyOCR text extraction from uploaded images
    operator.py              — ask_operator: non-blocking human-in-the-loop
    report.py                 — write_report -> standard finding format
    files.py / playbook.py     — sandboxed workspace I/O; consult_knowledge (RAG)
  memory/
    embeddings.py       — Ollama nomic-embed-text (local, free)
    vectorstore.py        — Chroma, persisted to ./memory_store
    ingest.py               — loads playbooks/ + Obsidian vault + engagement vault
    writeup_prep.py          — strip a cloned writeup repo to clean text for ingestion
  engagement.py         — auto-save a run (target + fingerprinted stack + sequence)
  web/                    — minimalistic FastAPI UI: chat, upload+OCR, live streaming
playbooks/                — distilled methodology: JWT bypass, recon, OWASP, source
                            audit, OSINT, tool refs, and per-class exploit guides
                            (SSRF, IDOR, XXE, race, GraphQL, deser+SSTI)
  playbooks/ctf/            — CTF category methodology (web/crypto/forensics/
                            reversing/pwn/misc-osint)
pentest-vault/            — engagement library: actual targets + the sequences that
                            worked, ingested so the agent reuses methodology by stack
benchmark/                — mock targets + scored harnesses (Haveloc JWT, path traversal)
tests/                    — pure-logic unit tests (14 passing across test_core +
                            test_tools), incl. the failover regression
config/config.example.yaml — pick your backend here
```

The backend is deliberately swappable — the agent loop has no idea whether it's
talking to a free local model or a paid API. This is the actual design answer to
"local vs. API": don't choose once, choose **per call** if you want to. The
`rotating` backend chains free providers (Groq -> Gemini -> local) and fails over
on rate-limit, so a run never fully stops.

## Proven capability (benchmarks)

- **Haveloc JWT payment-gate bypass** (6/6): full exploit chain + professional
  report, autonomously, on the free Groq brain. The local 7B scored 4/6,1/6,3/6.
- **Novel path traversal, no playbook** (5/5): genuine generalization - reasoned
  to the technique unprompted and fuzzed for the filename.
- **Live m1rage (authorized)**: found no way in and reported clean - does NOT
  fabricate findings on a hardened target.

## Free-tier reality (Groq)

Free Groq = **8000 tokens/minute AND ~200k tokens/day**. Long autonomous runs hit
the daily cap. Add a free Gemini key as a second `rotating` member so it fails over
cloud->cloud before dropping to the slow local model. See config.example.yaml.

## Testing

`python tests/test_core.py` (or `python -m pytest tests/`) - no network/LLM/Docker
needed. Covers the rotating failover, JWT tamper/decode, context trimming, the
text tool-call fallback parser, and stack fingerprinting.

## Hardware/cost reality (know this before you're surprised)

Measured on this machine: RTX 3050 Laptop, **4GB VRAM**, 15.8GB RAM.

| Backend | Capability | Speed here | Cost |
|---|---|---|---|
| `ollama` (qwen2.5-coder:7b, local) | Weakest at chaining multi-step reasoning; fine for routine/simple steps | ~10-25 tok/s, each step ~10-30s | Free (your electricity) |
| `anthropic` (Claude) | Best — this is what actually found the Haveloc chain | Fast, API latency only | Per-token, roughly ₹500-2,000/mo light use, more if heavy |
| `openai_compatible` (DeepSeek-R1, Kimi K2, etc. via DeepInfra/Together/OpenRouter) | Close to frontier on reasoning, real gap on the hardest agentic chains | Fast, API latency only | 5-10x cheaper per token than Claude |

Minimum model size that reliably reproduces the kind of chained reasoning the
Haveloc audit needed (decode → notice the hardcoded IV → connect it to
exploitability) is realistically **~32B** — nowhere close to what a 4GB card can
run. That's not a flaw in this build, it's the actual floor; plan your backend
choice accordingly.

## Setup

Install as a package (gives you the `c0mr4de` command):

```bash
pip install -e ".[full,browser,osint]"   # full local stack + browser + email OSINT
# or minimal: pip install -e .            # core agent only
```

Or run the bundled setup script (installs deps, pulls local models, ingests knowledge):

```powershell
cd D:\c0mr4de
.\scripts\setup.ps1
```

This installs Python deps, pulls the local Ollama models if missing, creates
`config/config.yaml` from the example (edit it to point at Claude or a hosted
open-weight provider instead), and ingests `playbooks/` + your Obsidian vault
(`C:\Users\rosha\OneDrive\ClaudeMemory\Claude-Context`) into the local knowledge
store.

Recon tools (`nmap`, `gobuster`, `ffuf`, `sqlmap`, `nikto`) run through the
`kali-mcp` Docker image — build/pull that separately if you haven't (see
`ctf-pentest-setup` in your memory vault for the original setup notes).

## Usage

```powershell
py -m c0mr4de.cli run "recon example.com and summarize the attack surface"
```

Re-run ingestion any time you add a new playbook or the Obsidian vault changes:

```powershell
py -m c0mr4de.cli ingest
```

### Growing the knowledge base from writeups (the honest way)

RAG retrieves on *relevance*, not volume — a 50GB dump of challenge archives is
mostly un-embeddable noise (binaries, images, challenge files). What actually
makes it smarter is clean prose: writeups, methodology, cheat sheets. `prep-writeups`
walks a cloned repo, drops everything that isn't text, strips images/base64/dupes,
tags each file by category, and writes a flat corpus ready to ingest:

```powershell
py -m c0mr4de.cli prep-writeups D:\some-ctf-writeups --out workspace\writeup-corpus
py -m c0mr4de.cli ingest --sources workspace\writeup-corpus
# or in one step:
py -m c0mr4de.cli prep-writeups D:\some-ctf-writeups --out workspace\writeup-corpus --ingest
```

Pentester Land's full index (~6400 curated bug-bounty/pentest writeups) can be
pulled in wholesale, grouped by bug class so a query like "SSRF account takeover"
retrieves a chunk full of real writeups + URLs (re-run weekly to refresh):

```powershell
py -m c0mr4de.cli pentesterland --ingest
```

## Scope and safety

The system prompt hard-requires the agent to stay inside a named target scope
and refuse to improvise past it. It will not create accounts or enter credentials
on its own — authenticated testing needs your session cookie, passed explicitly.
This tool is for targets you are authorized to test. Nothing here evades that
requirement or should be pointed at anything else.

## Honest roadmap (what's NOT built yet)

- **Multi-agent swarm orchestration** — right now this is a single agent loop, not
  a swarm. A real swarm (recon agent, exploit agent, reporting agent, shared
  blackboard memory) is a meaningfully bigger build than this v0.1 — next phase.
- **Browser control** — JARVIS already has a working browser-harness; wiring it in
  as a c0mr4de tool is straightforward but not done in this pass.
- **Automatic cost-aware routing** between local/cheap/premium backends per step —
  currently you pick one backend per run manually.
- **Burp integration** — MCP-based, needs the Claude Desktop Burp MCP bridge
  ported to a standalone client here.
