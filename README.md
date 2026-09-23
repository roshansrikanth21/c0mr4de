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
    backends.py    — model-agnostic LLM interface (Ollama / Anthropic / any
                      OpenAI-compatible hosted-open-weight provider)
    loop.py         — the ReAct tool-calling loop
    prompts.py       — system prompt
  tools/
    recon.py         — nmap, gobuster, ffuf, whatweb (via the kali-mcp Docker image)
    web.py            — raw HTTP requests, JWT decode, sqlmap, nikto
    files.py          — sandboxed workspace read/write
    playbook.py        — consult_knowledge (RAG retrieval tool)
  memory/
    embeddings.py       — Ollama nomic-embed-text (local, free)
    vectorstore.py        — Chroma, persisted to ./memory_store
    ingest.py               — loads playbooks/ + the Obsidian vault into the store
playbooks/                — the distilled methodology (see above)
config/config.example.yaml — pick your backend here
```

The backend is deliberately swappable — the agent loop has no idea whether it's
talking to a free local model or a paid API. This is the actual design answer to
"local vs. API": don't choose once, choose **per call** if you want to, by running
routine steps on one backend and routing the hard reasoning to another.

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
