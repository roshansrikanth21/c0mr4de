# c0mr4de improvement research - 2026-10-07

GitHub + web research into the current AI-security tooling landscape, turned into a
prioritized, concrete plan. Framed around c0mr4de's actual edge: deterministic /
execution-confirmed validation (proven in the no-BS true-positive/true-negative
test), model-agnostic free backend, runs on Roshan's own box, bug-bounty + CTF +
source-audit focus.

## Where c0mr4de sits in the 2026 landscape

39+ open-source AI pentest agents now exist across 6 architecture patterns
(single-agent, planner-executor, specialized-roles, swarm, MCP-based, Claude-Code-
native). The market has converged on exactly c0mr4de's thesis: the leaders win on
*validation*, not detection. The standout, Strix (~42k stars, Apache-2.0,
usestrix/strix), differentiates purely on "every finding ships a working PoC,
validated by actually running it." c0mr4de already does execution-confirmed
validation; the gap is in coverage and packaging, not philosophy.

## Tier 1 - highest ROI (do these first)

### 1. Source-audit mode (Vulnhuntr pattern)
`protectai/vulnhuntr` traces a call chain from remote user input (GET/POST) through
to a server-side sink across files, runs ONE tailored prompt per vuln class
(SQLi/XSS/LFI), and emits a PoC. It found real RCE 0-days (ComfyUI, FastChat,
Ragflow). This is Roshan's actual workflow (source audits: PINERP, Pramaan) and it
reuses the vuln-class playbooks just added (sqli/xss/file-inclusion/command-
injection). Add an `audit_source(repo_path, vuln_class)` tool: identify input
handlers, trace input->sink, feed the combined chain + the matching playbook to the
model, output finding + PoC + verified/unverified. Extends the validation thesis to
the static side.

### 2. Widen the recon stack (ProjectDiscovery tools c0mr4de lacks)
Already has httpx/nuclei/subfinder/naabu/amass. Missing, all free, all plug into the
existing `surface`/`import_scan` pipeline:
- `katana` - JS-aware crawler, finds far more params/endpoints than the native
  crawler (more surface to test = more bugs).
- `gau` + `waybackurls` - historical URLs from web archives; forgotten endpoints and
  params for free. Biggest cheap win for bug bounty.
- `dnsx` (resolution/bruteforce), `tlsx` (cert SANs -> more subdomains),
  `cdncheck` (identify CDN/WAF so testing adapts).

### 3. Auto-PoC per confirmed finding
Strix and Vulnhuntr both attach a reproducible PoC to every finding. c0mr4de reports
findings but should emit a copy-pasteable PoC (the exact request / a short script)
for each CONFIRMED finding, saved next to the report. Strengthens reports and matches
the verified/unverified discipline (only verified findings get a PoC).

## Tier 2 - strong, more build

### 4. Semgrep + LLM-triage (false-positive control, proven pattern)
The research consensus: layer an LLM over a SAST engine with code-context + dataflow
to cut false positives 88-99% (QASecClaw 88.6%, SAST-Genius 91%, OpenAnt 99.98%,
ZeroFalse, Vulnhalla-on-CodeQL). Add `semgrep` as a tool, then an LLM filter stage
that judges each hit's exploitability with the surrounding code + CWE context. Pairs
with #1; same verified/unverified output.

### 5. Isolated exploit sandbox
Strix runs active exploitation in a disposable container. c0mr4de runs active tests
from the host via httpx. A sandboxed runner (reuse the existing Kali-docker) for
anything beyond detection-only would be safer and let it do more aggressive
confirmation without risk to the host.

### 6. CI/CD GitHub Action
Strix scans every PR. c0mr4de now has the pieces (scope, deterministic checks, report
gen) to run as a GitHub Action against a target/repo on push. Useful for Roshan's own
repos and as a portfolio differentiator.

## Tier 3 - nice-to-have

- Structured attack-graph as swarm shared state (PentestGPT task-tree pattern) -
  c0mr4de's swarm passes state via conversation history; an explicit graph improves
  multi-step coherence.
- `dalfox` integration for deep XSS (param mining + DOM-XSS verification) - c0mr4de
  already has execution-confirmed XSS, so this is additive, not urgent.
- MCP-server exposure of c0mr4de's tools (HexStrike pattern) - lets Claude Desktop /
  Cursor drive the deterministic toolset directly.

## Honest notes

- c0mr4de does NOT need to chase "more autonomous" framing - the leaders are
  converging on validation, which it already has. The wins are coverage (source
  audit, more recon) and packaging (PoC, CI), not a bigger agent loop.
- Every FP-reduction result above is for STATIC analysis; c0mr4de's runtime
  deterministic checks are already the gold standard the static tools are trying to
  approximate with an LLM.

## Sources
- https://github.com/usestrix/strix , https://dev.to/andrew-ooo/strix-review-the-open-source-ai-pentester-that-attacks-3d3o
- https://github.com/protectai/vulnhuntr
- https://github.com/skyvanguard/awesome-ai-pentesting , https://www.besthub.dev/articles/a-complete-ai-penetration-testing-landscape-56-open-source-agents-73-papers-and-key-models-9f0fe997cab3
- https://docs.projectdiscovery.io/opensource/
- https://github.com/hahwul/dalfox , https://projectdiscovery.io/blog/simplifying-xss-detection-with-nuclei
- FP-reduction research: QASecClaw (arxiv 2605.01885), ZeroFalse/SAST-Genius (arxiv 2509.15433, 2510.02534), Vulnhalla (cyberark), OpenAnt (knostic.ai)
