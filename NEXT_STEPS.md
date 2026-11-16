# c0mr4de - status and next steps

_Last updated 2026-11-16. All work below is committed and pushed to `main`._

## Done
- **Intel Map**: bug-class browser over the open pentester.land dataset (6,421 writeups,
  671 classes) - ingest (`c0mr4de intel-map --ingest`), agent tools (`bug_class_intel`,
  `top_bug_classes`), and a web UI panel (tile grid + drill-down). Verified live.
- **Plugin Mode**: connect Claude Desktop, Claude Code, or OpenCode to c0mr4de's existing
  MCP server (`c0mr4de mcp`) so they can drive its tools/RAG/Intel Map directly. UI panel
  generates the correct per-client config (schemas verified live against each client's
  docs) and can merge it into the real config file (backs up first, touches nothing else).
- Groq (`gpt-oss-120b`) wired as the hivemind's heavy-chain primary via `heavy_model: auto`;
  RAG store at ~21k chunks (HackTricks, OWASP WSTG, PayloadsAllTheThings, writeups);
  CVE-intel -> Exploit-DB PoC lookup chain working end to end.
- 167 tests passing (`py -m pytest -q`).

## Not done yet (next steps)
1. **Click "write for me"** in the Plugin Mode panel for whichever of Claude Desktop /
   Claude Code / OpenCode you actually want connected, then restart that client. Nobody
   has clicked it yet - the configs are generated and tested, not applied.
2. **Delete the leftover parked Artifact data**: `workspace/intel-map/hexmap.json` and
   `BUILD_SPEC.md` are from an earlier standalone-Artifact plan that was superseded by
   the in-app Intel Map above. Safe to delete, currently harmless (gitignored).
3. **Historical commit trailer**: several older commits (9ecf16a, d0662f8, 0d41f31,
   2571fc4, ...) still carry a `Co-Authored-By: Claude` trailer. Removing it needs
   `git filter-repo` + a force-push, which rewrites published history - do this only if
   you explicitly want it, since it's destructive to `main`'s history for everyone.
4. **Optional**: connect more providers (Cerebras, Gemini, DeepInfra, OpenRouter) in the
   "keys" panel - they auto-join the heavy-chain rotation once a key is saved.
