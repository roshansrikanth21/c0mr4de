# c0mr4de MCP server

Expose c0mr4de's **verified** toolset to MCP clients (Claude Desktop, Cursor,
Windsurf, VS Code Cline) so you can drive recon, CVE intel, and - with approval -
active testing from the client you already use. This is the "wide toolbox over MCP"
idea (cf. hexstrike) **with the validation and safety layers those tools lack**.

## Two safety gates (always on)

1. **Confirmation gate.** Tools are classified *passive* or *active*.
   - *Passive* (knowledge, OSINT, CVE lookups, decode, read, report) run freely.
   - *Active* (anything that sends traffic/payloads to a target or changes state -
     crawl, probe, `test_injection`, `nuclei_scan`, `verify_finding`, `http_request`, …)
     require **operator approval**: either a single-use approval per action, or an
     operator-"armed" time window. Unknown/new tools default to *active* (fail-safe).
2. **Scope egress (fail-closed).** Active tools are checked against the operator's
   scope: an out-of-scope host is always refused, and when a scope is set, an
   unlisted host is refused too. **Scope is read-only over MCP** - the AI can see it
   (`scope_status`) but can never set or widen it. You own scope.

## Install

```
py -m pip install -e ".[mcp]"      # adds the `mcp` SDK
```

## Run / wire into a client

The server speaks MCP over stdio. Set scope at launch (active tools stay blocked
until a scope exists). Example Claude Desktop config
(`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "c0mr4de": {
      "command": "py",
      "args": ["-m", "c0mr4de.cli", "mcp", "--in-scope", "target.com", "--focus", "IDOR, SSRF"],
      "cwd": "D:\\c0mr4de"
    }
  }
}
```

Add `--auth-host/--auth-cookie/--auth-header` for authenticated testing, and
`--out-scope` to hard-block hosts. To change scope, edit the args and restart the
client (scope is set per launch).

## Approving active actions

When the AI calls an active tool it gets back a **pending id** and stops. You
approve out-of-band from a terminal in the repo:

```
c0mr4de mcp-approvals                 # list what's waiting
c0mr4de mcp-approve <id>              # approve one action (single use, 5 min)
c0mr4de mcp-arm 30                    # OR: allow in-scope active actions for 30 min
c0mr4de mcp-disarm                    # back to per-action approval
```

Out-of-scope actions are refused even while armed. Every gate decision is logged to
`workspace/mcp-approvals/_audit.log`.

## Notes

- Findings from these tools are still **leads to verify** unless a verifier
  CONFIRMED them - the MCP layer changes *who drives* the tools, not c0mr4de's
  verify-first discipline.
- The server exposes ~63 tools + `scope_status`. Passive tools need no setup;
  active tools need scope + approval.
