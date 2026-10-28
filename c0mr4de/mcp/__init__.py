"""c0mr4de MCP server - expose the VERIFIED toolset to MCP clients (Claude Desktop,
Cursor, ...) behind two safety gates borrowed from ARES, applied to c0mr4de's domain:

1. Confirmation gate: any ACTIVE tool (sends payloads/traffic to a target or changes
   state) needs explicit operator approval before it runs - a single-use approval, or
   an operator-"armed" time window. Passive tools (knowledge, OSINT, CVE lookups,
   decode, read) run freely.
2. Scope egress: active tools are fail-closed against the operator's scope - an
   out-of-scope host is always blocked, and (when a scope is set) an unlisted host is
   blocked too. The AI can read scope but NEVER set or widen it; that is operator-only.
"""
