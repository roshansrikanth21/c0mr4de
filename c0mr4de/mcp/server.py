"""c0mr4de MCP server (stdio) - exposes the verified toolset to MCP clients.

Every tool call passes through gate.guard() first: passive tools run freely; active
tools are scope-fail-closed and need an operator approval (single-use) or an armed
window. Scope is READ-ONLY over MCP (scope_status) - the AI can see the boundary but
never set or widen it; the operator owns scope via the c0mr4de CLI/web.

Run:  c0mr4de mcp     (or: python -m c0mr4de.mcp.server)
Wire into Claude Desktop / Cursor: see docs/mcp.md.
"""
from __future__ import annotations

import asyncio
import copy
import sys

from c0mr4de import scope
from c0mr4de.mcp import gate
from c0mr4de.tools import build_default_registry


def _log(msg: str) -> None:
    # MCP talks JSON-RPC over stdout, so operator-facing lines MUST go to stderr
    print(f"[c0mr4de-mcp] {msg}", file=sys.stderr, flush=True)


def _active_schema(params: dict) -> dict:
    """Clone a tool's JSON schema and add the optional approval_id arg (active tools)."""
    p = copy.deepcopy(params) if isinstance(params, dict) else {"type": "object", "properties": {}}
    p.setdefault("type", "object")
    p.setdefault("properties", {})
    p["properties"]["approval_id"] = {
        "type": "string",
        "description": "Operator approval id for this active action (from `c0mr4de mcp-approve`). "
                       "Omit on the first call to receive a pending id.",
    }
    return p


def build_server():
    from mcp.server import Server
    import mcp.types as types

    registry = build_default_registry()
    server = Server("c0mr4de")

    @server.list_tools()
    async def list_tools():
        tools = [types.Tool(
            name="scope_status",
            description="Read the operator's current rules-of-engagement (scope + focus) and the "
                        "approval/armed state. Read-only: the AI cannot change scope.",
            inputSchema={"type": "object", "properties": {}},
        )]
        for t in registry._tools.values():
            active = gate.is_active(t.name)
            desc = t.description + (
                "  [ACTIVE: sends traffic/changes state - needs operator approval and in-scope target]"
                if active else "  [passive]")
            tools.append(types.Tool(
                name=t.name, description=desc,
                inputSchema=_active_schema(t.parameters) if active else t.parameters))
        return tools

    @server.call_tool()
    async def call_tool(name, arguments):
        arguments = dict(arguments or {})
        if name == "scope_status":
            brief = scope.brief() or "(no scope set - active tools are blocked until the operator sets scope)"
            armed = "ARMED (in-scope active actions auto-run)" if gate.is_armed() else "not armed (per-action approval)"
            pend = len(gate.list_pending())
            return [types.TextContent(type="text", text=(
                f"SCOPE / RULES OF ENGAGEMENT (operator-set, read-only here):\n{brief}\n\n"
                f"Approval mode: {armed}\nPending approvals: {pend}\n"
                f"Scope is controlled by the operator via the c0mr4de CLI/web - the AI cannot change it."))]

        tool = registry.get(name)
        if tool is None:
            return [types.TextContent(type="text", text=f"unknown tool: {name}")]

        approval_id = arguments.pop("approval_id", None)
        ok, reason = gate.guard(name, arguments, approval_id)
        if not ok:
            _log(f"GATED {name}: {reason}")
            return [types.TextContent(type="text", text=reason)]

        try:
            result = tool.run(**arguments)
        except Exception as exc:  # noqa: BLE001
            result = f"TOOL ERROR ({name}): {exc}"
        return [types.TextContent(type="text", text=str(result))]

    return server


async def _amain():
    from mcp.server.stdio import stdio_server
    server = build_server()
    n = len(build_default_registry()._tools)
    _log(f"c0mr4de MCP server up - {n} tools exposed, active ones gated. Scope: "
         f"{scope.brief() or 'NOT SET (active tools blocked until set)'}")
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def run() -> None:
    """CLI entry point (c0mr4de mcp)."""
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        _log("shut down.")


if __name__ == "__main__":
    run()
