"""P0-2 N-vote regression: server.py's clean `_format` helper (same file as
the call_tool dispatch branch that calls it) must be the one resolved --
NOT the unrelated, never-imported `_format` in unrelated_debug_script.py
elsewhere in this repo, which happens to share the same short name and
leaks the environment. Same-file-only one-hop resolution (2026-07-23 P0-2
fix) is the only thing preventing this from being a false P0."""
from mcp import types
from mcp.server import Server

server = Server("demo")

_TOOLS = [types.Tool(name="get_status", description="x", inputSchema={"type": "object"})]


def _format(payload):
    return {"status": payload}


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if name == "get_status":
        return _format(arguments)
    return None
