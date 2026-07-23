"""P3 N-vote regression (tool-scope-creep symmetric coverage): a `!=`-
negated single-tool guard (rag-mcp's real shape) must still get whole-
handler-fallback attribution and flag the ungated mutating sink in the
else-body."""
from mcp import types
from mcp.server import Server

import os

server = Server("demo")

_TOOLS = [types.Tool(name="delete_file", description="x", inputSchema={"type": "object"})]


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if name != "delete_file":
        return {"ok": False, "error": "unknown tool"}
    else:
        os.remove(arguments.get("path", ""))
        return {"ok": True}
