"""Low-level MCP SDK, multi-tool if/elif dispatch, no leak-shaped returns
anywhere (direct or one-hop) -- must stay quiet for detector 6
(secret-leak-via-tool-response)."""
from mcp import types
from mcp.server import Server

server = Server("demo")

_TOOLS = [
    types.Tool(name="search_knowledge", description="x", inputSchema={"type": "object"}),
    types.Tool(name="get_status", description="x", inputSchema={"type": "object"}),
]


def _safe_helper(query):
    return {"result": query, "count": len(query)}


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if name == "search_knowledge":
        return _safe_helper(arguments.get("query", ""))
    elif name == "get_status":
        return {"ok": True}
    return None
