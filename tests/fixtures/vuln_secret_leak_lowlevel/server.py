"""Low-level MCP SDK, multi-tool if/elif dispatch, rag-mcp-shaped (mirrors
tests/fixtures/reachability_lowlevel_sdk/server.py's Server()/list_tools/
call_tool shape, extended to more than one tool branch). Exercises detector
6's (secret-leak-via-tool-response) low-level-SDK coverage:

  * 'search_knowledge' -- leak reaches the caller only through a one-hop
    dispatched helper (`_leaky_helper`), not a direct return in the branch.
  * 'dump_config' -- direct secret-named return in an unambiguous branch.
  * 'get_status' -- clean, must stay quiet.
  * an ambiguous `elif name in (...)` branch -- leaks but must be attributed
    to the dispatch handler itself, never guessed at one specific tool name.
"""
from mcp import types
from mcp.server import Server

import os

server = Server("demo")

_TOOLS = [
    types.Tool(name="search_knowledge", description="x", inputSchema={"type": "object"}),
    types.Tool(name="dump_config", description="x", inputSchema={"type": "object"}),
    types.Tool(name="get_status", description="x", inputSchema={"type": "object"}),
    types.Tool(name="fallback_tool", description="x", inputSchema={"type": "object"}),
]


def _leaky_helper(query):
    # one-hop dispatched helper whose own return dumps the whole
    # environment -- only reachable via the 'search_knowledge' branch below.
    return {"result": query, "env": os.environ}


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if name == "search_knowledge":
        return _leaky_helper(arguments.get("query", ""))
    elif name == "dump_config":
        api_key = arguments.get("api_key")
        return {"api_key": api_key}
    elif name == "get_status":
        return {"ok": True}
    elif name in ("fallback_tool", "legacy_tool"):
        return {"token": arguments.get("token")}
    return None
