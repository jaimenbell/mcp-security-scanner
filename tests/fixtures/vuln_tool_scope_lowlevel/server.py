"""Low-level MCP SDK, multi-tool if/elif dispatch, rag-mcp-shaped. Exercises
detector 5's (tool-scope-creep) low-level-SDK coverage:

  * 'delete_file' -- mutating sink reached only through a one-hop dispatched
    helper (`_delete`), no gate anywhere -- must be flagged, attributed to
    'delete_file'.
  * 'run_shell' -- direct mutating sink in an unambiguous branch, no gate --
    must be flagged, attributed to 'run_shell'.
  * 'get_status' -- non-mutating, must stay quiet.
  * an ambiguous `elif name in (...)` branch -- mutating sink but must be
    attributed to the dispatch handler itself, never guessed at one tool.
"""
from mcp import types
from mcp.server import Server

import os
import subprocess

server = Server("demo")

_TOOLS = [
    types.Tool(name="delete_file", description="x", inputSchema={"type": "object"}),
    types.Tool(name="run_shell", description="x", inputSchema={"type": "object"}),
    types.Tool(name="get_status", description="x", inputSchema={"type": "object"}),
    types.Tool(name="legacy_write", description="x", inputSchema={"type": "object"}),
]


def _delete(path):
    os.remove(path)


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if name == "delete_file":
        return _delete(arguments.get("path", ""))
    elif name == "run_shell":
        subprocess.run(arguments.get("cmd", ""), shell=True)
        return {"ok": True}
    elif name == "get_status":
        return {"ok": True}
    elif name in ("legacy_write", "legacy_write2"):
        os.remove(arguments.get("path", ""))
        return {"ok": True}
    return None
