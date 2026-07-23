"""Low-level MCP SDK, multi-tool if/elif dispatch -- a shared permission
check runs before the dispatch if/elif chain (leftover-segment gate), so
every mutating branch is gated. Must stay quiet for detector 5
(tool-scope-creep)."""
from mcp import types
from mcp.server import Server

import os

server = Server("demo")

_TOOLS = [
    types.Tool(name="delete_file", description="x", inputSchema={"type": "object"}),
    types.Tool(name="get_status", description="x", inputSchema={"type": "object"}),
]


def check_permission(name):
    return os.environ.get("ALLOW_MUTATING_TOOLS") == "1"


def _delete(path):
    os.remove(path)


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if not check_permission(name):
        raise PermissionError("write_group not enabled")
    if name == "delete_file":
        return _delete(arguments.get("path", ""))
    elif name == "get_status":
        return {"ok": True}
    return None
