"""Dispatcher A -- an unrelated low-level MCP server sharing this repo with
dispatcher B (``server_b.py``). Its own tool calls nothing dangerous; this
file exists purely so a naive repo-wide first-found-dispatcher root pick
(the pre-fix bug, N-vote P0) has a WRONG root available to mis-attribute
dispatcher B's tools to, if the fix regresses.
"""
from mcp import types
from mcp.server import Server

server_a = Server("demo-a")

_TOOL_A = types.Tool(name="tool_a", description="a", inputSchema={"type": "object"})


@server_a.list_tools()
async def list_tools_a():
    return [_TOOL_A]


@server_a.call_tool()
async def call_tool_a(name, arguments):
    return {"ok": True}
