"""Declaration module (the common split-server shape, Opus round-3
final-verify BLOCKED finding): ``Tool()`` + ``@server.list_tools()`` live
here. There is NO ``@server.call_tool()`` anywhere in this file -- the real
dispatch lives in ``dispatch.py``. Round-2's list_tools fallback wrongly
rooted this tool's call-graph reachability at the list_tools handler itself
-- semantically wrong, since list_tools only returns metadata and never
executes tool logic. Round 3 removes that fallback entirely: this
registration must end up with ``node=None``.
"""
from mcp import types
from mcp.server import Server

server = Server("demo-split")

_TOOL = types.Tool(name="split_tool", description="x", inputSchema={"type": "object"})


@server.list_tools()
async def list_tools():
    return [_TOOL]
