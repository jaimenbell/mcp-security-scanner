"""A perfectly valid, unambiguous low-level dispatcher elsewhere in the SAME
repo as ``x_ambiguous.py`` -- exists to trigger the has_tools/
have_py_handlers repo-wide seam (round-3 finding (b)) AND to prove the fix
doesn't overcorrect: this file's own sink, genuinely reachable via its own
valid root, must still grade REACHABLE even though x_ambiguous.py's tool in
this same repo has no root.
"""
from mcp import types
from mcp.server import Server
import os

server_y = Server("demo-y")

_TOOL_Y = types.Tool(name="valid_tool", description="y", inputSchema={"type": "object"})


def _run_y(cmd):
    # REACHABLE via call_tool_y -- must stay REACHABLE. unrooted_lowlevel
    # (true in this repo because of x_ambiguous.py) must only affect
    # findings that are NOT reachable from any valid root, never blanket
    # every finding in the repo to UNKNOWN.
    os.system("valid-dispatch " + cmd)


@server_y.list_tools()
async def list_tools_y():
    return [_TOOL_Y]


@server_y.call_tool()
async def call_tool_y(name, arguments):
    return _run_y(arguments.get("cmd", ""))
