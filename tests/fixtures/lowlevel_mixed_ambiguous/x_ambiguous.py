"""Genuinely ambiguous dispatcher module: TWO ``@server.call_tool()``
handlers in the same file (two ``Server()`` instances sharing a file,
or a copy-paste artifact) -- ``tool_registry.py`` correctly refuses to
guess which one is the real root (``node=None``). The sink behind these
dispatchers must grade UNKNOWN, never CLI_ONLY/UNCALLED, even though
ANOTHER file in this same repo (``y_valid.py``) has a perfectly valid,
unambiguous root.

Opus round-3 final-verify BLOCKED finding (b): the repo-wide has_tools/
have_py_handlers seam in reachability.py/taint.py would otherwise let
y_valid.py's valid root "unlock" confident grading for this file's
un-rooted tool too, once ANY registration anywhere in the repo has a valid
node.
"""
from mcp import types
from mcp.server import Server
import os

server_x1 = Server("demo-x1")
server_x2 = Server("demo-x2")

_TOOL_X = types.Tool(name="ambiguous_tool", description="x", inputSchema={"type": "object"})


def _run_x(cmd):
    os.system("ambiguous-dispatch " + cmd)


@server_x1.list_tools()
async def list_tools_x():
    return [_TOOL_X]


@server_x1.call_tool()
async def call_tool_x1(name, arguments):
    return _run_x(arguments.get("cmd", ""))


@server_x2.call_tool()
async def call_tool_x2(name, arguments):
    return _run_x(arguments.get("cmd", ""))
