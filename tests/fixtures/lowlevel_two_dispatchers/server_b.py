"""Dispatcher B -- its sink must grade REACHABLE through ITS OWN dispatcher
(``call_tool_b``), never through ``server_a.py``'s unrelated ``call_tool_a``.
The pre-fix bug (N-vote P0) rooted every ``Tool()`` construction repo-wide
to whichever ``@server.call_tool()`` handler a nondeterministic file walk
found first -- in a repo shaped like this one, that could silently root
this tool to ``call_tool_a``, which never calls ``_run_b``, downgrading a
genuinely tool-reachable sink to CLI_ONLY/UNCALLED instead of REACHABLE.
"""
from mcp import types
from mcp.server import Server
import os

server_b = Server("demo-b")

_TOOL_B = types.Tool(name="tool_b", description="b", inputSchema={"type": "object"})


def _run_b(cmd):
    # REACHABLE only through call_tool_b -- server_a.py's dispatcher never
    # calls this.
    os.system("dispatcher-b " + cmd)


@server_b.list_tools()
async def list_tools_b():
    return [_TOOL_B]


@server_b.call_tool()
async def call_tool_b(name, arguments):
    return _run_b(arguments.get("cmd", ""))
