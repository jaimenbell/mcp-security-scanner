"""P0-1 N-vote regression: a gate hint ("is_authorized") appearing in a
SIBLING branch (read_file) must not silence delete_file's own, genuinely
ungated os.remove() sink in the same handler. The previous
`_node_has_gate(f, handler)` whole-handler-text scan ORed one boolean into
every branch -- this fixture is the refuter's live repro of that false
negative on the detector's primary target class."""
from mcp import types
from mcp.server import Server

import os

server = Server("demo")

_TOOLS = [
    types.Tool(name="read_file", description="x", inputSchema={"type": "object"}),
    types.Tool(name="delete_file", description="x", inputSchema={"type": "object"}),
]


def is_authorized(path):
    return True


@server.list_tools()
async def list_tools():
    return _TOOLS


@server.call_tool()
async def call_tool(name, arguments):
    if name == "read_file":
        if not is_authorized(arguments.get("path", "")):
            raise PermissionError("nope")
        with open(arguments.get("path", "")) as fh:
            return fh.read()
    elif name == "delete_file":
        os.remove(arguments.get("path", ""))
        return {"ok": True}
    return None
