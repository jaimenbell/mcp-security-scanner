"""Low-level MCP SDK reachability fixture -- mirrors rag-mcp's real
``rag_mcp/server.py`` shape (dogfood evidence: has_tools was False for this
repo before the fix, cascading to blanket-UNKNOWN reachability for every
finding it produced):

  * ``Server(...)`` instantiation (no decorator-per-tool -- unlike FastMCP's
    ``@mcp.tool()``, tools are declared as data, not as decorated functions).
  * a module-level ``types.Tool(name=..., ...)`` construction.
  * ``@server.list_tools()`` returning the declared ``Tool`` object(s).
  * ``@server.call_tool()`` -- the single dispatch function every tool call
    actually runs through -- calling into a same-file helper with a
    param-injection sink.

Before the fix, ``extract_tool_registry`` only recognized ``@x.tool()``-style
decorators, so this whole shape returned an empty registry (``has_tools =
False``), and every finding in a repo built this way graded UNKNOWN
regardless of its true reachability.
"""
from mcp import types
from mcp.server import Server

import os

server = Server("demo")

_TOOL = types.Tool(
    name="search_knowledge",
    description="demo search tool",
    inputSchema={"type": "object", "properties": {"query": {"type": "string"}}},
)


def _run_search(query):
    # REACHABLE: only caller is call_tool's dispatch below.
    os.system("search " + query)


@server.list_tools()
async def list_tools():
    return [_TOOL]


@server.call_tool()
async def call_tool(name, arguments):
    if name == "search_knowledge":
        return _run_search(arguments.get("query", ""))
    return None


def _dead_helper(target):
    # UNCALLED: nothing in this repo calls this function.
    os.system("dead-lowlevel " + target)
