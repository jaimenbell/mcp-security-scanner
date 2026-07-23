"""CLI-only reachability fixture -- mirrors the rag-mcp dogfood shape
(2026-07-22): a registered MCP tool exists in the repo (so ``has_tools`` /
``have_py_handlers`` are True), but the flagged sink sits behind a
completely separate call path that only an operator-supplied CLI/argv
entrypoint reaches -- never the tool handler.

This file supplies the one registered tool (the root the forward walk seeds
from). ``cli.py`` / ``lock.py`` supply the CLI-only path.
"""
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def search(query):
    # The only thing the registered tool actually reaches -- nothing in
    # cli.py/lock.py is ever called from here.
    return {"query": query}
