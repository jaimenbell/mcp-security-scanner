"""Regression fixture: a sink called from BOTH a registered MCP tool AND a
CLI entrypoint must stay REACHABLE -- the new CLI_ONLY/UNCALLED branch must
never override a real tool-reachable path."""
from fastmcp import FastMCP

from shared import shared_sink

mcp = FastMCP("demo")


@mcp.tool()
def run(target):
    # REACHABLE: called directly from a registered tool handler.
    shared_sink(target)
