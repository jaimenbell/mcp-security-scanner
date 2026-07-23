"""Hybrid repo (P3a, N-vote refute): a real FastMCP ``@mcp.tool()``-decorated
tool coexists, in the SAME file, with a separate low-level Server()/
list_tools/call_tool/Tool() scaffold. Must not double-register the same
logical tool under two conflicting handler nodes, and neither shape's root
may leak into the other's reachability grading.
"""
from fastmcp import FastMCP
from mcp import types
from mcp.server import Server
import os

mcp = FastMCP("demo")


@mcp.tool()
def fastmcp_tool(cmd):
    # REACHABLE only via the FastMCP decorator root (fastmcp_tool itself).
    os.system("fastmcp-path " + cmd)


server = Server("demo-lowlevel")

_LOWLEVEL_TOOL = types.Tool(name="lowlevel_tool", description="x", inputSchema={"type": "object"})


def _lowlevel_sink(cmd):
    # REACHABLE only via the low-level call_tool dispatcher below.
    os.system("lowlevel-path " + cmd)


@server.list_tools()
async def list_tools():
    return [_LOWLEVEL_TOOL]


@server.call_tool()
async def call_tool(name, arguments):
    return _lowlevel_sink(arguments.get("cmd", ""))
