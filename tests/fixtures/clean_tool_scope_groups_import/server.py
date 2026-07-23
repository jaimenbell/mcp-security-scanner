"""Clean fixture (round 2): the actual dominant real fleet shape -- a thin
@mcp.tool() wrapper in server.py delegating to a gated helper in a SEPARATE
`groups/*.py` submodule, imported via `from .groups import write` (the
exact real shape of github-mcp's `from .groups import read, write` /
desktop-mcp's `from .groups import input_tools, observe, record, window`).
The import-aware one-hop resolver must follow this explicit, same-repo
import for gate credit -- this must stay quiet."""
from __future__ import annotations

from fastmcp import FastMCP

from .groups import write

mcp = FastMCP("clean-groups-import-demo")


@mcp.tool(name="delete_file", description="Delete a file by path. Requires DEMO_MCP_ENABLE_WRITE=1.")
async def delete_file_tool(path: str) -> dict:
    return write.delete_file(path)


@mcp.tool(name="run_shell", description="Run a shell command. Requires DEMO_MCP_ENABLE_WRITE=1.")
async def run_shell_tool(cmd: str) -> dict:
    return write.run_shell(cmd)
