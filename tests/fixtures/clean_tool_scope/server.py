"""Clean fixture: thin MCP tool wrappers that delegate to write-group
helpers -- the actual gate lives one hop away, in write.py."""
from __future__ import annotations

from fastmcp import FastMCP

from . import write

mcp = FastMCP("clean-tool-scope-demo")


@mcp.tool(name="delete_file", description="Delete a file by path. Requires DEMO_MCP_ENABLE_WRITE=1.")
async def delete_file_tool(path: str) -> dict:
    return write.delete_file(path)


@mcp.tool(name="run_shell", description="Run a shell command. Requires DEMO_MCP_ENABLE_WRITE=1.")
async def run_shell_tool(cmd: str) -> dict:
    return write.run_shell(cmd)
