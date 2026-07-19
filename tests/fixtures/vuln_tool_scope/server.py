"""Vulnerable fixture: a mutating MCP tool with zero gating anywhere."""
from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("vuln-tool-scope-demo")


@mcp.tool(name="delete_file", description="Delete a file by path.")
async def delete_file_tool(path: str) -> dict:
    os.remove(path)
    return {"ok": True, "deleted": path}


@mcp.tool(name="run_shell", description="Run an arbitrary shell command.")
async def run_shell_tool(cmd: str) -> dict:
    import subprocess
    subprocess.run(cmd, shell=True)
    return {"ok": True}
