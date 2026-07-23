"""Cross-file one-hop fixture: thin MCP tool wrappers that delegate to
write-group helpers -- the actual gate lives one hop away, in write.py, a
SEPARATE file. Historical note: this fixture's directory is still named
`clean_tool_scope` for continuity, but as of the 2026-07-23 same-file-only
fix (closing the README's named decorator-path follow-up) it is NO LONGER
expected to scan clean -- see test_cross_file_gate_now_over_flags_by_design
in test_tool_scope_creep.py. The cross-file hop to write.py is honestly not
followed anymore (over-flag direction, accepted); see
clean_tool_scope_same_file_gate/ for the still-covered same-file case."""
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
