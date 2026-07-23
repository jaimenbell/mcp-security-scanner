"""Cross-file one-hop fixture: thin MCP tool wrappers that delegate via an
explicit `from . import write` to write-group helpers -- the actual gate
lives one hop away, in write.py, a SEPARATE file. 2026-07-23 history: an
interim same-file-only fix briefly over-flagged this fixture (closing a
repo-wide gate-index collision an N-vote refuter proved live), then a
same-day round-2 fix added a bounded, one-hop, IMPORT-AWARE resolver that
follows this exact explicit-import shape again -- see
test_cross_file_gate_via_explicit_import_stays_quiet in
test_tool_scope_creep.py for the full history. This fixture is expected to
scan clean."""
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
