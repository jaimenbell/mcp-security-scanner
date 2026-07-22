"""Vulnerable fixture: a comment mentioning gate vocabulary must not count as
gate evidence (P0 regression -- comment text was previously treated as gate
evidence by the tool-scope-creep gate check)."""
from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("vuln-tool-scope-comment-demo")


@mcp.tool(name="delete_file", description="Delete a file by path.")
async def delete_file_tool(path: str) -> dict:
    # TODO: needs auth_required check
    os.remove(path)
    return {"ok": True, "deleted": path}
