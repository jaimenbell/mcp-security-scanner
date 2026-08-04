"""Receiver classification across an explicit same-repo import.

The class lives in `registry.py` and is bound here by a real, statically
resolvable relative import, then instantiated at module level. Proving the
receiver is a repo-internal instance therefore has to go through
`_build_import_map` -- exactly the same machinery the one-hop resolver uses to
FOLLOW this call, which is what makes demoting it safe rather than blind.

Tool name is non-mutating; nothing in either file touches a real sink.
"""
from __future__ import annotations

from fastmcp import FastMCP

from .registry import ConnectionRegistry

mcp = FastMCP("receiver-binding-cross-file-demo")

db = ConnectionRegistry()


@mcp.tool(name="lookup_status", description="Report a cached connection's status.")
async def lookup_status(key: str) -> dict:
    db.remove(key)
    return {"ok": True}
