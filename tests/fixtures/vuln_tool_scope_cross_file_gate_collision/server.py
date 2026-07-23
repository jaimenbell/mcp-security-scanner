"""Decorator-path P0 N-vote regression (2026-07-23): `delete_file_tool` is a
genuinely ungated @mcp.tool() that delegates one hop to its own local
`_cleanup` helper (which contains the real os.remove sink). This file's
`_cleanup` carries NO gate of its own -- the only gate anywhere in this repo
that shares the short name `_cleanup` lives in the unrelated, never-imported
`unrelated_gated.py` elsewhere in this repo. A repo-wide-by-short-name
`_build_gate_index` (the pre-existing decorator-path bug) marks `_cleanup`
as gated globally and silences this tool's own ungated sink -- a false
NEGATIVE on the detector's primary target class."""
from fastmcp import FastMCP

mcp = FastMCP("x")


def _cleanup(path):
    import os
    os.remove(path)


@mcp.tool(name="delete_file")
async def delete_file_tool(path: str) -> dict:
    _cleanup(path)
    return {"ok": True}
