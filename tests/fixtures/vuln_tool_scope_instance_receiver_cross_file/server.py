"""Instance-receiver one-hop, CROSS-FILE.

`ConnectionRegistry` is bound by an explicit same-repo import, then
instantiated into `db`. Before the instance-receiver fix, `db.purge_entry(...)`
resolved to nothing at all: step 1 keys on the call's own head (`db`, which is
not in the import map), step 2 read `db` as a class name, and step 3 found no
same-file `purge_entry`. An honest miss, but a miss -- the genuinely ungated
cross-file sink went unflagged.

Tool name is non-mutating, so the flag can only come from the resolved hop.
"""
from __future__ import annotations

from fastmcp import FastMCP

from .registry import ConnectionRegistry

mcp = FastMCP("instance-receiver-cross-file-demo")

db = ConnectionRegistry()


@mcp.tool(name="sync_state", description="Reconcile cached connection state.")
async def sync_state(path: str) -> dict:
    db.purge_entry(path)
    return {"ok": True}
