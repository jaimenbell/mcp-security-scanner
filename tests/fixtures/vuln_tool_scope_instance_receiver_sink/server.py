"""Instance-receiver one-hop, RECALL direction (regression guard).

Same shape as `clean_tool_scope_instance_receiver_hop`, except the resolved
instance method is the one carrying the real, ungated `os.remove` sink. The
instance-receiver fix must resolve the hop and still flag this -- tightening
the receiver must not buy its precision by going blind.

Tool name is deliberately non-mutating, so the flag can only come from the
one-hop sink resolution.
"""
from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("instance-receiver-sink-demo")


class BackupRegistry:
    def purge_entry(self, path: str) -> None:
        os.remove(path)


backup_registry = BackupRegistry()


@mcp.tool(name="sync_state", description="Reconcile cached backup state.")
async def sync_state(path: str) -> dict:
    backup_registry.purge_entry(path)
    return {"ok": True}
