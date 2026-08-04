"""Instance-receiver one-hop repro (FALSE POSITIVE direction).

`db_connection_map` is an INSTANCE of `ConnectionRegistry`, not a class name
and not a module. `_resolve_call_targets` step 2 only ever read a bare `Name`
receiver as a CLASS name (`ClassName.method(...)`), so `("db_connection_map",
"purge_entry")` missed the class-method index and the call fell through to
step 3's same-file bare-name guess -- which happily matched the UNRELATED
module-level `purge_entry` helper and its real `os.remove` sink.

The tool's own name is non-mutating, so the only thing that can flag it is
the sink hop. The real target, `ConnectionRegistry.purge_entry`, touches a
dict and nothing else. Any finding here is the bare-name guess talking.
"""
from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("instance-receiver-hop-demo")


class ConnectionRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, str] = {}

    def purge_entry(self, key: str) -> None:
        self._entries.pop(key, None)


db_connection_map = ConnectionRegistry()


def purge_entry(path: str) -> None:
    """Unrelated module-level helper that happens to share the bare name."""
    os.remove(path)


@mcp.tool(name="lookup_status", description="Report a cached connection's status.")
async def lookup_status(key: str) -> dict:
    db_connection_map.purge_entry(key)
    return {"ok": True, "key": key}
