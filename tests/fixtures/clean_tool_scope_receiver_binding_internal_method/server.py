"""Receiver-classification repro (FALSE POSITIVE direction), modelled on the
real shape found live: `db_connection_map.remove(...)` in three AWS Labs
database MCP servers, where `db_connection_map` is a module-level instance of
the repo's own `DBConnectionMap` and `.remove()` just drops a dict entry.

`_is_mutating_sink_call`'s attribute branch matched any short name in
`_MUTATING_SINK_SHORT` REGARDLESS OF RECEIVER, so an in-memory registry's own
`remove` method was read as a filesystem delete. The tool's name is
non-mutating and nothing else in this repo touches a sink, so any finding here
is the receiver-agnostic short-name match talking.
"""
from __future__ import annotations

from fastmcp import FastMCP

mcp = FastMCP("receiver-binding-demo")


class ConnectionRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, str] = {}

    def remove(self, key: str) -> None:
        self._entries.pop(key, None)


db_connection_map = ConnectionRegistry()


@mcp.tool(name="lookup_status", description="Report a cached connection's status.")
async def lookup_status(key: str) -> dict:
    db_connection_map.remove(key)
    return {"ok": True, "key": key}
