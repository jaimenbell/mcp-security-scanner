"""Disclosed-residual fixture (round 2): `sync_data` is a non-mutating-verb
tool name that delegates one hop to `do_thing`, imported from a THIRD-PARTY
package (`external_helpers`) that is not part of this repo at all -- no file
to resolve to, no way to see its body. This must stay quiet: the honest
residual explicitly disclosed in the module docstring and README is that an
unresolvable hop (no explicit same-repo import match, not same-file) leaves
a non-mutating-named tool's sink un-followed -- a real, stated miss, not a
guess in either direction."""
from __future__ import annotations

from external_helpers import do_thing
from fastmcp import FastMCP

mcp = FastMCP("vuln-unresolvable-external-hop-demo")


@mcp.tool(name="sync_data", description="Sync data via an external helper.")
async def sync_data_tool(cmd: str) -> dict:
    return do_thing(cmd)
