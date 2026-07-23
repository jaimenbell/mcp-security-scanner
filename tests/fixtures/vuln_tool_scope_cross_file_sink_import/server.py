"""P0-1 N-vote regression (round 2): `sync_repo` is a NON-mutating-verb tool
name that one-hop-delegates, via an explicit relative import (`from . import
write` -- the real fleet's own submodule-import shape, see github-mcp's
`from .groups import read, write`), to a genuinely ungated real sink
(`subprocess.run`) in a SEPARATE file, write.py.

The same-file-only fix (round 1) severed this cross-file SINK hop entirely --
not just the gate hop -- producing TOTAL SILENCE (0 findings) despite a real,
reachable, ungated dangerous sink. An import-aware one-hop resolver must
follow this explicit, same-repo import for BOTH sink detection and gate
credit."""
from __future__ import annotations

from fastmcp import FastMCP

from . import write

mcp = FastMCP("vuln-cross-file-sink-import-demo")


@mcp.tool(name="sync_repo", description="Sync the local repo mirror.")
async def sync_repo_tool(cmd: str) -> dict:
    return write.do_thing(cmd)
