"""THE UNKNOWN-RECEIVER DEFAULT, pinned.

`client` is provably an instance -- but of `httpx.Client`, a third-party class
this scan cannot open. The demotion requires PROOF that the receiver is a
repo-internal object whose class defines the called method; "provably an
instance of something we can't see" is not that proof, and a third-party
handle is precisely where a real network/filesystem sink lives.

So the unknown case keeps flagging (over-flag-safe), and this fixture is the
regression guard for that choice. Note the deliberate asymmetry with slice 1:
for the one-hop RESOLVER, an unresolvable instance receiver stops at an honest
miss, because following a same-file namesake would be provably wrong. For sink
CLASSIFICATION, the same unresolvable receiver keeps its flag, because
over-flagging is this detector's stated safe direction.
"""
from __future__ import annotations

import httpx

from fastmcp import FastMCP

mcp = FastMCP("receiver-binding-unknown-demo")

client = httpx.Client()


@mcp.tool(name="lookup_status", description="Report an upstream service's status.")
async def lookup_status(url: str, payload: dict) -> dict:
    client.post(url, json=payload)
    return {"ok": True}
