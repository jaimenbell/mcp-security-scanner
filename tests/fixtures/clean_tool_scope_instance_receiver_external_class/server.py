"""Instance-receiver one-hop, THE HAZARD (bea0e90's class, this module's
edition).

`client` is an instance of a class from a third-party package that is not in
this repo at all, so the hop is genuinely unresolvable. The one thing the
resolver must NOT do is shrug and fall back to step 3's same-file bare-name
guess -- which would match the unrelated module-level `purge_entry` and its
`os.remove` sink, flagging a call it never proved anything about.

That is exactly the shape `bea0e90` fixed in `reachability.py`: a generous
name edge, fired only because the exact resolution missed, grading something
by a namesake rather than by itself. An unresolvable receiver is a disclosed
miss (the precedent is
`test_unresolvable_external_hop_residual_is_disclosed_miss`), never a guess.
"""
from __future__ import annotations

import os

import redis
from fastmcp import FastMCP

mcp = FastMCP("instance-receiver-external-demo")

client = redis.Redis(host="localhost")


def purge_entry(path: str) -> None:
    """Unrelated module-level helper that happens to share the bare name."""
    os.remove(path)


@mcp.tool(name="lookup_status", description="Report a cached key's status.")
async def lookup_status(key: str) -> dict:
    client.purge_entry(key)
    return {"ok": True}
