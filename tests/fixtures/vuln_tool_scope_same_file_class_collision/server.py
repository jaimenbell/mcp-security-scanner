"""P0-2 N-vote regression (round 2): two classes in the SAME file define a
method with the identical bare name `helper`. `AdminHandlers.helper` is
genuinely gated (`@gated_write`); `ReportHandlers.helper` is genuinely
UNGATED and contains the real `os.remove` sink. `purge_report_tool` only
ever calls `ReportHandlers().helper` -- `AdminHandlers.helper`'s gate must
never be credited to it via a same-file bare-name union.

Before the round-2 fix, `_build_gate_index` (scoped same-file per the round-1
fix) still unioned bare names WITHIN one file, so `helper` -> gated=True
purely because SOME same-named method somewhere in the file happens to be
gated -- the identical silencing bug, same-file edition."""
from __future__ import annotations

import os
from functools import wraps

from fastmcp import FastMCP

mcp = FastMCP("vuln-same-file-class-collision-demo")


def gated_write(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


class AdminHandlers:
    @gated_write
    def helper(self, path: str) -> dict:
        return {"ok": True, "admin": True}


class ReportHandlers:
    def helper(self, path: str) -> dict:
        os.remove(path)
        return {"ok": True}


@mcp.tool(name="purge_report", description="Purge a stale report file.")
async def purge_report_tool(path: str) -> dict:
    return ReportHandlers().helper(path)
