"""Disclosed-residual regression fixture (round-2 N-vote fix pass, P2 item,
2026-07-23) -- pins the EXACT shape that produced vllm-ops-mcp's real,
live, verified outcome: a tool delegates through a cross-file, one-hop,
import-resolved call (`probes.get_status()`) to a function whose OWN body
then calls a SECOND helper (`_run_subprocess`, a bare same-file call) which
finally reaches the real `subprocess.run(...)` sink.

This detector's one-hop resolver (round 2 of the earlier cross-file-sink-
import fix, explicitly documented as "BOUNDED -- not a real call graph or
transitive dataflow proof") only inspects the FIRST resolved hop's own body
for a sink; it does not recursively resolve a second hop. So `get_status`'s
one-hop-resolved target (`probes.get_status`) is inspected directly -- its
body's only call is the bare `_run_subprocess(...)`, which (correctly,
after the sink-substring-fix lane) resolves to a repo-internal function
name and is NOT itself classified as a sink; the real `subprocess.run`
one hop further in is out of this resolver's bound.

Verified: this MUST produce ZERO findings -- not because of any suppression
logic, but as the honest, disclosed consequence of an already-existing,
already-disclosed one-hop-only limitation. See
`tool_scope_creep.py`'s module docstring ("Round 3") for the live
vllm-ops-mcp verification this fixture pins as a permanent regression
guard (previously undocumented by any fixture -- refuter B's P2 finding)."""
from __future__ import annotations

from fastmcp import FastMCP

from . import probes

mcp = FastMCP("clean-two-hop-probe-miss-demo")


@mcp.tool(name="get_status", description="Read-only status probe (two hops deep).")
async def get_status_tool() -> dict:
    return probes.get_status()
