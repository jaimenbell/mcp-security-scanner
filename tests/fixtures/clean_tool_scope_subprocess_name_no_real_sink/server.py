"""Regression fixture for the sink-substring-fix lane (2026-07-23).

`_is_mutating_sink_call` used to do a bare substring test -- `if "subprocess"
in name` -- against the call's own dotted/bare NAME. A helper function whose
NAME merely contains the word "subprocess" (like `_run_subprocess` below)
matched that substring even though the helper's BODY never calls the real
`subprocess` module at all. This is the exact false-positive class the
vllm-ops-mcp fleet sweep reproduced live (`get_gpu_status` -> `_run_subprocess`
-- see `vuln_tool_scope_subprocess_readonly_probe` for the sibling fixture
where the helper's body DOES reach a real sink).

`get_status_tool` has a non-mutating name and one-hop-delegates (same file)
to `_run_subprocess`, whose body contains no dangerous sink whatsoever (just
arithmetic) -- this must stay entirely quiet."""
from __future__ import annotations

from fastmcp import FastMCP

mcp = FastMCP("clean-subprocess-name-no-sink-demo")


def _run_subprocess(a: int, b: int) -> int:
    """Named like a subprocess helper, but never touches the subprocess
    module -- benign arithmetic only."""
    return a + b


@mcp.tool(name="get_status", description="Read-only status check.")
async def get_status_tool() -> dict:
    total = _run_subprocess(1, 2)
    return {"ok": True, "total": total}
