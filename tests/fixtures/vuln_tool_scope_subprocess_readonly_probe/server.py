"""Regression fixture for the sink-substring-fix lane (2026-07-23), modeled
directly on the live vllm-ops-mcp shape that motivated it: `get_gpu_status`
(non-mutating name) one-hop-delegates, same file, to `_run_subprocess`, whose
body genuinely calls `subprocess.run(...)` -- but as a fixed argv LIST, no
`shell=True`, exactly like `nvidia-smi --query-gpu=...`.

Semantics decision (see tool_scope_creep.py's module docstring, "round 3"
section, for the full rationale): this IS a real, structurally-true sink hit
-- it is NOT suppressed, matching the round-2-pinned
`vuln_tool_scope_cross_file_sink_import` precedent that a non-mutating-named
tool's one-hop-resolved real subprocess sink must still surface. But
`subprocess.run`/`Popen`/`call`/`check_output`/`check_call` invoked WITHOUT
`shell=True` -- a fixed argv list, no shell metacharacter interpretation --
is a materially lower-risk shape than the `shell=True` case
(`vuln_tool_scope`'s `run_shell`, `vuln_tool_scope_cross_file_sink_import`'s
`sync_repo`). Severity/confidence are calibrated down to P2/MEDIUM for this
shape; the finding is never fully suppressed."""
from __future__ import annotations

import subprocess

from fastmcp import FastMCP

mcp = FastMCP("vuln-subprocess-readonly-probe-demo")


def _run_subprocess(args: list[str], timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


@mcp.tool(name="get_gpu_status", description="Read-only GPU status probe.")
async def get_gpu_status_tool() -> dict:
    rc, stdout, _stderr = _run_subprocess(["nvidia-smi", "--query-gpu=index,name"], 10.0)
    return {"ok": rc == 0, "raw": stdout}
