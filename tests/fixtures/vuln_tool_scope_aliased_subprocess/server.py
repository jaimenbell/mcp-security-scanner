"""Round-2 N-vote fix regression fixture (refuter A, item 4, 2026-07-23):
aliased-import severity calibration. `import subprocess as sp` then calling
`sp.run(...)` must canonicalize through the module alias to the real
`subprocess.run` spelling for BOTH sink classification and the shell=True
severity axis -- `probe_status` (no `shell=True`, fixed argv list) must
calibrate to P2/MEDIUM exactly like the un-aliased spelling would;
`check_task` (`shell=True`) must stay P1/HIGH. Before this fix, an aliased
call would fall through `_is_high_risk_sink_call`'s exact-set check (which
only matched the literal `subprocess.run` spelling) straight to the
unconditional-high-risk short-name fallback -- silently losing the P2
calibration for every aliased-import repo."""
from __future__ import annotations

import subprocess as sp

from fastmcp import FastMCP

mcp = FastMCP("vuln-aliased-subprocess-demo")


@mcp.tool(name="probe_status", description="Read-only status probe.")
async def probe_status_tool(args: list[str]) -> dict:
    proc = sp.run(args, capture_output=True, text=True, check=False)
    return {"ok": proc.returncode == 0, "out": proc.stdout}


@mcp.tool(name="check_task", description="Check a background task.")
async def check_task_tool(cmd: str) -> dict:
    sp.run(cmd, shell=True)
    return {"ok": True}
