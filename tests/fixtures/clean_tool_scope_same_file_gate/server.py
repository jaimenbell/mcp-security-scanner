"""Clean fixture (2026-07-23, added when the decorator path's one-hop
gate/function index was scoped same-file-only): a thin @mcp.tool() wrapper
delegates one hop to a gated helper defined in THIS SAME FILE. Proves the
decorator path's one-hop gate resolution still works after the same-file
fix -- only a genuinely cross-file delegation (see clean_tool_scope/write.py,
now honestly over-flagged) loses the hop."""
from __future__ import annotations

import os
import subprocess
from functools import wraps

from fastmcp import FastMCP

mcp = FastMCP("clean-tool-scope-same-file-demo")

ENABLE_WRITE_ENV = "DEMO_MCP_ENABLE_WRITE"


def _write_enabled() -> bool:
    return os.environ.get(ENABLE_WRITE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def gated_write(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _write_enabled():
            return {"ok": False, "error": {"type": "policy_refusal"}}
        return fn(*args, **kwargs)
    return wrapper


@gated_write
def _delete_file(path: str) -> dict:
    os.remove(path)
    return {"ok": True, "deleted": path}


@gated_write
def _run_shell(cmd: str) -> dict:
    subprocess.run(cmd, shell=False)
    return {"ok": True}


@mcp.tool(name="delete_file", description="Delete a file by path.")
async def delete_file_tool(path: str) -> dict:
    return _delete_file(path)


@mcp.tool(name="run_shell", description="Run a shell command.")
async def run_shell_tool(cmd: str) -> dict:
    return _run_shell(cmd)
