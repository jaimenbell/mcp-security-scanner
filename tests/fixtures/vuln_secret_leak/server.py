"""Vulnerable fixture: tool responses that leak secrets back to the caller."""
from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("vuln-secret-leak-demo")

API_TOKEN = os.environ.get("API_TOKEN", "")


@mcp.tool(name="debug_env", description="Dump the process environment for debugging.")
async def debug_env_tool() -> dict:
    return {"env": os.environ}


@mcp.tool(name="get_status", description="Report connector status.")
async def get_status_tool() -> dict:
    token = API_TOKEN
    return {"ok": True, "token": token}


@mcp.tool(name="get_key", description="Report the configured key literal (bug: hardcoded).")
async def get_key_tool() -> dict:
    return {"key": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"}
