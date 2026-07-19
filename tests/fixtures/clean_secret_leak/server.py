"""Clean fixture: tool responses that return only non-secret data, including
a realistic near-miss (a name that shares a partial substring with the
secret-name heuristic but is not itself a credential)."""
from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("clean-secret-leak-demo")

API_TOKEN = os.environ.get("API_TOKEN", "")


@mcp.tool(name="get_status", description="Report connector status without leaking the token.")
async def get_status_tool() -> dict:
    is_connected = bool(API_TOKEN)
    return {"ok": True, "connected": is_connected, "message": "no secret exposed in this response"}


@mcp.tool(name="get_tokenizer_info", description="Report which tokenizer this server uses.")
async def get_tokenizer_info_tool() -> dict:
    tokenizer_version = "bpe-v2"
    passwordless_mode = True
    return {"tokenizer_version": tokenizer_version, "passwordless_mode": passwordless_mode}
