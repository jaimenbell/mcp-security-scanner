"""Fixture: a pagination/continuation-cursor field name (real ecosystem shape,
anonymized from an AWS-labs MCP server's list-jobs tool: `next_token` dict key
+ a `result_next_token`-named variable holding an opaque, server-issued
continuation handle) must NOT trip the secret-leak-via-tool-response
heuristic. A genuinely credential-named field returned alongside it in a
sibling tool must still flag -- proving the pagination demotion cannot mask
a real secret leak."""
from __future__ import annotations

from fastmcp import FastMCP

mcp = FastMCP("vuln-secret-leak-pagination-demo")


@mcp.tool(name="list_jobs", description="List translation jobs (paginated).")
async def list_jobs_tool() -> dict:
    job_list: list[dict] = []
    result_next_token = "opaque-server-issued-continuation-handle"
    return {
        "jobs": job_list,
        "total_count": len(job_list),
        "next_token": result_next_token,
    }


@mcp.tool(name="list_more", description="Pagination via a bare cursor field.")
async def list_more_tool() -> dict:
    cursor = "opaque-cursor-handle"
    return {"items": [], "cursor": cursor}


@mcp.tool(name="get_creds", description="Buggy: returns a real access token.")
async def get_creds_tool() -> dict:
    access_token = "should-still-flag-as-a-real-credential"
    return {"access_token": access_token}
