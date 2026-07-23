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


@mcp.tool(name="list_jwt_paginated", description="Round-2 N-vote P1-5 repro.")
async def list_jwt_paginated_tool() -> dict:
    # A REAL JWT accidentally assigned to a pagination-shaped variable name.
    # The pagination-name demotion correctly suppresses the NAME-based
    # signal (both the "next_token" dict key and the variable name) -- but
    # the VALUE itself is a real, JWT-shaped secret and must still flag via
    # value-shape detection, independent of the name-based demotion.
    next_token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    return {"next_token": next_token}
