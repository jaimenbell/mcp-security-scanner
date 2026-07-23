"""Same shape as fixtures/reachability_cli, minus the UNCALLED dead-code
case -- used by test_cli_fail_on_gate.py so the only finding in this repo
is CLI_ONLY, proving the --fail-on gate carve-out end-to-end through main()."""
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def search(query):
    return {"query": query}
