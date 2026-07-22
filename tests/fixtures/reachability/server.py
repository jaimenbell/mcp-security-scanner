"""Reachability fixture -- one finding of every reachability grade.

A registered MCP tool, a same-file helper it calls, a cross-file helper it
calls, a dead helper nothing calls, an imported-but-never-called helper, and
module-level code. Each ``os.system`` below is a param-injection sink the
scanner already flags; this fixture exercises how the post-detector
reachability pass grades each one.
"""
import os

from fastmcp import FastMCP

from helpers import shared_build, orphan_build  # orphan_build imported, never called

mcp = FastMCP("demo")


@mcp.tool()
def run_report(target):
    # REACHABLE: sink sits directly inside a registered tool handler.
    os.system("report " + target)
    _same_file_helper(target)
    return shared_build(target)


def _same_file_helper(target):
    # REACHABLE: transitively called by run_report within the same file.
    os.system("same-file " + target)


def _dead_helper(target):
    # UNREACHABLE-BY-TOOLS: no registered tool has a call path to this.
    os.system("dead " + target)


# UNKNOWN: module-level code has no enclosing function to attribute to a tool.
os.system("startup " + os.environ.get("BOOT", ""))
