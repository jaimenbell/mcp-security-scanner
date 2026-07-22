"""Cross-file taint fixture (Slice 2) -- the tool handler.

A registered tool passes its parameter across a direct import into another
same-repo module. Taint is followed ONE hop (server -> sinks); a second hop
(sinks -> deeper) is deliberately NOT followed -- the documented limit.
"""
import os

from fastmcp import FastMCP

from sinks import run_cmd, log_fixed

mcp = FastMCP("demo")


@mcp.tool()
def handle(target):
    # TAINTED cross-file: `target` flows one import hop into sinks.run_cmd's sink.
    run_cmd(target)
    # UNTAINTED cross-file: log_fixed only ever receives a constant.
    log_fixed("static-label")
    # TAINTED same-file baseline (regression that same-file still works here).
    os.system("localdirect " + target)
    return 0
