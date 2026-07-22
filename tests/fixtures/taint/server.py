"""Intra-file taint fixture -- one finding of every intra-file taint grade.

Every ``os.system`` / ``subprocess`` below is a param-injection sink the scanner
already flags; this fixture exercises how the post-detector TAINT pass grades
whether a TOOL PARAMETER's value reaches each one. Distinct snippet markers let
the tests select each finding unambiguously.
"""
import os
import subprocess

from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run_report(target):
    # TAINTED: the tool parameter `target` flows directly into the sink.
    os.system("direct " + target)
    # TAINTED: through an assignment + f-string.
    cmd = f"fstr {target}"
    os.system(cmd)
    # TAINTED: through a same-file helper that receives the tainted arg.
    _same_file_helper(target)
    # UNTAINTED: shell=True always flags, but the argument is a constant --
    # no tool parameter reaches it (finding kept, confidence lowered).
    subprocess.run("const-cmd --flag", shell=True)
    return 0


def _same_file_helper(p):
    # TAINTED: `p` is the tainted argument passed by run_report.
    os.system("helper " + p)


def _dead_helper(target):
    # UNKNOWN (taint): unreachable from any tool -> the taint axis stays silent
    # (reachability is what grades this UNREACHABLE-by-tools).
    os.system("dead " + target)
