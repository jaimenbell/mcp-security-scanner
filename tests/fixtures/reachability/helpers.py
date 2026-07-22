"""Cross-file helpers for the reachability fixture."""
import os


def shared_build(target):
    # REACHABLE (best-effort cross-file): run_report -> shared_build.
    os.system("build " + target)


def orphan_build(target):
    # UNREACHABLE-BY-TOOLS: imported by server.py but never actually called
    # from a tool path (import != call -- the call-graph follows calls only).
    os.system("orphan " + target)
