"""Cross-file taint fixture (Slice 2) -- one import hop from the tool handler."""
import os

from deeper import deep_sink


def run_cmd(c):
    # TAINTED: `c` is the tool parameter, one import hop from the handler.
    os.system("cross " + c)
    # SECOND hop out of this module -- NOT followed by the one-hop taint pass.
    deep_sink(c)


def log_fixed(msg):
    # UNTAINTED: `msg` is only ever called with a constant literal.
    os.system("logfixed " + msg)
