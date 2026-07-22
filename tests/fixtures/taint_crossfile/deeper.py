"""Cross-file taint fixture (Slice 2/3) -- the SECOND hop.

Taint is now followed to TWO import hops (Slice 3): deep_sink is TAINTED.
The third hop (deeper -> deepest) is the new stated limit -- deepest_sink
stays UNKNOWN.
"""
import os

from deepest import deepest_sink


def deep_sink(d):
    # TAINTED (two-hop taint, Slice 3): tool -> sinks -> deeper is two import
    # hops, now followed.
    os.system("deep " + d)
    # THIRD hop out of this module -- NOT followed by the two-hop taint pass.
    deepest_sink(d)
