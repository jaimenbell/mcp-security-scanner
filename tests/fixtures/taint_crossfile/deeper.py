"""Cross-file taint fixture (Slice 2) -- the SECOND hop, intentionally beyond
the one-hop taint boundary. Reachability still reaches it (its call-graph is
unbounded by name); taint labels it UNKNOWN because it will not follow a second
import hop."""
import os


def deep_sink(d):
    # UNKNOWN (taint): two import hops from the tool -> the one-hop taint pass
    # does not prove the dataflow, so it honestly declines to grade it.
    os.system("deep " + d)
