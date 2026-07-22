"""Cross-file taint fixture (Slice 3) -- the THIRD hop, intentionally beyond
the two-hop taint boundary. Reachability still reaches it (its call-graph is
unbounded by name); taint labels it UNKNOWN because it will not follow a
third import hop."""
import os


def deepest_sink(e):
    # UNKNOWN (taint): three import hops from the tool -> the two-hop taint
    # pass does not prove the dataflow, so it honestly declines to grade it.
    os.system("deepest " + e)
