"""Test-path half of the alias fixture.

The same state-changing aliased sinks as `server.py`, on a path the shared
classifier calls a test path. Per README's one law a path-shape signal may
only demote or tag: the P2 -> P1 escalation is withheld, the finding itself
still reports. Alias resolution must not have bought its recall by routing
around that carve-out -- an alias-resolved match is subject to every gate the
literal spelling is subject to, and to no different ones.
"""

import httpx
import httpx as hx
from httpx import post as tp_post


def probe_unaliased(url, body):
    # Control on the SAME path, so the two below are asserted as parity with
    # the literal spelling under the carve-out rather than against a constant.
    tp_control = httpx.put(url, json=body)
    return tp_control


def probe_module_alias(url, body):
    tp_mod_write = hx.put(url, json=body)
    return tp_mod_write


def probe_symbol_alias(url, body):
    tp_sym_write = tp_post(url, json=body)
    return tp_sym_write
