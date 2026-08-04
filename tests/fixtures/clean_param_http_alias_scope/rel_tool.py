"""Relative imports: same-repo by construction, never a third-party alias.

`from .util import get` names a module that can only live in this repo, so it
is the re-export case again. `from .httpx import post` is the sharp one: the
leading dot is the ONLY thing distinguishing it from the real package, since
`ast` reports the module as plain "httpx" either way. If the level were not
checked, this repo's own `httpx.py` would be admitted as the third-party
package it is not, and a local helper would be reported as an HTTP sink.
"""

from .util import get
from .httpx import post as p


def fetch_with_a_local_helper(url):
    return get(url)


def send_with_a_local_helper(url, body):
    return p(url, json=body)
