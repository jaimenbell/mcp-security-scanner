"""A wrapper module that re-exports an HTTP verb.

This file itself calls nothing. It exists so `tool.py` can import the verb
from HERE rather than from the third-party package, which is the re-export
hop -- an explicit NON-GOAL of same-file alias resolution.
"""

from httpx import get
from httpx import AsyncClient
