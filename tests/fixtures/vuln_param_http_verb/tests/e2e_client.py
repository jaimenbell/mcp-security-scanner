"""Fixture: a state-changing ssrf sink sitting in a TEST-path directory.

Deliberately NOT named ``test_*.py``: this tree lives under the scanner's own
``tests/`` root, and pytest's ``testpaths = ["tests"]`` has no fixture
exclusion, so a ``test_*.py`` here would be collected as a real test module.
The directory segment ``tests/`` is what ``test_paths.is_test_path`` keys on,
which is the marker this fixture needs.

Mirrors the shape found live in the ecoscan corpus (sooperset/mcp-atlassian's
``tests/e2e/conftest.py`` drives real POST/DELETE calls against a fixture
server).
"""

import requests


def provision(base, payload):
    resp = requests.post(base, json=payload)
    requests.delete(base)
    return resp
