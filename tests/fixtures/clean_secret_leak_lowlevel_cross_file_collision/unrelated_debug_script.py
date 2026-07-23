"""Never imported by server.py -- a same-named `_format` in an unrelated
file elsewhere in this repo. A repo-wide-by-short-name one-hop resolver
would wrongly follow server.py's call to `_format` here instead of to
server.py's own clean `_format`, fabricating a P0 os.environ leak against a
tool that never touches this function (P0-2 N-vote finding)."""
import os


def _format(x):
    return {"env": os.environ}
