"""A same-repo module that happens to be NAMED like the third-party package.

Nothing here is a sink. It exists so `rel_tool.py` can write
`from .httpx import post`, where `ast` reports `node.module == "httpx"` --
the exact spelling the module list admits. The relative-import guard, not the
module list, is what has to keep this out.
"""


def post(url, json=None):
    return url


def get(url):
    return url
