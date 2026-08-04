"""The re-export hop: a sink imported from a same-repo wrapper, not from the
package.

`mywrap` is not on the HTTP module list, so nothing here resolves and nothing
here is flagged. This is a stated MISS, not a claim of safety -- resolving it
needs cross-file import chasing, which is a different mechanism (see
`taint.py`'s two-hop propagation) and is deliberately not bundled into a
same-file alias resolver.

The test module pins it as a boundary rather than leaving it undocumented: a
future contributor who widens the module list into a general import graph
should be met by a failing test, not by a silently larger report.
"""

from mywrap import get
from mywrap import AsyncClient


def fetch_through_the_wrapper(url):
    return get(url)


def fetch_through_a_wrapped_client(url):
    wclient = AsyncClient()
    return wclient.post(url)
