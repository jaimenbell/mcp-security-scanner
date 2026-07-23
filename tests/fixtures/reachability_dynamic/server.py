"""Dynamic-dispatch reachability fixture -- proves ``unknown`` is preserved
(not overclaimed to cli-only/uncalled) when the repo contains a call site
this scanner cannot statically resolve to a name, e.g.
``getattr(handlers, name)(args)``. Such a call could, at runtime, reach ANY
function in the repo -- including one otherwise found to have zero static
callers -- so grading it confidently as UNCALLED (or CLI_ONLY) would
overclaim decidability. Soundness requires falling back to UNKNOWN.
"""
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def dispatch(name, args):
    # Unresolvable call target: `getattr(...)` result is invoked directly,
    # so the callee's identity is only known at runtime.
    handler = getattr(_handlers, name)
    return handler(args)


class _Handlers:
    pass


_handlers = _Handlers()
