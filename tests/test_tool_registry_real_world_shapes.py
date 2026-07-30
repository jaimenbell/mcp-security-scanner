"""Tool-registry extraction for the registration idioms real MCP servers use
(2026-07-30 recall slice 1).

The 2026-07-30 five-target hand audit (``ecoscan-targets.lock.json``) found the
registry extractor matched **none** of the five pinned servers' registration
idioms.  ``_JS_TOOL_RE`` was ``\\b[\\w$]+\\.tool\\s*\\(`` -- the *deprecated*
``server.tool()`` API only -- and the Python side understood decorators only:

    | target               | idiom                                        | found/actual |
    | mcp-server-qdrant    | ``self.tool(func, name=...)`` FastMCP subclass| 0/2 |
    | notion-mcp-server    | ``setRequestHandler(CallToolRequestSchema,)`` | 0/-- |
    | mcp-server-neon      | ``server.tool(t.name, ...)`` in a forEach     | 1/34 (``(inline)``) |
    | airtable-mcp-server  | ``server.registerTool(name, config, handler)``| 0/16 |
    | firecrawl-mcp-server | ``server.addTool({ ... })`` (fastmcp TS SDK)  | 0/28 |

``has_tools`` was therefore False on four of five real targets, which cascades:
``grading._reason_for`` reports "no MCP tool registrations were found", and
``tool_scope_creep._scan_js`` / ``secret_leak_response._scan_js`` -- both of
which key off ``source == "js-regex"`` registrations to derive their line
windows -- never inspected a single handler.

THE HARD INVARIANT this file exists to pin: a regex-derived JS/TS registration
keeps ``node=None``.  ``ToolRegistration.node`` is consumed as an ``ast.AST``
by ``reachability.reachable_from`` / ``taint.propagate``; inventing a non-None
value for a JS match would feed a non-AST object into the Python call-graph.
This slice buys ``has_tools`` and detector windows.  It does NOT buy JS/TS a
call graph, and must not pretend to.
"""
import tempfile
from pathlib import Path

from mcp_scanner.scanner import build_context
from mcp_scanner.tool_registry import extract_tool_registry


def _regs(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as d:
        for rel, body in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        ctx, _ = build_context(d)
        return extract_tool_registry(ctx)


def _names(regs, source=None):
    return {r.name for r in regs if source is None or r.source == source}


# --------------------------------------------------------------------- #
# 1. current MCP TS SDK: server.registerTool(name, config, handler)
#    (airtable-mcp-server; tab-indented, name on the line AFTER the call)
# --------------------------------------------------------------------- #
REGISTER_TOOL_TS = (
    "export function registerCreateRecord(server: McpServer) {\n"
    "\tserver.registerTool(\n"
    "\t\t'create_record',\n"
    "\t\t{\n"
    "\t\t\ttitle: 'Create Record',\n"
    "\t\t\tdescription: 'Create a new record in a table',\n"
    "\t\t},\n"
    "\t\tasync (args) => {\n"
    "\t\t\treturn await client.createRecord(args);\n"
    "\t\t},\n"
    "\t);\n"
    "}\n"
)


def test_register_tool_multiline_name_is_extracted():
    regs = _regs({"src/tools/create-record.ts": REGISTER_TOOL_TS})
    assert "create_record" in _names(regs), (
        "the current MCP TS SDK registerTool() API must be recognized; it is "
        "what airtable-mcp-server uses in all 16 of its tool files"
    )


def test_register_tool_same_line_name_is_extracted():
    regs = _regs({"a.ts": "server.registerTool('list_bases', {}, handler);\n"})
    assert "list_bases" in _names(regs)


# --------------------------------------------------------------------- #
# 2. fastmcp TS SDK: server.addTool({ name: '...' })
#    (firecrawl-mcp-server, 28 real call sites)
# --------------------------------------------------------------------- #
ADD_TOOL_TS = (
    "server.addTool({\n"
    "  name: 'firecrawl_scrape',\n"
    "  annotations: {\n"
    "    title: 'Scrape a URL',\n"
    "  },\n"
    "  execute: async (args) => doScrape(args),\n"
    "});\n"
    "\n"
    "  registrar.addTool({\n"
    "    name: 'firecrawl_monitor_list',\n"
    "    execute: async () => listMonitors(),\n"
    "  });\n"
)


def test_add_tool_object_literal_name_is_extracted():
    regs = _regs({"src/index.ts": ADD_TOOL_TS})
    assert {"firecrawl_scrape", "firecrawl_monitor_list"} <= _names(regs)


def test_add_tool_non_registration_noise_is_not_a_registration():
    """The four shapes firecrawl's own source carries that LOOK like addTool
    but register nothing -- a type alias, a ``Parameters<typeof>``, the
    ``.bind`` rebinding, and a proxy-object property.  Over-matching these
    would inflate the tool count and, worse, hand the JS window detectors a
    bogus window anchored on a type declaration."""
    noise = (
        "type Registrar = Pick<FastMCP<SessionData>, 'addTool'>;\n"
        "type ToolArg = Parameters<typeof server.addTool>[0];\n"
        "const addTool = server.addTool.bind(server);\n"
        "server.addTool = ((tool) => addTool(guardHostedTool(tool))) as any;\n"
        "const proxy = { addTool: ((tool) => {}) as FastMCP<X>['addTool'] };\n"
    )
    regs = _regs({"src/noise.ts": noise})
    assert regs == [], f"expected zero registrations from type/rebinding noise, got {regs}"


# --------------------------------------------------------------------- #
# 3. low-level TS SDK: setRequestHandler(CallToolRequestSchema, ...)
#    (notion-mcp-server; tools are generated at runtime from an OpenAPI spec,
#    so there is no static name to recover -- but the dispatcher IS a
#    registration, and finding it is what flips has_tools.)
# --------------------------------------------------------------------- #
LOWLEVEL_TS = (
    "class MCPProxy {\n"
    "  setupHandlers() {\n"
    "    this.server.setRequestHandler(ListToolsRequestSchema, async () => {\n"
    "      return { tools: this.buildToolList() };\n"
    "    })\n"
    "    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
    "      return this.dispatch(request.params.name, request.params.arguments);\n"
    "    })\n"
    "  }\n"
    "}\n"
)


def test_lowlevel_ts_call_tool_dispatcher_is_a_registration():
    regs = _regs({"src/proxy.ts": LOWLEVEL_TS})
    assert len(regs) == 1, f"expected exactly the CallTool dispatcher, got {regs}"
    assert regs[0].line == 6, "the registration must anchor on the CallTool handler line"


def test_lowlevel_ts_list_tools_handler_is_not_a_registration():
    """``ListToolsRequestSchema`` returns tool METADATA and never executes tool
    logic -- the same distinction ``_extract_low_level_sdk`` already enforces
    on the Python side (round-3 N-vote fix).  Anchoring a window there would
    scan the tool-listing code as if it were a handler body."""
    regs = _regs({
        "src/list_only.ts":
            "this.server.setRequestHandler(ListToolsRequestSchema, async () => ({tools: []}))\n"
    })
    assert regs == [], f"expected no registration from a list_tools-only file, got {regs}"


# --------------------------------------------------------------------- #
# 4. THE HARD INVARIANT -- node stays None for every regex-derived JS match
# --------------------------------------------------------------------- #
def test_every_js_registration_keeps_node_none():
    regs = _regs({
        "src/tools/create-record.ts": REGISTER_TOOL_TS,
        "src/index.ts": ADD_TOOL_TS,
        "src/proxy.ts": LOWLEVEL_TS,
        "src/legacy.ts": "server.tool('deprecated_api', {}, handler);\n",
    })
    js = [r for r in regs if r.source == "js-regex"]
    assert len(js) >= 5
    assert all(r.node is None for r in js), (
        "ToolRegistration.node is consumed as an ast.AST by the Python "
        "call-graph; a JS regex match has no AST node and must never invent one"
    )


# --------------------------------------------------------------------- #
# 5. Python FastMCP-subclass call shape: self.tool(func, name="...")
#    (mcp-server-qdrant -- a plain call, not a decorator)
# --------------------------------------------------------------------- #
QDRANT_SHAPE = (
    # The standalone `fastmcp` distribution, NOT `mcp.server.fastmcp` -- this
    # is qdrant's real import line, and an ``mcp``-only provenance gate found
    # zero of its 2 tools.
    "from fastmcp import Context, FastMCP\n"
    "\n"
    "class QdrantMCPServer(FastMCP):\n"
    "    def setup_tools(self):\n"
    "        async def find(query: str):\n"
    "            return await self.connector.search(query)\n"
    "\n"
    "        find_foo = find\n"
    "        if self.settings.wrap:\n"
    "            find_foo = wrap_filters(find_foo, {})\n"
    "\n"
    "        self.tool(\n"
    "            find_foo,\n"
    "            name='qdrant-find',\n"
    "            description=self.settings.find_description,\n"
    "        )\n"
)


def test_python_tool_call_registration_is_extracted():
    regs = _regs({"server.py": QDRANT_SHAPE})
    assert "qdrant-find" in _names(regs), (
        "FastMCP subclasses register via a self.tool(func, name=...) CALL, not "
        "a decorator; mcp-server-qdrant registered 0 of its 2 tools before this"
    )


def test_python_tool_call_via_alias_variable_claims_no_root():
    """``find_foo`` is a local alias that is conditionally REASSIGNED to a
    wrapper.  Resolving it to the ``find`` def would be a guess, and a wrong
    root is a confident mis-grade -- the exact failure ``_extract_low_level_sdk``
    was corrected for twice.  Never guess: node=None."""
    regs = _regs({"server.py": QDRANT_SHAPE})
    r = [x for x in regs if x.name == "qdrant-find"][0]
    assert r.node is None


def test_python_tool_call_with_direct_funcdef_arg_resolves_its_root():
    """When the first positional argument IS the name of a function defined in
    the same file, that FunctionDef is an unambiguous, genuine call-graph root
    -- a real ast node, unlike anything on the JS path."""
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('demo')\n"
        "\n"
        "def do_search(query: str):\n"
        "    return query\n"
        "\n"
        "mcp.tool(do_search, name='search')\n"
    )
    regs = _regs({"server.py": src})
    r = [x for x in regs if x.name == "search"][0]
    assert r.node is not None
    assert getattr(r.node, "name", None) == "do_search"


def test_python_tool_call_without_name_kwarg_falls_back_to_the_func_name():
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('demo')\n"
        "\n"
        "def store_note(text: str):\n"
        "    return text\n"
        "\n"
        "mcp.tool(store_note)\n"
    )
    regs = _regs({"server.py": src})
    assert "store_note" in _names(regs)


def test_python_tool_decorator_is_not_double_counted_as_a_call():
    """``@mcp.tool()`` is an ast.Call too.  It must produce exactly ONE
    registration, from the decorator path, not a second from the call path."""
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('demo')\n"
        "\n"
        "@mcp.tool()\n"
        "def decorated(x: str):\n"
        "    return x\n"
    )
    regs = _regs({"server.py": src})
    assert len(regs) == 1, f"expected one registration, got {regs}"
    assert regs[0].source == "py-decorator"


def test_python_tool_call_bundled_fastmcp_import_also_counts():
    """Both distributions that export ``FastMCP`` must satisfy provenance:
    the standalone ``fastmcp`` package (tested above via QDRANT_SHAPE) and the
    bundled ``mcp.server.fastmcp``."""
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('demo')\n"
        "def ping():\n"
        "    return 'pong'\n"
        "mcp.tool(ping, name='ping')\n"
    )
    regs = _regs({"server.py": src})
    assert "ping" in _names(regs, "py-call")


def test_python_tool_call_on_a_non_mcp_file_is_ignored():
    """Provenance gate, mirroring ``_file_imports_mcp``: some other library's
    ``.tool(...)`` call must not flip ``has_tools`` for a repo that exposes no
    MCP tools at all."""
    src = (
        "from langchain.agents import AgentExecutor\n"
        "def helper(x):\n"
        "    return x\n"
        "registry.tool(helper, name='not-an-mcp-tool')\n"
    )
    regs = _regs({"agent.py": src})
    assert regs == [], f"expected no registration without mcp provenance, got {regs}"
