"""Low-level MCP SDK coverage for detector 6 (secret-leak-via-tool-response),
2026-07-23. Before this fix, ``secret_leak_response.py`` only walked
``@mcp.tool()``-decorated functions -- a repo using the low-level SDK shape
(``Server()`` + a single ``@server.call_tool()`` dispatch function, see
tests/fixtures/reachability_lowlevel_sdk/server.py) produced ZERO findings
from this detector regardless of what its tool responses leaked.
"""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretLeakResponseDetector
from mcp_scanner.models import Severity


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_lowlevel_sdk_leak_via_one_hop_helper_attributed_to_tool(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "vuln_secret_leak_lowlevel"), [SecretLeakResponseDetector()])
    assert "secret-leak-via-tool-response" in _classes(result)
    hits = [f for f in result.findings if "environ" in f.detail.lower()]
    assert hits, f"expected an os.environ leak via the one-hop helper, got: {result.findings}"
    assert any("search_knowledge" in f.detail for f in hits), (
        f"leak reached via the dispatched helper must be attributed to the "
        f"'search_knowledge' tool branch that calls it, got: {[f.detail for f in hits]}"
    )
    assert any(f.severity == Severity.P0 for f in hits)


def test_lowlevel_sdk_direct_branch_leak_attributed_to_tool(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "vuln_secret_leak_lowlevel"), [SecretLeakResponseDetector()])
    hits = [f for f in result.findings if "api_key" in f.detail.lower()]
    assert hits
    assert any("dump_config" in f.detail for f in hits), (
        f"direct secret-named return in the unambiguous 'dump_config' branch "
        f"must be attributed to that tool, got: {[f.detail for f in hits]}"
    )


def test_lowlevel_sdk_ambiguous_branch_attributed_to_handler_not_a_tool(fixtures_dir):
    """The `elif name in ('fallback_tool', 'legacy_tool')` branch leaks a
    'token' field but is genuinely ambiguous (more than one tool name) --
    must be attributed to the dispatch handler itself, never guessed."""
    result = scan_repo(str(fixtures_dir / "vuln_secret_leak_lowlevel"), [SecretLeakResponseDetector()])
    hits = [f for f in result.findings if "'token'" in f.detail]
    assert hits, f"expected the ambiguous-branch token leak to be flagged, got: {result.findings}"
    for f in hits:
        assert "fallback_tool" not in f.detail and "legacy_tool" not in f.detail, (
            f"ambiguous branch must not be guessed as one specific tool name, got: {f.detail}"
        )
        assert "call_tool" in f.detail or "dispatch handler" in f.detail, (
            f"ambiguous branch finding must attribute to the dispatch handler, got: {f.detail}"
        )


def test_lowlevel_sdk_clean_repo_quiet(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "clean_secret_leak_lowlevel"), [SecretLeakResponseDetector()])
    hits = [f for f in result.findings if f.vuln_class == "secret-leak-via-tool-response"]
    assert hits == [], f"non-leaking low-level-SDK tool responses must not be flagged, got: {hits}"


def test_lowlevel_sdk_get_status_branch_stays_quiet(fixtures_dir):
    """Sanity: the clean 'get_status' branch inside the vuln fixture itself
    must not spuriously fire."""
    result = scan_repo(str(fixtures_dir / "vuln_secret_leak_lowlevel"), [SecretLeakResponseDetector()])
    hits = [f for f in result.findings if "get_status" in f.detail]
    assert hits == []


def test_lowlevel_sdk_ambiguous_call_tool_file_never_guessed(tmp_path):
    """Two @server.call_tool() handlers in one file (genuinely ambiguous) --
    even a blatant os.environ leak inside must never be attributed, never
    guessed. Mirrors tool_registry's own never-guess-a-root discipline for
    reachability."""
    (tmp_path / "server.py").write_text(
        "from mcp import types\n"
        "from mcp.server import Server\n"
        "import os\n"
        "server_a = Server('a')\n"
        "server_b = Server('b')\n"
        "\n"
        "@server_a.call_tool()\n"
        "async def call_tool_a(name, arguments):\n"
        "    return {'env': os.environ}\n"
        "\n"
        "@server_b.call_tool()\n"
        "async def call_tool_b(name, arguments):\n"
        "    return {'env': os.environ}\n",
        encoding="utf-8",
    )
    result = scan_repo(str(tmp_path), [SecretLeakResponseDetector()])
    assert result.findings == [], (
        f"an ambiguous (2+ call_tool handlers) file must be skipped entirely, "
        f"got: {result.findings}"
    )


# --------------------------------------------------------------------- #
# P0-2 N-vote fix: one-hop helper resolution must be SAME-FILE-ONLY
# --------------------------------------------------------------------- #
def test_p0_2_cross_file_same_name_helper_not_followed(fixtures_dir):
    """A same-named `_format` in an unrelated, never-imported file elsewhere
    in the repo must NOT be resolved as the one-hop helper for a call in
    server.py -- that would fabricate a P0 os.environ leak against a clean
    tool. Repro straight from the N-vote refuter."""
    result = scan_repo(
        str(fixtures_dir / "clean_secret_leak_lowlevel_cross_file_collision"),
        [SecretLeakResponseDetector()],
    )
    assert result.findings == [], (
        f"cross-file same-named helper must never be followed by the one-hop "
        f"resolver, got: {[(f.file, f.detail) for f in result.findings]}"
    )


# --------------------------------------------------------------------- #
# P3 N-vote fix: detector-level end-to-end proof for the negated-guard shape
# --------------------------------------------------------------------- #
def test_p3_negated_guard_shape_still_flags_via_whole_handler_fallback(fixtures_dir):
    """rag-mcp's REAL dispatch shape (`if name != "x": ... else: ...`) isn't
    recognized as attributable dispatch (only `==` is), but the leak in the
    else-body must still surface via the whole-handler fallback -- an
    end-to-end proof beyond the `_string_eq_literal` unit test alone."""
    result = scan_repo(
        str(fixtures_dir / "vuln_secret_leak_lowlevel_negated_guard"),
        [SecretLeakResponseDetector()],
    )
    hits = [f for f in result.findings if "environ" in f.detail.lower()]
    assert hits, f"expected the else-body os.environ leak to fire, got: {result.findings}"
    for f in hits:
        assert "search_knowledge" not in f.detail, (
            f"a `!=`-guarded shape must not be guessed at one tool name, got: {f.detail}"
        )
        assert "call_tool" in f.detail or "dispatch handler" in f.detail
