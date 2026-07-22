"""Manifest-aware reachability grading + the shared tool-registry extractor."""
import tempfile
from pathlib import Path

import pytest

from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Reachability
from mcp_scanner.tool_registry import extract_tool_registry


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #
@pytest.fixture
def graded(fixtures_dir):
    """Scan the reachability fixture with only param-injection for determinism."""
    return scan_repo(str(fixtures_dir / "reachability"), [ParamInjectionDetector()])


def _by_snippet(result, needle):
    """The single shell finding whose flagged line contains ``needle``."""
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------- #
# The reachability matrix
# --------------------------------------------------------------------- #
def test_sink_inside_tool_handler_is_reachable(graded):
    assert _by_snippet(graded, '"report ').reachability is Reachability.REACHABLE


def test_same_file_transitive_helper_is_reachable(graded):
    assert _by_snippet(graded, '"same-file ').reachability is Reachability.REACHABLE


def test_cross_file_called_helper_is_reachable(graded):
    # Best-effort cross-file: run_report -> shared_build in helpers.py.
    assert _by_snippet(graded, '"build ').reachability is Reachability.REACHABLE


def test_dead_helper_is_unreachable(graded):
    assert _by_snippet(graded, '"dead ').reachability is Reachability.UNREACHABLE


def test_imported_but_uncalled_helper_is_unreachable(graded):
    # import != call: orphan_build is imported by server.py but never called.
    assert _by_snippet(graded, '"orphan ').reachability is Reachability.UNREACHABLE


def test_module_level_code_is_unknown(graded):
    assert _by_snippet(graded, '"startup ').reachability is Reachability.UNKNOWN


# --------------------------------------------------------------------- #
# Confidence nudges -- raise on reachable, lower on unreachable, never drop
# --------------------------------------------------------------------- #
def test_reachable_keeps_high_confidence(graded):
    # os.system(non-const) is P1/HIGH at the detector; reachable keeps it HIGH.
    assert _by_snippet(graded, '"report ').confidence is Confidence.HIGH


def test_unreachable_lowers_confidence(graded):
    # Same HIGH detector confidence, lowered to MEDIUM because it's unreachable.
    assert _by_snippet(graded, '"dead ').confidence is Confidence.MEDIUM


def test_unknown_leaves_confidence_untouched(graded):
    assert _by_snippet(graded, '"startup ').confidence is Confidence.HIGH


def test_grading_never_drops_a_finding(fixtures_dir):
    """Reachability grading only relabels/nudges -- it must not change the
    number of findings a detector produced."""
    from mcp_scanner.detectors.base import RepoContext
    from mcp_scanner import reachability

    ctx, _ = build_context(str(fixtures_dir / "reachability"))
    raw = ParamInjectionDetector().run(ctx)
    result = scan_repo(str(fixtures_dir / "reachability"), [ParamInjectionDetector()])
    assert len(result.findings) == len(raw)
    # every finding carries a concrete grade
    assert all(f.reachability in Reachability for f in result.findings)


def test_reachability_serialized_in_to_dict(graded):
    d = _by_snippet(graded, '"report ').to_dict()
    assert d["reachability"] == "reachable"


# --------------------------------------------------------------------- #
# No discoverable tools -> everything UNKNOWN, confidence untouched
# --------------------------------------------------------------------- #
def test_no_tools_grades_all_unknown_and_preserves_confidence():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "lib.py"
        p.write_text(
            "import os\n"
            "def helper(x):\n"
            "    os.system('run ' + x)\n",
            encoding="utf-8",
        )
        r = scan_repo(d, [ParamInjectionDetector()])
        assert r.findings, "sanity: the sink should still be flagged"
        assert all(f.reachability is Reachability.UNKNOWN for f in r.findings)
        # HIGH detector confidence must be preserved when we can't reason.
        assert all(f.confidence is Confidence.HIGH for f in r.findings)


# --------------------------------------------------------------------- #
# tool_registry extractor: python decorator + JS regex + server.json manifest
# --------------------------------------------------------------------- #
def test_extractor_finds_python_decorator_tool(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "reachability"))
    regs = extract_tool_registry(ctx)
    names = {r.name for r in regs if r.source == "py-decorator"}
    assert "run_report" in names


def test_extractor_finds_js_and_manifest():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "index.js").write_text(
            'server.tool("do_thing", async (args) => { return 1; });\n',
            encoding="utf-8",
        )
        (Path(d) / "server.json").write_text(
            '{"tools": [{"name": "manifest_tool"}]}\n',
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        regs = extract_tool_registry(ctx)
        by_source = {r.source: {x.name for x in regs if x.source == r.source} for r in regs}
        assert "do_thing" in by_source.get("js-regex", set())
        assert "manifest_tool" in by_source.get("manifest", set())
