"""Decidable-reachability grades: CLI_ONLY / UNCALLED (2026-07-22).

Born from the rag-mcp dogfood friction log: the scanner flagged a
path-traversal sink at ``rag_mcp/lock.py:144`` as ``reachable: unknown`` when
the true answer was decidable by hand -- the sink's only caller was
operator-argv (``cli.py``), with zero MCP-tool-registered callers reaching
it. These grades close that gap without overclaiming decidability: dynamic
dispatch keeps the old ``unknown`` behavior (see
``test_dynamic_dispatch_stays_unknown`` below).
"""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Reachability


def _by_snippet(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------- #
# CLI_ONLY -- the rag-mcp shape: sink has a real caller, but every found
# caller traces to a non-tool (argv/CLI-main) entrypoint.
# --------------------------------------------------------------------- #
def test_argv_only_sink_grades_cli_only(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"acquire-lock ')
    assert f.reachability is Reachability.CLI_ONLY


def test_cli_only_carries_caller_chain_evidence(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"acquire-lock ')
    assert f.reachability_evidence, "CLI_ONLY must carry caller-chain evidence"
    assert "_cmd_ingest" in f.reachability_evidence
    assert "cli.py" in f.reachability_evidence


def test_cli_only_serialized_in_to_dict(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    d = _by_snippet(result, '"acquire-lock ').to_dict()
    assert d["reachability"] == "cli-only"
    assert d["reachability_evidence"]


def test_cli_only_lowers_confidence_like_unreachable(fixtures_dir):
    from mcp_scanner.models import Confidence
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"acquire-lock ')
    # os.system(non-const) is HIGH at the detector; a non-tool-reachable
    # grade still lowers confidence, same as the old UNREACHABLE behavior.
    assert f.confidence is Confidence.MEDIUM


# --------------------------------------------------------------------- #
# UNCALLED -- genuinely zero callers anywhere in the repo.
# --------------------------------------------------------------------- #
def test_truly_dead_sink_grades_uncalled(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"dead-cli ')
    assert f.reachability is Reachability.UNCALLED


def test_uncalled_serialized_in_to_dict(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    d = _by_snippet(result, '"dead-cli ').to_dict()
    assert d["reachability"] == "uncalled"


# --------------------------------------------------------------------- #
# Soundness: dynamic dispatch keeps `unknown`, never overclaims cli-only/
# uncalled -- a getattr(...)()-style call could reach anything.
# --------------------------------------------------------------------- #
def test_dynamic_dispatch_stays_unknown(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_dynamic"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"hidden ')
    assert f.reachability is Reachability.UNKNOWN
    assert f.reachability_evidence == ""


# --------------------------------------------------------------------- #
# Regression: a sink reachable from a TOOL (even if a CLI path also calls
# it) must stay REACHABLE -- the new branch only applies when the forward
# tool-walk found no path at all.
# --------------------------------------------------------------------- #
def test_mixed_tool_and_cli_caller_stays_reachable(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_toolcaller"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"shared ')
    assert f.reachability is Reachability.REACHABLE


# --------------------------------------------------------------------- #
# Never drops a finding, even with the two new grades in play.
# --------------------------------------------------------------------- #
def test_new_grades_never_drop_a_finding(fixtures_dir):
    from mcp_scanner.detectors.base import RepoContext
    from mcp_scanner.scanner import build_context

    ctx, _ = build_context(str(fixtures_dir / "reachability_cli"))
    raw = ParamInjectionDetector().run(ctx)
    result = scan_repo(str(fixtures_dir / "reachability_cli"), [ParamInjectionDetector()])
    assert len(result.findings) == len(raw)
    assert all(f.reachability in Reachability for f in result.findings)
