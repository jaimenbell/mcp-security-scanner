"""Tool-parameter taint tracking (post-detector pass).

Slice 1 -- intra-file taint: tool params are sources; propagate through
assignments / f-strings / concat / same-file helper calls into the
param-injection sinks. Slice 2 (cross-file) lives in test_taint_crossfile.py.
"""
import tempfile
from pathlib import Path

import pytest

from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Taint


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #
@pytest.fixture
def graded(fixtures_dir):
    """Scan the intra-file taint fixture with only param-injection."""
    return scan_repo(str(fixtures_dir / "taint"), [ParamInjectionDetector()])


def _by_snippet(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------- #
# The intra-file taint matrix
# --------------------------------------------------------------------- #
def test_direct_param_into_sink_is_tainted(graded):
    assert _by_snippet(graded, '"direct ').taint is Taint.TAINTED


def test_taint_through_fstring_assignment(graded):
    assert _by_snippet(graded, "os.system(cmd)").taint is Taint.TAINTED


def test_taint_through_same_file_helper(graded):
    assert _by_snippet(graded, '"helper ').taint is Taint.TAINTED


def test_constant_arg_is_untainted_not_dropped(graded):
    # shell=True flags regardless; the constant argument is UNTAINTED. Critically
    # the finding is KEPT (over-flag philosophy), only its confidence lowered.
    f = _by_snippet(graded, "const-cmd")
    assert f.taint is Taint.UNTAINTED


def test_dead_helper_is_taint_unknown(graded):
    # Unreachable from any tool -> taint axis stays UNKNOWN (reachability owns
    # the reachable/unreachable verdict).
    assert _by_snippet(graded, '"dead ').taint is Taint.UNKNOWN


# --------------------------------------------------------------------- #
# Confidence nudges -- raise on tainted, lower on untainted, never drop
# --------------------------------------------------------------------- #
def test_tainted_raises_confidence(graded):
    # os.system(non-const) is HIGH at the detector; tainted keeps it HIGH.
    assert _by_snippet(graded, '"direct ').confidence is Confidence.HIGH


def test_untainted_lowers_but_keeps_finding(graded):
    # subprocess shell=True is P1/HIGH; untainted lowers to MEDIUM, still present.
    f = _by_snippet(graded, "const-cmd")
    assert f.confidence is Confidence.MEDIUM


def test_taint_never_drops_a_finding(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "taint"))
    raw = ParamInjectionDetector().run(ctx)
    result = scan_repo(str(fixtures_dir / "taint"), [ParamInjectionDetector()])
    assert len(result.findings) == len(raw)
    assert all(f.taint in Taint for f in result.findings)


def test_taint_serialized_in_to_dict(graded):
    d = _by_snippet(graded, '"direct ').to_dict()
    assert d["taint"] == "tainted"


# --------------------------------------------------------------------- #
# No discoverable tools -> everything UNKNOWN, confidence untouched
# --------------------------------------------------------------------- #
def test_no_tools_grades_all_taint_unknown_and_preserves_confidence():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "lib.py"
        p.write_text(
            "import os\n"
            "def helper(x):\n"
            "    os.system('run ' + x)\n",
            encoding="utf-8",
        )
        r = scan_repo(d, [ParamInjectionDetector()])
        assert r.findings
        assert all(f.taint is Taint.UNKNOWN for f in r.findings)
        assert all(f.confidence is Confidence.HIGH for f in r.findings)


# --------------------------------------------------------------------- #
# Non-dataflow finding classes are never taint-graded
# --------------------------------------------------------------------- #
def test_non_dataflow_class_is_taint_unknown(fixtures_dir):
    # The auth/secret/etc. detectors are not dataflow-shaped; scan the vuln_auth
    # fixture with all detectors and confirm any non-param-injection finding is
    # left taint-UNKNOWN.
    r = scan_repo(str(fixtures_dir / "vuln_auth"))
    non_df = [f for f in r.findings
              if f.vuln_class not in {"shell-injection", "code-eval",
                                      "unsafe-deserialization", "ssrf",
                                      "path-traversal"}]
    assert non_df, "sanity: expected at least one non-dataflow finding"
    assert all(f.taint is Taint.UNKNOWN for f in non_df)
