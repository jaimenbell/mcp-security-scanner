"""Tool-parameter taint tracking -- Slice 2, cross-file (one import hop).

Follows a tool parameter one direct-import hop into another same-repo module and
propagates through the callee's params to its sinks. Documents the one-hop
limit: a second import hop is NOT followed (stays taint-UNKNOWN) even though the
reachability pass still reaches it.
"""
import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Reachability, Taint


@pytest.fixture
def graded(fixtures_dir):
    return scan_repo(str(fixtures_dir / "taint_crossfile"), [ParamInjectionDetector()])


def _by_snippet(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


def test_cross_file_one_hop_is_tainted(graded):
    # server.handle(target) -> import hop -> sinks.run_cmd(c) -> os.system.
    assert _by_snippet(graded, '"cross ').taint is Taint.TAINTED


def test_cross_file_constant_is_untainted(graded):
    # log_fixed only ever receives a constant -> UNTAINTED (kept, not dropped).
    f = _by_snippet(graded, "logfixed")
    assert f.taint is Taint.UNTAINTED


def test_same_file_baseline_still_tainted(graded):
    assert _by_snippet(graded, "localdirect").taint is Taint.TAINTED


def test_second_import_hop_is_not_followed(graded):
    # deeper.deep_sink is TWO hops from the tool. Reachability still reaches it
    # (unbounded by name); taint honestly declines -> UNKNOWN, the stated limit.
    f = _by_snippet(graded, '"deep ')
    assert f.taint is Taint.UNKNOWN
    assert f.reachability is Reachability.REACHABLE


def test_cross_file_tainted_raises_confidence(graded):
    # os.system(non-const) is HIGH; cross-file tainted keeps it HIGH.
    assert _by_snippet(graded, '"cross ').confidence is Confidence.HIGH


def test_cross_file_untainted_lowers_confidence(graded):
    # os.system("logfixed " + msg) with msg untainted -> HIGH lowered to MEDIUM.
    assert _by_snippet(graded, "logfixed").confidence is Confidence.MEDIUM
