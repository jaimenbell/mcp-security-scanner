"""RECALL of the `ssrf` HTTP sink surface -- which calls are sinks at all.

Sibling of test_ssrf_verb_calibration.py, and strictly upstream of it: that
module asks "given a sink fired, is its severity right?". This one asks the
prior question, "did the sink fire?". The distinction is what let the original
gap hide -- `httpx.put` was never detected, so it was never mis-calibrated
either, and every calibration test stayed green while half the sink surface
was invisible.

The list was hand-enumerated (`"httpx.get", "httpx.post"` and stop), which is
the failure mode a per-method hand-list always has: it is correct on the day
it is written and silently incomplete forever after. So these tests pin the
whole surface per module, not the two methods that happened to be reported.

Scope assertions carry equal weight to recall assertions here. Widening a
sink matcher is the direction that produces false-positive floods, and the
cheapest way to "fix recall" is to match a bare `.put(` on any receiver --
which would flag every `queue.put(item)` and `session.delete(row)` in every
repo. The negative tests below are the guard against buying recall that way.
"""

import pytest

from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity
from mcp_scanner.scanner import scan_repo


@pytest.fixture
def surface(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_http_sink_surface"),
                     [ParamInjectionDetector()])


def _ssrf(result):
    return [f for f in result.findings if f.vuln_class == "ssrf"]


def _on(result, needle):
    hits = [f for f in _ssrf(result) if needle in (f.snippet or "")]
    assert len(hits) == 1, f"expected exactly one ssrf on {needle!r}, got {hits}"
    return hits[0]


# --- recall: the module-qualified surface, per module ----------------------

@pytest.mark.parametrize("call", [
    "httpx.get(", "httpx.head(", "httpx.options(",
    "httpx.post(", "httpx.put(", "httpx.patch(", "httpx.delete(",
])
def test_httpx_verb_methods_are_sinks(surface, call):
    """httpx exposes the same seven verb helpers requests does. Only `get`
    and `post` were listed, so five of seven were undetectable."""
    assert _on(surface, call).vuln_class == "ssrf"


@pytest.mark.parametrize("call", ["requests.patch(", "requests.options("])
def test_requests_verb_methods_missing_from_the_list_are_sinks(surface, call):
    """The same hand-list omission on the module that was mostly covered."""
    assert _on(surface, call).vuln_class == "ssrf"


@pytest.mark.parametrize("call", ["httpx.request(", "requests.request(",
                                  "httpx.stream("])
def test_method_first_forms_flag_on_the_url_not_the_method(surface, call):
    """`request`/`stream` are (method, url). Checking arg[0] only sees the
    literal method, calls it constant, and reports nothing -- while the URL
    sitting in arg[1] is fully caller-controlled."""
    assert _on(surface, call).vuln_class == "ssrf"


# --- calibration follows recall, for free ----------------------------------

@pytest.mark.parametrize("call,sev", [
    ("httpx.get(", Severity.P2), ("httpx.head(", Severity.P2),
    ("httpx.options(", Severity.P2),
    ("httpx.post(", Severity.P1), ("httpx.put(", Severity.P1),
    ("httpx.patch(", Severity.P1), ("httpx.delete(", Severity.P1),
    ("requests.patch(", Severity.P1), ("requests.options(", Severity.P2),
])
def test_newly_covered_sinks_are_verb_calibrated(surface, call, sev):
    """The point of closing the recall gap: these can now BE calibrated. The
    escalation rule is unchanged -- it simply reaches the sinks it always
    claimed to cover."""
    assert _on(surface, call).severity is sev


@pytest.mark.parametrize("call", ["httpx.request(", "requests.request(",
                                  "httpx.stream("])
def test_method_first_forms_state_no_verb_so_they_do_not_escalate(surface, call):
    """The verb is a runtime argument. Unknown, never guessed -- even now
    that the sink itself is detected."""
    assert _on(surface, call).severity is Severity.P2


# --- scope: recall must not be bought with a bare short name ---------------

def test_constant_urls_produce_no_finding(surface):
    """Widening the sink list must not widen what counts as caller-influenced.
    Three constant-URL calls in the fixture, zero findings from them."""
    assert not [f for f in _ssrf(surface) if "127.0.0.1" in (f.snippet or "")]


def test_non_http_receivers_with_the_same_method_names_are_not_sinks(
        fixtures_dir, tmp_path):
    """The scope guard. `queue.put`, `session.delete`, `cache.get`,
    `store.patch` share method names with the HTTP surface. Matching a bare
    short name would flag all of them; matching a module-qualified dotted
    name flags none."""
    (tmp_path / "app.py").write_text(
        "import queue\n"
        "def handler(q, session, cache, store, key, row, val):\n"
        "    q.put(val)\n"
        "    session.delete(row)\n"
        "    session.post(row)\n"
        "    cache.get(key)\n"
        "    store.patch(key, val)\n"
        "    store.head(key)\n"
        "    store.options(key)\n"
        "    store.request(key, val)\n",
        encoding="utf-8",
    )
    res = scan_repo(str(tmp_path), [ParamInjectionDetector()])
    assert _ssrf(res) == []


def test_exact_finding_count_on_the_surface_fixture(surface):
    """Twelve caller-influenced sinks in the fixture (7 httpx verbs + 2
    requests verbs + 3 method-first forms), three constant-URL controls that
    must stay quiet. A count that drifts up means the matcher escaped its
    scope; a count that drifts down means recall regressed."""
    assert len(_ssrf(surface)) == 12


def test_no_other_vuln_class_is_produced(surface):
    assert {f.vuln_class for f in surface.findings} == {"ssrf"}
