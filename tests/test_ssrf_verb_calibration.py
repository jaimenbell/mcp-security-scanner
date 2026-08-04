"""HTTP-verb severity calibration for `ssrf` findings.

The rule under test: for the SAME underlying issue (a caller-influenced URL
fetched with no host allowlist), a sink whose name states a STATE-CHANGING
verb (post/put/patch/delete) is escalated P2 -> P1, because SSRF through a
mutating method can drive internal state, not merely read it. A read-only verb
(get/head/options) keeps the base P2.

Half of these tests pin the calibration's SCOPE rather than its logic. That is
deliberate: this repo's recorded failure mode is a rule shipped without its
scope, which then silently means "everywhere". The scope assertions below are
the regression guard for that, and they are as load-bearing as the escalation
assertions.
"""

import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity


@pytest.fixture
def verbs(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_http_verb"),
                     [ParamInjectionDetector()])


@pytest.fixture
def verbs_js(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_http_verb_js"),
                     [ParamInjectionDetector()])


def _ssrf(result):
    return [f for f in result.findings if f.vuln_class == "ssrf"]


def _by_snippet(result, needle):
    """The single ssrf finding in server.py whose flagged line holds `needle`.

    Scoped to server.py on purpose: the fixture's test-path file repeats some
    of the same calls, and those are the subject of the carve-out test below.
    """
    hits = [f for f in _ssrf(result)
            if f.file == "server.py" and needle in (f.snippet or "")]
    assert len(hits) == 1, f"expected exactly one ssrf on {needle!r}, got {hits}"
    return hits[0]


# --- the calibration itself ------------------------------------------------

@pytest.mark.parametrize("call", ["requests.get(", "requests.head("])
def test_read_only_verbs_keep_base_severity(verbs, call):
    assert _by_snippet(verbs, call).severity is Severity.P2


@pytest.mark.parametrize("call", ["requests.post(", "requests.put(",
                                  "requests.delete("])
def test_state_changing_verbs_escalate(verbs, call):
    assert _by_snippet(verbs, call).severity is Severity.P1


def test_escalated_finding_names_the_verb_that_escalated_it(verbs):
    """An escalation a reader cannot audit is not an honest escalation."""
    f = _by_snippet(verbs, "requests.post(")
    assert "POST" in f.detail
    assert "state-changing" in f.detail.lower()


def test_read_only_finding_does_not_claim_an_escalation(verbs):
    assert "state-changing" not in _by_snippet(verbs, "requests.get(").detail.lower()


# --- scope: the verb must be STATED, never inferred ------------------------

@pytest.mark.parametrize("call", ["requests.request(", "urlopen("])
def test_verb_not_stated_in_sink_name_keeps_base_severity(verbs, call):
    """`requests.request(method, url)` / `urlopen(url)` carry no verb in the
    sink name -- the method is a runtime value. Unknown, never guessed."""
    assert _by_snippet(verbs, call).severity is Severity.P2


# --- scope: test paths withhold the escalation, never the finding ----------

def test_test_path_withholds_escalation_but_keeps_the_finding(fixtures_dir):
    """Per README's one law a path may only demote/tag, never suppress. So the
    ESCALATION is what the test-path carve-out scopes away -- the finding
    itself still reports, at its base severity."""
    res = scan_repo(str(fixtures_dir / "vuln_param_http_verb"),
                    [ParamInjectionDetector()])
    in_tests = [f for f in _ssrf(res) if "tests/" in f.file]
    assert len(in_tests) == 2, f"finding must not be dropped, got {in_tests}"
    assert {f.severity for f in in_tests} == {Severity.P2}
    assert all("test-path" in f.detail for f in in_tests)


# --- scope: the JS/TS path is excluded -------------------------------------

def test_js_state_changing_verb_does_not_escalate(verbs_js):
    """`axios.post(...)` states a mutating verb as plainly as the Python form.
    It still must not escalate -- the calibration is Python-AST-scoped."""
    hits = _ssrf(verbs_js)
    assert hits, "fixture must still produce its ssrf finding"
    assert {f.severity for f in hits} == {Severity.P2}


# --- scope: the calibration moves severity ONLY ----------------------------

def test_calibration_adds_and_drops_no_findings(verbs):
    """Nine ssrf sinks in (seven in server.py, two under tests/), nine out. A
    severity calibration that changes the finding COUNT has escaped its
    scope."""
    assert len(_ssrf(verbs)) == 9


def test_no_other_vuln_class_is_touched(verbs):
    """The verb rule is bound to `ssrf`. Nothing else in the fixture may move."""
    assert {f.vuln_class for f in verbs.findings} == {"ssrf"}
