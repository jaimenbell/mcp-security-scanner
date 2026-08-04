"""`ssrf` recall through a bound HTTP CLIENT INSTANCE.

Third module in the ssrf trio and the widest of the three:

  test_ssrf_sink_surface.py       -- is a module-qualified call a sink?
  this module                     -- is an instance-method call a sink?
  test_ssrf_verb_calibration.py   -- given a sink fired, is its severity right?

This is where the precision risk actually lives. `get`, `put`, `delete`,
`patch`, `head`, `options` and `request` are among the most common method
names in Python; matching them on ANY receiver would take this repo's own
13-repo scan corpus from 198 ssrf findings to roughly 12,400 candidate call
sites. So recall here is bought with EVIDENCE -- a same-file binding that
says what the receiver was constructed from -- and never with the name.

Half these tests are therefore negative. That is the point: the guard against
buying recall the cheap way is as load-bearing as the recall itself, and a
future contributor who "simplifies" the binding lookup into a short-name
check should be met by seven failing tests, not by a green suite and a
63x-inflated report.
"""

import pytest

from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity
from mcp_scanner.scanner import scan_repo


@pytest.fixture
def bound(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_http_client_bound"),
                     [ParamInjectionDetector()])


def _ssrf(result):
    return [f for f in result.findings if f.vuln_class == "ssrf"]


def _on(result, needle):
    hits = [f for f in _ssrf(result) if needle in (f.snippet or "")]
    assert len(hits) == 1, f"expected exactly one ssrf on {needle!r}, got {hits}"
    return hits[0]


# --- recall: each binding shape resolves ----------------------------------

@pytest.mark.parametrize("call", ["hclient.get(", "hclient.put(",
                                  "hclient.delete("])
def test_plain_assignment_binding(bound, call):
    """`hclient = httpx.Client()` then `hclient.put(url)`."""
    assert _on(bound, call).vuln_class == "ssrf"


@pytest.mark.parametrize("call", ["sess.post(", "sess.patch("])
def test_requests_session_binding(bound, call):
    assert _on(bound, call).vuln_class == "ssrf"


@pytest.mark.parametrize("call", ["ac.head(", "ac.options("])
def test_async_context_manager_binding(bound, call):
    """`async with httpx.AsyncClient() as ac:` binds via a withitem, not an
    assignment."""
    assert _on(bound, call).vuln_class == "ssrf"


def test_aiohttp_client_session_binding(bound):
    """aiohttp has no module-level verb helpers at all -- `ClientSession()`
    is its ONLY shape, so without receiver binding the library is 100%
    invisible to this detector."""
    assert _on(bound, "cs.post(").vuln_class == "ssrf"


def test_attribute_receiver_binding(bound):
    """`self._http = httpx.AsyncClient()` in __init__, used in a method."""
    assert _on(bound, "self._http.get(").vuln_class == "ssrf"


@pytest.mark.parametrize("call", ["mclient.request(", "mclient.stream("])
def test_method_first_forms_on_an_instance(bound, call):
    """(method, url) on an instance too -- the URL is arg[1]."""
    assert _on(bound, call).vuln_class == "ssrf"


# --- calibration reaches the newly-visible sinks --------------------------

@pytest.mark.parametrize("call,sev", [
    ("hclient.get(", Severity.P2), ("ac.head(", Severity.P2),
    ("ac.options(", Severity.P2),
    ("hclient.put(", Severity.P1), ("hclient.delete(", Severity.P1),
    ("sess.post(", Severity.P1), ("sess.patch(", Severity.P1),
    ("cs.post(", Severity.P1),
])
def test_bound_sinks_are_verb_calibrated(bound, call, sev):
    assert _on(bound, call).severity is sev


@pytest.mark.parametrize("call", ["mclient.request(", "mclient.stream("])
def test_method_first_instance_forms_state_no_verb(bound, call):
    assert _on(bound, call).severity is Severity.P2


# --- precision: the name is never the evidence ----------------------------

def test_queue_put_is_not_a_sink(bound):
    assert not [f for f in _ssrf(bound) if "q.put(" in (f.snippet or "")]


@pytest.mark.parametrize("call", ["db.delete(", "db.get("])
def test_orm_session_is_not_an_http_session(bound, call):
    assert not [f for f in _ssrf(bound) if call in (f.snippet or "")]


@pytest.mark.parametrize("call", ["fetcher.post(", "fetcher.delete("])
def test_a_bare_parameter_is_not_evidence(bound, call):
    """The single most tempting shortcut -- trusting the identifier. A
    parameter called `fetcher` or `client` could be boto3, a DB handle,
    anything."""
    assert not [f for f in _ssrf(bound) if call in (f.snippet or "")]


def test_a_parameter_shadowing_a_bound_name_is_not_flagged(bound):
    """The case that broke the first implementation. `client` really is
    bound to `httpx.Client()` -- in a DIFFERENT function. Resolution is
    file-wide, so without counting a parameter as conflicting evidence that
    binding leaks onto this function's parameter and manufactures a finding
    on a receiver nothing in the file describes."""
    assert not [f for f in _ssrf(bound) if "client.patch(" in (f.snippet or "")]


def test_the_contested_name_is_cancelled_in_both_directions(bound):
    """The stated COST of the rule above, pinned so it stays deliberate: the
    other use of `client` is a genuine httpx sink and is missed too. A
    per-scope resolution would recover it. Recording the miss as a passing
    test is the honest form -- an undocumented miss is how a recall gap
    like this one starts."""
    # Anchored on `return ` so this cannot accidentally match `hclient.get(`,
    # the uncontested sink three functions up.
    assert not [f for f in _ssrf(bound)
                if "return client.get(" in (f.snippet or "")]


@pytest.mark.parametrize("call", ["store.get(", "store.put(", "store.delete("])
def test_a_non_http_constructor_binds_nothing(bound, call):
    assert not [f for f in _ssrf(bound) if call in (f.snippet or "")]


def test_a_rebound_name_is_ambiguous_and_flags_neither_use(bound):
    """`conn` is an httpx.Client in one function and a dict in another. Same
    file, conflicting evidence. Fail QUIET here, not loud: an over-flag on a
    name-shaped receiver is the documented flood direction, and one honest
    miss costs less than a class of false positives."""
    assert not [f for f in _ssrf(bound) if "conn.get(" in (f.snippet or "")]


def test_constant_url_on_a_bound_client_is_not_a_sink(bound):
    """Binding widens WHICH receivers count, never what counts as
    caller-influenced."""
    assert not [f for f in _ssrf(bound) if "127.0.0.1" in (f.snippet or "")]


def test_exact_finding_count_on_the_bound_fixture(bound):
    """Eleven bound caller-influenced sinks. Twelve calls across the negative
    half (eleven decoys plus the one honest miss on the contested name) and
    one constant-URL control, all silent. A count that drifts up means the
    binding rule degraded into a name match."""
    assert len(_ssrf(bound)) == 11


def test_no_other_vuln_class_is_produced(bound):
    assert {f.vuln_class for f in bound.findings} == {"ssrf"}
