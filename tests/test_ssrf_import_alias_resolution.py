"""`ssrf` recall through an IMPORT ALIAS, and the scope that recall is bought in.

Fourth module in the ssrf set:

  test_ssrf_sink_surface.py       -- is a module-qualified call a sink?
  test_ssrf_client_bound_sinks.py -- is an instance-method call a sink?
  test_ssrf_verb_calibration.py   -- given a sink fired, is its severity right?
  this module                     -- does the sink survive being RENAMED?

Two mechanisms are under test and they are separate: sink-name
canonicalization (`hx.get` -> `httpx.get`) and constructor canonicalization
(`AsyncClient()` -> `httpx.AsyncClient`, which then proves a receiver). The
second is the one found in the wild -- the reference "fetch" MCP server
imports `AsyncClient` by symbol -- so a port that only did the first would
close the documented gap and still miss the real case.

Roughly half these tests pin SCOPE rather than recall, on purpose. A rule
whose entire job is to make more names match is the one that most needs its
boundary stated in the same change as its pattern: severity parity against
the unaliased spelling, the constant-URL and test-path gates still applying,
the module list still gating, and the two excluded forms (re-export hop,
relative import) proven silent rather than merely documented.
"""

import pytest

from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Severity
from mcp_scanner.scanner import scan_repo


@pytest.fixture
def aliased(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_http_alias"),
                     [ParamInjectionDetector()])


@pytest.fixture
def scope_boundary(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param_http_alias_scope"),
                     [ParamInjectionDetector()])


def _ssrf(result):
    return [f for f in result.findings if f.vuln_class == "ssrf"]


def _on(result, needle):
    """The single ssrf finding in server.py whose flagged line holds `needle`.

    Scoped to server.py because the fixture's test-path file repeats the same
    aliased calls; those are the subject of the carve-out test below.
    """
    hits = [f for f in _ssrf(result)
            if f.file == "server.py" and needle in (f.snippet or "")]
    assert len(hits) == 1, f"expected exactly one ssrf on {needle!r}, got {hits}"
    return hits[0]


def _parity(result, aliased_needle, control_needle):
    """Assert the aliased sink reports IDENTICALLY to the literal spelling.

    Parity against the control in the same file, not against a hardcoded
    constant: the claim is "resolving a rename changes nothing about the
    finding", and a constant could drift away from the control silently.
    """
    a = _on(result, aliased_needle)
    c = _on(result, control_needle)
    assert (a.severity, a.confidence) == (c.severity, c.confidence)
    return a


# --- recall: one test per alias form --------------------------------------

def test_module_alias_read_verb(aliased):
    """`import httpx as hx; hx.get(url)`."""
    assert _parity(aliased, "r_mod_read", "c_read").severity is Severity.P2


def test_module_alias_state_changing_verb(aliased):
    """`hx.put(url)` -- the verb calibration must see through the alias too,
    or resolving a rename would silently downgrade a P1 to a P2."""
    assert _parity(aliased, "r_mod_write", "c_write").severity is Severity.P1


def test_symbol_alias_renamed(aliased):
    """`from httpx import post as hx_post; hx_post(url)`."""
    assert _parity(aliased, "r_sym_write", "c_write").severity is Severity.P1


def test_symbol_alias_bare(aliased):
    """`from httpx import get; get(url)` -- no rename, but the surface is
    keyed by dotted name, so the bare local name still needs resolving."""
    assert _parity(aliased, "r_bare_read", "c_read").severity is Severity.P2


def test_module_chain_alias(aliased):
    """`import urllib.request as ur; ur.urlopen(url)`.

    The two-level dotted submodule. A port that copied `tool_scope_creep`'s
    bare single-token module list without adapting it would resolve this to
    `urllib` and match nothing. `urlopen` states no HTTP verb, so it keeps
    the base P2 -- exactly as the unaliased spelling does.
    """
    f = _on(aliased, "r_chain_read")
    assert (f.severity, f.confidence) == (Severity.P2, Confidence.MEDIUM)


def test_constructor_module_alias(aliased):
    """`c = hx.Client(); c.post(url)` -- the RECEIVER-BINDING path, which is a
    different mechanism from sink-name canonicalization and would be missed by
    porting `_resolved_sink_name` alone."""
    assert _parity(aliased, "r_ctor_mod", "c_write").severity is Severity.P1


def test_constructor_symbol_alias(aliased):
    """`from httpx import AsyncClient; c = AsyncClient(); c.get(url)` -- the
    one shape actually present in the 13-repo corpus."""
    assert _parity(aliased, "r_ctor_sym", "c_read").severity is Severity.P2


def test_constructor_symbol_alias_on_requests_session(aliased):
    """`from requests import Session; s = Session(); s.patch(url)`."""
    assert _parity(aliased, "r_ctor_sess", "c_write").severity is Severity.P1


def test_alias_resolution_does_not_move_confidence(aliased):
    """Alias resolution says what a name IS, never how sure we are the sink is
    real. Scoped to `server.py`: the `tests/` half is demoted to LOW by the
    reachability pass, which is that pass's own pre-existing test-path
    behaviour and is asserted as parity below, not here."""
    in_server = [f for f in _ssrf(aliased) if f.file == "server.py"]
    assert {f.confidence for f in in_server} == {Confidence.MEDIUM}


# --- scope: the existing gates still apply --------------------------------

def test_constant_url_under_an_alias_is_still_silent(aliased):
    """`_is_constant_str` is untouched: resolving a name says nothing about
    whether its URL is caller-influenced."""
    assert not [f for f in _ssrf(aliased)
                if "127.0.0.1:1/static" in (f.snippet or "")]


def test_test_path_still_withholds_the_escalation(aliased):
    """The carve-out has to reach alias-resolved matches exactly as it reaches
    literal ones. All three calls under `tests/` state a state-changing verb --
    one written literally, two through an alias. All three must report, all
    three must stay at the base P2 with the tag, and (per README's one law) the
    path may never suppress the finding itself."""
    in_tests = [f for f in _ssrf(aliased) if "tests/" in f.file]
    assert len(in_tests) == 3, f"finding must not be dropped, got {in_tests}"
    assert {f.severity for f in in_tests} == {Severity.P2}
    assert all("test-path" in f.detail for f in in_tests)


def test_test_path_demotion_treats_aliased_and_literal_alike(aliased):
    """Parity under the carve-out: the aliased pair must carry the SAME
    confidence and reachability grade the literal control on the same path
    gets. A resolver that bought recall by routing around the test-path pass
    would show up here as a split."""
    in_tests = [f for f in _ssrf(aliased) if "tests/" in f.file]
    assert len({(f.confidence, f.reachability) for f in in_tests}) == 1


# --- scope: what alias resolution must NOT reach --------------------------

def test_an_alias_of_a_non_sink_is_not_a_sink(aliased):
    """`hx.Headers(url)` resolves to `httpx.Headers`, which is on the module
    list and is not in the sink surface. Resolution recovers renames of names
    ALREADY in that surface; it never adds one."""
    assert not [f for f in _ssrf(aliased) if "Headers" in (f.snippet or "")]


def test_a_module_off_the_list_resolves_to_nothing(aliased):
    """`import flask as fl; fl.get(url)`. The fixed module list is the gate --
    this is the assertion that fails first if it ever becomes a general
    import graph."""
    assert not [f for f in _ssrf(aliased) if "fl.get(" in (f.snippet or "")]


def test_re_export_hop_is_not_resolved(scope_boundary):
    """A same-repo wrapper re-exporting `get`/`AsyncClient` is a cross-file
    import chain, not an alias, and is an explicit non-goal. Stated as a
    boundary so widening the module list into a general import graph fails a
    test instead of silently enlarging the report."""
    assert not [f for f in _ssrf(scope_boundary) if f.file == "tool.py"]


def test_relative_import_is_not_resolved(scope_boundary):
    """`from .httpx import post` -- `ast` reports the module as plain "httpx",
    the exact spelling the list admits. Only the explicit `node.level` check
    keeps this repo's own `httpx.py` from being read as the package."""
    assert not [f for f in _ssrf(scope_boundary) if f.file == "rel_tool.py"]


def test_the_scope_fixture_is_entirely_clean(scope_boundary):
    """Both excluded forms, both directions, nothing else leaking either."""
    assert scope_boundary.findings == []


# --- scope: the count, so drift is visible --------------------------------

def test_exact_finding_count_on_the_alias_fixture(aliased):
    """Three unaliased controls plus ten aliased sinks (two module-alias, one
    symbol-alias-renamed, one bare symbol, one module-chain, three
    constructor-bound, two under `tests/`). Four silent controls. A count that
    drifts up means resolution stopped being a rename lookup."""
    assert len(_ssrf(aliased)) == 13


def test_no_other_vuln_class_is_touched(aliased):
    """Alias resolution is bound to the `ssrf` branch of `_check_call`.
    Nothing else in the fixture may move."""
    assert {f.vuln_class for f in aliased.findings} == {"ssrf"}
