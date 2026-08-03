r"""Best-effort cross-file NAME edges must not make a test double REACHABLE.

FROM THE 2026-08-03 HAND-AUDIT of the 66 gate-qualifying findings in the
published ecosystem scan. **Two of the three P0s in the entire 66 were this
one bug**, both in ``PrefectHQ/fastmcp``:

* ``tests/experimental/transforms/test_code_mode.py:112``
* ``tests/experimental/transforms/test_code_mode_discovery.py:76``

Both are byte-identical copies of ``_UnsafeTestSandboxProvider``, whose own
docstring reads "UNSAFE: Uses exec() for testing only. Never use in
production." The shipped wheel contains ZERO ``exec`` calls -- fastmcp's
``pyproject.toml`` sets ``only-include = []`` / ``exclude = ["/*"]``, so
``tests/`` and ``examples/`` ship nothing at all. There is no attack path.

WHY THE EXISTING TEST-PATH FALLBACK DID NOT SAVE US. ``CallGraph.reachable_from``
follows a callee by SHORT NAME repo-wide ("deliberately generous", its own
docstring). Production ``sandbox_provider.run(`` at ``code_mode.py:626`` is
rooted in a registered tool, so EVERY function named ``run`` anywhere in the
repo -- including both test doubles -- lands in ``reachable_ids``. ``_grade_one``
then consults ``_grade_ast`` FIRST and treats a decided answer as final, so the
``is_test_path() -> CLI_ONLY`` fallback added on 2026-07-29 is structurally
unable to fire. It never gets asked.

That is not cosmetic. REACHABLE also triggers the ``_RAISE`` confidence nudge
(both findings were promoted a tier) while CLI_ONLY carries the ``--fail-on``
exclusion -- so the bug inflates severity AND defeats the suppression in one
step, which is exactly how a test double reached a P0 slot in a published
report.

SCOPE, STATED WITH THE PATTERN (the rule this repo keeps re-learning): the
downgrade fires ONLY when BOTH hold -- the sink is reachable *solely* through
best-effort cross-file name edges (no exact same-file resolution anywhere on
any path from a root), AND the file is a test path. A sink reached by an
exactly-resolved same-file edge is untouched, at any path. Production recall
is therefore unchanged, which ``test_production_sink_stays_reachable`` and the
scope pin in ``test_reachability_test_path_fallback.py`` both hold us to.
"""
from pathlib import Path

import pytest

from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Reachability
from mcp_scanner.scanner import scan_repo


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    """The fastmcp shape, reduced: a registered tool calls ``run`` across a
    file boundary, and a test double in ``tests/`` defines a same-named ``run``
    holding the dangerous sink.

    Each ``exec`` argument is a DIFFERENT variable name so a finding can be
    located by its own snippet and no assertion can pass by matching the other.
    """
    _write(tmp_path, "server.py", '''
from mcp.server.fastmcp import FastMCP
from sandbox import run

mcp = FastMCP("demo")


@mcp.tool()
def code_mode(payload: str):
    """Registered tool root. Calls ``run`` ACROSS a file boundary, which is
    what promotes every repo-wide ``run`` into reachable_ids."""
    return run(payload)
'''.lstrip())
    # Production sandbox: the real implementation, reached by a genuine edge.
    _write(tmp_path, "sandbox.py", '''
def run(prod_code):
    exec(prod_code)
'''.lstrip())
    # The unsafe TEST DOUBLE -- same short name, never shipped, never called
    # by anything but the test module. This is the fastmcp finding verbatim.
    _write(tmp_path, "tests/test_code_mode.py", '''
class _UnsafeTestSandboxProvider:
    """UNSAFE: Uses exec() for testing only. Never use in production."""

    def run(self, double_code):
        exec(double_code)
'''.lstrip())
    return scan_repo(str(tmp_path), [ParamInjectionDetector()])


def _one(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, (
        f"expected exactly one finding containing {needle!r}, got "
        f"{[(h.file, h.line, h.snippet) for h in hits]}"
    )
    return hits[0]


def test_test_double_reached_only_by_name_edge_is_not_reachable(repo):
    """THE REGRESSION. Before the fix this graded REACHABLE, because the
    production ``run(payload)`` call promoted every repo-wide ``run``."""
    f = _one(repo, "double_code")
    assert f.reachability is not Reachability.REACHABLE, (
        f"{f.file}:{f.line} is an unshipped test double reached ONLY by a "
        f"best-effort cross-file name guess; grading it REACHABLE is what put "
        f"two test doubles into P0 slots in a published report "
        f"(got {f.reachability})"
    )
    assert f.reachability is Reachability.CLI_ONLY, (
        "it should land on the existing CLI_ONLY test-path fallback, which "
        f"carries the --fail-on exclusion (got {f.reachability})"
    )
    assert "test" in f.reachability_evidence.lower(), (
        "the grade must carry evidence naming WHY, not just a bare label"
    )


def test_production_sink_stays_reachable(repo):
    """THE RECALL HALF, and the one that proves the fix discriminates. A rule
    that downgraded everything would pass the assertion above. ``sandbox.run``
    is genuinely called by a registered tool and must stay REACHABLE."""
    f = _one(repo, "prod_code")
    assert f.reachability is Reachability.REACHABLE, (
        "the real sandbox implementation IS reached from a registered tool "
        f"root; the fix must not cost production recall (got {f.reachability})"
    )


def test_the_gate_excludes_the_double_but_not_production(repo):
    """End-to-end consequence: this is the number the published report quotes.
    CLI_ONLY is excluded from the default --fail-on gate; REACHABLE is not."""
    double = _one(repo, "double_code")
    prod = _one(repo, "prod_code")
    gated = [f for f in (double, prod)
             if f.reachability is not Reachability.CLI_ONLY]
    assert gated == [prod], (
        "exactly one of these two belongs in the gate queue -- the production "
        f"sink. Got {[(g.file, g.line) for g in gated]}"
    )
