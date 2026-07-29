r"""Path-shape CLI_ONLY fallback: a test harness is not a tool entrypoint.

FROM THE 2026-07-29 HELD-OUT MEASUREMENT (0 true / 58 findings on 5 pinned
third-party MCP servers). Class (iv) -- "test harness treated as production
attack surface" -- was ~30 of the 58:

* airtable ``src/e2e.test.ts`` -- 6 ``execSync`` P1s and 1 SSRF, all vitest
  harness code (``testDir`` is a string literal declared one line above).
* firecrawl ``tests/mcp-smoke.test.mjs`` / ``tests/mcp-search-profile.test.mjs``
  -- 18 SSRFs, every one a ``fetch(\`http://127.0.0.1:${port}/...\`)`` against
  a locally-spawned test server.
* neon ``mcp/__tests__/refresh-concurrency.bench.test.ts`` -- 2 SSRFs.

THE FIX IS REUSE, NOT A NEW MECHANISM. ``Reachability.CLI_ONLY`` already
means, in its own enum docstring, "has a real caller, but every found caller
traces to a non-tool entrypoint (argv/CLI-main, **a test file**, an admin
script) -- never a registered MCP tool". The Python AST pass has emitted it
since 2026-07-22. All that was missing is that a non-Python surface never
reached that branch at all. So a test/spec path now selects CLI_ONLY as a
FALLBACK, which brings with it two behaviours already built and tested:
the ``_LOWER`` confidence nudge, and exclusion from the ``--fail-on`` gate
unless ``--include-cli-only-in-gate`` is passed.

SCOPE, STATED WITH THE PATTERN: the fallback fires ONLY where the AST pass
returned UNKNOWN. It can never override REACHABLE / CLI_ONLY / UNCALLED
decided by real call-graph evidence -- path shape is the weakest evidence in
this module and must never outrank the strongest. The test-path Python case
below pins exactly that ordering.
"""
from pathlib import Path

import pytest

from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Reachability
from mcp_scanner.scanner import scan_repo


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    """A minimal TS MCP server: one registered tool, one production module
    with a real sink, and the three test-harness shapes from the measurement.

    Every flagged line is a DIFFERENT command/URL string so a finding can be
    located by its own snippet and no assertion can pass by matching the
    wrong one.
    """
    _write(tmp_path, "server.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.tool("fetch_doc", async ({ slug }) => await getDoc(slug));
""".lstrip())
    # Production surface -- must stay UNGRADED/UNKNOWN, never CLI_ONLY.
    _write(tmp_path, "src/monitor.ts", """
export async function getDoc(slug) {
  return await fetch(prodUrl + slug);
}
""".lstrip())
    # (a) test file beside its subject -- the airtable e2e.test.ts shape.
    # The child_process import is what makes the execSync line a P1
    # shell-injection finding (the ONLY P1 in this repo), which the gate
    # assertion below depends on.
    _write(tmp_path, "src/e2e.test.ts", """
import {execSync} from 'node:child_process';
const testDir = 'test-mcpb-client';
execSync(`rm -rf ${testDir} && echo shellsink-in-harness`);
await fetch(`http://127.0.0.1:${port}/harness-beside-subject`);
""".lstrip())
    # (b) tests/ directory -- the firecrawl shape.
    _write(tmp_path, "tests/mcp-smoke.test.mjs", """
await fetch(`http://127.0.0.1:${port}/harness-in-tests-dir`);
""".lstrip())
    # (c) __tests__/ directory -- the neon shape.
    _write(tmp_path, "mcp/__tests__/bench.test.ts", """
await fetch(`http://127.0.0.1:${port}/harness-in-dunder-tests`);
""".lstrip())
    return scan_repo(str(tmp_path), [ParamInjectionDetector()])


def _one(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, (
        f"expected exactly one finding containing {needle!r}, got "
        f"{[(h.file, h.line, h.snippet) for h in hits]}"
    )
    return hits[0]


@pytest.mark.parametrize("needle", [
    "harness-beside-subject",
    "harness-in-tests-dir",
    "harness-in-dunder-tests",
])
def test_js_test_harness_findings_grade_cli_only(repo, needle):
    f = _one(repo, needle)
    assert f.reachability is Reachability.CLI_ONLY, (
        f"{f.file}:{f.line} is a test harness; it must not be graded as "
        f"unknown production surface (got {f.reachability})"
    )
    assert "test" in f.reachability_evidence.lower(), (
        "the grade must carry evidence naming WHY, not just a bare label"
    )


def test_js_production_surface_is_not_swept_up(repo):
    """The recall half. A rule that returned CLI_ONLY for every JS file would
    pass every assertion above -- this is the one that proves it discriminates.
    ``src/monitor.ts`` is a real production module and must stay ungraded."""
    f = _one(repo, "prodUrl")
    assert f.reachability is Reachability.UNKNOWN, (
        "a production .ts module has no call-graph and must stay honestly "
        f"UNKNOWN, never CLI_ONLY on path shape (got {f.reachability})"
    )
    assert f.reachability_evidence == ""


def test_cli_only_lowers_confidence_via_the_existing_nudge(repo):
    """CLI_ONLY has always applied the ``_LOWER`` table. The JS SSRF findings
    are emitted at MEDIUM by the detector, so the graded result must be LOW --
    a DIFFERENT value from the detector's own, so this cannot pass vacuously."""
    f = _one(repo, "harness-in-tests-dir")
    assert f.confidence is Confidence.LOW


def test_path_shape_never_overrides_a_real_call_graph_grade(tmp_path):
    """SCOPE PIN. A Python sink inside a registered tool handler is REACHABLE
    on hard call-graph evidence. Putting that same file at a test path must
    NOT downgrade it to CLI_ONLY -- the fallback fires only where the AST pass
    said UNKNOWN. Without this ordering, the weakest evidence in the module
    would outrank the strongest."""
    _write(tmp_path, "tests/test_server.py", '''
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool()
def run(cmd: str):
    subprocess.run("graded-by-callgraph " + cmd, shell=True)
'''.lstrip())
    result = scan_repo(str(tmp_path), [ParamInjectionDetector()])
    f = _one(result, "graded-by-callgraph")
    assert f.reachability is Reachability.REACHABLE, (
        "a call-graph-proven REACHABLE grade must survive the file sitting at "
        f"a test path (got {f.reachability})"
    )


def test_cli_only_findings_are_excluded_from_the_fail_on_gate_by_default(repo):
    """The consequence that makes this reuse worth having: the P1 exec finding
    in a test harness no longer fails a CI gate, while the opt-in flag still
    counts it. Both directions asserted so neither can pass vacuously.

    Gated at P1, not P2, on purpose: the repo's only P1 is the test-harness
    ``execSync``, whereas ``src/monitor.ts``'s production SSRF is a P2 that
    SHOULD keep failing a P2 gate. Asserting at P2 would have conflated "the
    harness stopped gating" with "nothing gates any more"."""
    from mcp_scanner.cli import _exit_code

    p1s = [f for f in repo.findings if f.severity.value == "P1"]
    assert len(p1s) == 1 and p1s[0].file == "src/e2e.test.ts", (
        f"fixture drift: expected exactly one P1 (the harness execSync), got {p1s}"
    )
    assert _exit_code([repo], "P1", include_cli_only=False) == 0
    assert _exit_code([repo], "P1", include_cli_only=True) == 2
    # And the production P2 still gates, in both modes -- the carve-out is
    # scoped to the harness, not to the repo.
    assert _exit_code([repo], "P2", include_cli_only=False) == 2
