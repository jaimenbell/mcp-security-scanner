r"""The grade axis: a report must say which findings were never graded.

THE PRODUCT DEFECT THIS FIXES (2026-07-29 held-out measurement, 0 true / 58
findings across 5 pinned third-party MCP servers):

    reachability.py and taint.py both bail unless the file is .py/.pyw. Every
    JS/TS finding therefore came back reachability=unknown, taint=unknown --
    raw regex output with no precision layer applied at all. But the report
    rendered it IDENTICALLY to a properly-graded Python finding: same severity
    badge, same confidence, no visible difference. A client reading the report
    could not tell that four P0s rested on a regex match and nothing else.

    MCP servers skew TypeScript -- 4 of the 5 sampled -- so this was not an
    edge case, it was the common case.

THE RULE (language-agnostic on purpose, so it cannot drift the way a
per-language special case would): a finding is UNGRADED when BOTH precision
axes came back UNKNOWN, i.e. nothing whatsoever was established beyond the
pattern match. That is true of every JS/TS finding, and equally true of a
Python finding in a repo with no discoverable tool registrations -- which is
honest, because in both cases the answer really is "we established nothing".

THE SEVERITY CAP, AND ITS SCOPE (stated together, never apart -- a rule
shipped without its scope silently defaults to "everywhere"):

    Capping is scoped to the DATAFLOW classes, the same set taint.py already
    owns: shell-injection, code-eval, unsafe-deserialization, ssrf,
    path-traversal. For those, "P0 = exploitable now, no preconditions" is
    precisely a claim that caller-controlled data reaches a sink -- the claim
    taint exists to establish. Without it, P0 is unearned, so an ungraded
    dataflow finding is capped at P2/LOW.

    It is NOT applied to hardcoded-secret, secret-in-log, auth-posture,
    job-* or tool-scope-creep. A committed AWS key is a P1 whether or not any
    tool reaches it; its severity never rested on a reachability claim, so
    capping it would be dishonest in the OTHER direction and would lose real
    recall. Pinned below in both directions.

Nothing is ever dropped. The over-flag philosophy and README's one law stand:
this labels, caps and explains -- it does not suppress.
"""
from pathlib import Path

import pytest

from mcp_scanner.detectors import ParamInjectionDetector, SecretHandlingDetector
from mcp_scanner.models import Confidence, Grade, ScanResult, Severity
from mcp_scanner.scanner import scan_repo


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def ts_repo(tmp_path):
    """A TypeScript MCP server -- the shape 4 of the 5 measured repos had."""
    _write(tmp_path, "server.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.tool("fetch_doc", async ({ slug }) => await getDoc(slug));
""".lstrip())
    _write(tmp_path, "src/monitor.ts", """
export async function getDoc(slug) {
  return await fetch(prodUrl + "/ungraded-ssrf-sink/" + slug);
}
export function build(x) { return new Function("return " + x); }
""".lstrip())
    return scan_repo(str(tmp_path), [ParamInjectionDetector()])


@pytest.fixture
def py_repo(tmp_path):
    """A Python MCP server whose sink IS reachable from a registered tool --
    the graded control. Without this half, every assertion about UNGRADED
    could be satisfied by labelling everything ungraded."""
    _write(tmp_path, "server.py", '''
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool()
def run(cmd: str):
    subprocess.run("graded-shell-sink " + cmd, shell=True)
'''.lstrip())
    return scan_repo(str(tmp_path), [ParamInjectionDetector()])


def _one(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, (
        f"expected one finding containing {needle!r}, got "
        f"{[(h.file, h.line) for h in hits]}"
    )
    return hits[0]


# --- the label itself ------------------------------------------------------
def test_typescript_finding_is_labelled_ungraded(ts_repo):
    f = _one(ts_repo, "ungraded-ssrf-sink")
    assert f.grade is Grade.UNGRADED
    assert f.grade_reason, "an ungraded finding must carry a stated reason"
    assert ".ts" in f.grade_reason, (
        "the reason must name the actual surface that could not be graded, "
        f"not a generic string (got {f.grade_reason!r})"
    )


def test_reachable_python_finding_is_labelled_graded(py_repo):
    """The control. A DIFFERENT expected value from the ts_repo case, so a
    constant-returning implementation fails one of the two."""
    f = _one(py_repo, "graded-shell-sink")
    assert f.grade is Grade.GRADED
    assert f.grade_reason == ""


# --- the severity cap, and its scope --------------------------------------
def test_ungraded_dataflow_finding_is_capped_at_p2_low(ts_repo):
    """`new Function(...)` is emitted by the detector at P0/HIGH. Ungraded, it
    must not keep a P0. Asserting against the detector's OWN emitted values
    (P0/HIGH) rather than a copy of the expected ones."""
    f = _one(ts_repo, "new Function")
    assert f.vuln_class == "code-eval"
    assert f.severity is Severity.P2, (
        "an ungraded regex hit cannot claim P0 'exploitable now' -- that is a "
        f"taint claim, and no taint pass ran (got {f.severity})"
    )
    assert f.confidence is Confidence.LOW


def test_graded_dataflow_finding_keeps_its_severity(py_repo):
    """The cap must be a consequence of being ungraded, not a blanket
    downgrade of the dataflow classes."""
    f = _one(py_repo, "graded-shell-sink")
    assert f.severity is Severity.P1, (
        f"a call-graph-graded finding keeps its severity (got {f.severity})"
    )


def test_cap_is_not_applied_to_hardcoded_secret(tmp_path):
    """SCOPE PIN, and the direction that costs real recall if botched. A
    genuine AWS key committed in a .ts file is ungraded (no JS call-graph
    exists) but its P1 never rested on a reachability claim, so it must keep
    P1 -- and must NOT be forced to LOW confidence either."""
    _write(tmp_path, "server.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.tool("noop", async () => 1);
""".lstrip())
    _write(tmp_path, "src/config.ts", """
export const creds = { accessKeyId: "AKIAQ7Z3K9XLMNPRSTUV" };
""".lstrip())
    result = scan_repo(str(tmp_path), [SecretHandlingDetector()])
    hits = [f for f in result.findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a value-shaped AWS key in a .ts file must still be reported"
    f = hits[0]
    assert f.grade is Grade.UNGRADED, "it IS ungraded -- say so"
    assert f.severity is Severity.P1, (
        "but a committed credential's severity never depended on reachability; "
        f"capping it would lose real recall (got {f.severity})"
    )
    assert f.confidence is not Confidence.LOW


# --- per-run coverage ------------------------------------------------------
def test_result_reports_which_files_could_not_be_graded(ts_repo):
    cov = ts_repo.coverage
    assert cov["findings_ungraded"] > 0
    assert cov["ungradable_files"] >= 2, (
        "server.ts and src/monitor.ts are both ungradable surfaces"
    )
    assert cov["gradable_files"] == 0
    reasons = cov["ungradable_files_by_reason"]
    assert reasons, "coverage must say WHY, not just how many"
    assert any(".ts" in r for r in reasons), reasons


def test_python_repo_reports_full_grading_coverage(py_repo):
    cov = py_repo.coverage
    assert cov["gradable_files"] == 1
    assert cov["ungradable_files"] == 0
    assert cov["findings_ungraded"] == 0


# --- the actual product defect: the report must SHOW it --------------------
def test_markdown_report_marks_ungraded_findings_and_states_coverage(ts_repo):
    from mcp_scanner.reporting import render_markdown

    md = render_markdown(ts_repo)
    assert "ungraded" in md.lower()
    assert "Grading coverage" in md, (
        "a per-run coverage section is required: the reader must be able to "
        "see WHICH files could not be graded and why"
    )
    assert ".ts" in md


def test_client_report_marks_ungraded_findings(ts_repo):
    from mcp_scanner.client_report import render_client_report

    md = render_client_report(ts_repo, client_name="Acme")
    assert "ungraded" in md.lower()
    assert "Grading coverage" in md


def test_graded_report_does_not_cry_ungraded(py_repo):
    """The other direction: a fully-graded Python scan must not carry the
    ungraded caveat, or the warning becomes noise everyone learns to skip."""
    from mcp_scanner.reporting import render_markdown

    md = render_markdown(py_repo)
    assert "UNGRADED" not in md
    assert "could not be graded" not in md


def test_json_carries_grade_and_coverage(ts_repo):
    d = ts_repo.to_dict()
    assert "coverage" in d
    assert all("grade" in f and "grade_reason" in f for f in d["findings"])
    assert any(f["grade"] == "ungraded" for f in d["findings"])


def test_clean_bill_on_an_ungradable_repo_is_not_presented_as_assurance(tmp_path):
    """The mirror-image failure. Capping ungraded dataflow findings to P2 can
    turn a TypeScript repo into a 'clean bill' -- which would be a FALSE
    assurance, since the clean part is the part we could not analyse. The
    report must qualify it."""
    from mcp_scanner.reporting import render_markdown

    _write(tmp_path, "server.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.tool("go", async ({ u }) => await fetch(u));
""".lstrip())
    result = scan_repo(str(tmp_path), [ParamInjectionDetector()])
    assert result.clean_bill, "fixture drift: expected no P0/P1 here"
    md = render_markdown(result)
    assert "Clean bill" in md
    assert "could not be graded" in md, (
        "a clean bill over an ungradable surface must say so in the same "
        "callout, not bury it lower in the report"
    )


def test_report_generator_marks_ungraded_in_markdown_and_html(ts_repo, tmp_path):
    """The client-grade deliverable (`mcp-scan report <scan.json>`) renders
    from scan JSON, so it needs its own pin -- the two renderers above go
    straight from the ScanResult object and would not catch a JSON-path gap."""
    import json

    from mcp_scanner import report_generator as rg

    p = tmp_path / "scan.json"
    p.write_text(json.dumps(ts_repo.to_dict()), encoding="utf-8")
    model = rg.build_report_model(rg.load_scan(p), {}, client="Acme",
                                  engagement="e", scope="s",
                                  annotations_name="")
    md = rg.render_markdown_report(model)
    html = rg.render_html_report(model)
    assert "**UNGRADED**" in md and "Not graded because" in md
    assert "<strong>UNGRADED</strong>" in html and "grade: ungraded" in html


def test_report_generator_defaults_pre_grade_scan_json_to_graded(tmp_path):
    """Backward compatibility: a scan JSON produced before the grade axis
    existed has no 'grade' key and must never be retro-labelled UNGRADED --
    that would put a warning on findings nobody ever assessed for it."""
    import json

    from mcp_scanner import report_generator as rg

    legacy = {
        "target": "x", "files_scanned": 1,
        "counts_by_severity": {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        "clean_bill": False, "errors": [],
        "findings": [{
            "finding_id": "abc123", "vuln_class": "ssrf", "title": "t",
            "severity": "P1", "confidence": "high", "file": "a.py", "line": 3,
            "detail": "d", "remediation": "r", "snippet": "",
            "reachability": "unknown", "reachability_evidence": "",
            "taint": "unknown",
        }],
    }
    p = tmp_path / "legacy.json"
    p.write_text(json.dumps(legacy), encoding="utf-8")
    model = rg.build_report_model(rg.load_scan(p), {}, client="Acme",
                                  engagement="e", scope="s",
                                  annotations_name="")
    md = rg.render_markdown_report(model)
    assert "**Grade:** graded" in md
    assert "UNGRADED" not in md


def test_summary_line_surfaces_the_ungraded_count(ts_repo):
    from mcp_scanner.reporting import render_summary_line

    assert "ungraded" in render_summary_line(ts_repo).lower()


# --- the grade rule cannot silently diverge from taint's class set ---------
def test_capped_classes_are_exactly_taints_dataflow_classes():
    from mcp_scanner import grading
    from mcp_scanner.taint import _DATAFLOW_CLASSES

    assert grading._CAPPED_CLASSES is _DATAFLOW_CLASSES, (
        "the capped set must BE taint's dataflow set, not a copy that can "
        "drift out of sync with the pass whose absence justifies the cap"
    )


def test_hand_built_scanresult_still_works():
    """Every field added here must be optional -- ScanResult/Finding are
    constructed by hand in dozens of existing tests and by report_generator."""
    r = ScanResult(target="x")
    assert r.coverage == {}
    assert r.to_dict()["coverage"] == {}
