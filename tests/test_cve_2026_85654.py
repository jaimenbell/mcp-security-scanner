"""Regression pin for CVE-2026-85654 (GHSA-35jj-hwvm-792x, AWS as CNA).

The codegen-injection detector flagged awslabs/mcp's dynamodb-mcp-server CDK
generator (``cdk_generator/generator.py:48``) in the 2026-07-23 ecosystem scan
(``ecoscan-artifacts/report-awslabs_mcp.md``, finding ``4daab31b00b0``). A human
read of the flagged spot found that ``templates/stack.ts.j2`` interpolated
caller-supplied table and attribute names raw into single-quoted TypeScript
string literals. AWS reproduced it and fixed it in PR #4384 (merged 2026-08-13,
v2.1.6): every slot became ``{{ x | tojson }}``.

The fixtures are trimmed verbatim copies of the pre-fix (``cdd87a8``) and
post-fix (``46ca139``) source, Apache-2.0. They pin three things:

FIRES     the pre-fix shape produces exactly one P1 codegen-injection finding,
          on the ``Environment(`` line the report quoted.

BOUNDARY  the post-fix shape produces the SAME finding. The fix changed the
          template and left autoescape off -- which is correct for a code
          template, as the detector's own docstring says. The detector flags
          the surface (autoescape-off + a code-targeting template), not the
          bug: the interpolation-level discriminator (``_JINJA_EXPR`` /
          ``_SAFE_FILTERS`` / ``_expr_has_safe_filter``) is defined but not
          called from ``run()``. If this test starts failing, the detector has
          learned to tell the two apart -- update this test deliberately, and
          re-read the README's CVE paragraph, which must not claim more than
          the detector does.

SILENT    the hand-rolled-escape rule fires on neither shape; the AWS template
          never used ``replace(...)``. ``vuln_codegen`` trips both rules, so
          this is the first fixture that isolates the autoescape rule.
"""

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import CodegenInjectionDetector
from mcp_scanner.models import Severity

_TITLE = "Jinja autoescape disabled in a code-generating tool"
_EVIDENCE = "nosec B701"  # the exact snippet the ecosystem-scan report quoted
_RAW_SLOT = "'{{ table.table_name }}'"


def _codegen_findings(fixtures_dir, name):
    r = scan_repo(str(fixtures_dir / name), [CodegenInjectionDetector()])
    return [f for f in r.findings if f.vuln_class == "codegen-injection"]


def _template_text(fixtures_dir, name):
    return (fixtures_dir / name / "templates" / "stack.ts.j2").read_text(encoding="utf-8")


def _assert_the_cve_finding(cg):
    assert len(cg) == 1, (
        "expected exactly the Environment finding, got "
        f"{[(f.title, f.file, f.line) for f in cg]}"
    )
    (f,) = cg
    assert f.title == _TITLE
    assert f.severity == Severity.P1, "a code-targeting .ts.j2 is present, so this is the P1 branch"
    assert f.file.replace("\\", "/").endswith("generator.py")
    assert _EVIDENCE in f.snippet, f"finding must land on the flagged line; snippet was {f.snippet!r}"


def test_prefix_shape_is_the_vulnerable_template(fixtures_dir):
    t = _template_text(fixtures_dir, "cve_2026_85654_prefix")
    assert _RAW_SLOT in t, "pre-fix fixture must carry the raw quoted interpolation"
    assert t.count("| tojson") == 0


def test_postfix_shape_is_the_fixed_template(fixtures_dir):
    t = _template_text(fixtures_dir, "cve_2026_85654_postfix")
    assert _RAW_SLOT not in t
    assert t.count("| tojson") == 9, "PR #4384 escaped nine slots"


def test_prefix_shape_fires_p1(fixtures_dir):
    _assert_the_cve_finding(_codegen_findings(fixtures_dir, "cve_2026_85654_prefix"))


def test_postfix_shape_still_fires_same_finding_boundary(fixtures_dir):
    # See BOUNDARY in the module docstring before "fixing" this test.
    _assert_the_cve_finding(_codegen_findings(fixtures_dir, "cve_2026_85654_postfix"))


def test_neither_shape_trips_handrolled_escape(fixtures_dir):
    for name in ("cve_2026_85654_prefix", "cve_2026_85654_postfix"):
        titles = [f.title for f in _codegen_findings(fixtures_dir, name)]
        assert not any("Hand-rolled" in t for t in titles), f"{name}: {titles}"
