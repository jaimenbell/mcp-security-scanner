"""Regression pin for CVE-2026-85654 (GHSA-35jj-hwvm-792x, AWS as CNA).

The codegen-injection detector flagged awslabs/mcp's dynamodb-mcp-server CDK
generator (``cdk_generator/generator.py:48``) in the 2026-07-23 ecosystem scan:
finding ``4daab31b00b0``, recorded in ``docs/ECOSYSTEM-SCAN-2026-08-03-AUDIT-66.md``
(file:line in ``docs/ECOSYSTEM-SCAN-2026-08-03.md``). A human read of the
flagged spot found that ``templates/stack.ts.j2`` interpolated caller-supplied
table and attribute names raw into single-quoted TypeScript string literals.
AWS reproduced it and fixed it in PR #4384 (merged 2026-08-13, v2.1.6): the
nine string-literal slots became ``{{ x | tojson }}``; identifier-position
slots (the class name, camel/pascal-cased names, enum members) were covered by
parse-time validation instead and stay bare.

The fixtures are trimmed verbatim copies of the pre-fix (``cdd87a8``) and
post-fix (``46ca139``) source. Apache-2.0; license and NOTICE in
``tests/fixtures/third_party/awslabs-mcp/``. They pin three things:

FIRES     the pre-fix shape produces exactly one P1 codegen-injection finding
          at detector level, on the ``Environment(`` line the report quoted.

BOUNDARY  the post-fix shape produces the SAME detector-level finding. The fix
          changed the template and left autoescape off -- correct for a code
          template, as the detector's own docstring says. The detector's rule
          is autoescape-off + a code-targeting template present; it flags the
          surface, not the bug. The interpolation-level discriminator
          (``_JINJA_EXPR`` / ``_SAFE_FILTERS`` / ``_expr_has_safe_filter``) is
          defined but not called from ``run()``. In a full scan the grading
          pass reports this finding UNGRADED (reachability and taint undecided),
          so the P1 asserted here is the detector's grade, not the report's.
          This is a characterization pin: if it starts failing, the detector
          has learned to tell the two apart -- update it deliberately, and
          re-read the README's CVE paragraph, which must not claim more than
          the detector does. Anyone wiring the discriminator: string-literal
          position must be detected (identifier slots are legitimately bare),
          and ``_expr_has_safe_filter``'s bare ``|e`` substring would score
          ``| equalto`` as safe.

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


def _body_after_header(path):
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    i = 0
    while i < len(lines) and lines[i].startswith("#"):
        i += 1
    return "".join(lines[i:])


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
    assert t.count("| tojson") == 9, "PR #4384 serialized nine string-literal slots"


def test_prefix_and_postfix_generators_are_identical_after_header(fixtures_dir):
    # The pair's premise is "same generator, different template". Keep it true.
    a = _body_after_header(fixtures_dir / "cve_2026_85654_prefix" / "generator.py")
    b = _body_after_header(fixtures_dir / "cve_2026_85654_postfix" / "generator.py")
    assert a == b


def test_prefix_shape_fires_p1(fixtures_dir):
    _assert_the_cve_finding(_codegen_findings(fixtures_dir, "cve_2026_85654_prefix"))


def test_postfix_shape_still_fires_same_finding_boundary(fixtures_dir):
    # See BOUNDARY in the module docstring before "fixing" this test.
    _assert_the_cve_finding(_codegen_findings(fixtures_dir, "cve_2026_85654_postfix"))


def test_neither_shape_trips_handrolled_escape(fixtures_dir):
    for name in ("cve_2026_85654_prefix", "cve_2026_85654_postfix"):
        titles = [f.title for f in _codegen_findings(fixtures_dir, name)]
        assert not any("Hand-rolled" in t for t in titles), f"{name}: {titles}"
