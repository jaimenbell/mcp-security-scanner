"""Tests for mcp_scanner/client_report.py -- the 8-section client-facing
consulting report (Phase 0 report upgrade, ports reliability-retainer's
tools/report.py *structure*, not its code -- see mcp-security-scanner-
retainer-spec-2026-07-16.md §3).

Asserts the 8 sections are present, the perceived-value deltas (exec
summary in plain incident language rather than raw vuln_class ids, top-3,
remediation + confidence columns, a reproducible proof for every P0, the
verbatim capability statement including the honest not-yet-built-detectors
disclosure), the framing rules (counts generated not hand-typed), and the
structural zero-effector rail (this module only reads a ScanResult and
returns a string).
"""
from __future__ import annotations

from mcp_scanner.models import ScanResult, Finding, Severity, Confidence
from mcp_scanner import client_report


def _finding(sev, vuln_class="codegen-injection", conf=Confidence.HIGH,
             file="app.py", line=10, title="unsafe autoescape",
             detail="Jinja autoescape is off in a code-generating tool.",
             remediation="Use a real serializer or enable autoescape."):
    return Finding(
        vuln_class=vuln_class, title=title, severity=sev, confidence=conf,
        file=file, line=line, detail=detail, remediation=remediation,
        snippet="env = Environment(autoescape=False)",
    )


def _sample_result():
    r = ScanResult(target="/repos/acme-mcp-server", files_scanned=12)
    r.add(_finding(Severity.P0, vuln_class="codegen-injection", file="gen.py", line=8,
                    title="autoescape disabled in codegen tool",
                    detail="A code-generating tool renders untrusted fields with "
                           "Jinja autoescape off -- injected markup lands verbatim "
                           "in generated source.",
                    remediation="Enable autoescape or use a real serializer."))
    r.add(_finding(Severity.P1, vuln_class="param-injection", file="sinks.py", line=22,
                    conf=Confidence.MEDIUM, title="subprocess shell=True",
                    detail="A tool handler shells out with shell=True on a "
                           "caller-influenced argument.",
                    remediation="Use subprocess with a list of args, shell=False."))
    r.add(_finding(Severity.P2, vuln_class="auth-posture", file="server.py", line=40,
                    conf=Confidence.LOW, title="no rate limiter",
                    detail="Networked server has no visible rate limiter.",
                    remediation="Add a rate limiter in front of the mutating routes."))
    return r


# --------------------------------------------------------------------- #
# The 8 sections
# --------------------------------------------------------------------- #

def test_report_has_all_eight_sections():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    assert "# MCP Server Security Audit -- Acme" in out       # 1 header
    assert "## 1. Executive summary" in out                    # 2
    assert "## 2. Top 3 to fix" in out                          # 3
    assert "## 3. Findings by severity" in out                 # 4
    assert "## 4. Critical evidence appendix" in out           # 5
    assert "## 5. Detector-class reference" in out             # 6
    assert "## 6. Scope & method" in out                        # 7
    assert "## 7. Ranked fix-lane plan" in out                 # 8


def test_header_states_readonly_and_scope_boundary():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    assert "Read-only static scan" in out
    assert "modified, deleted, or executed" in out
    assert "Scope boundary:" in out


def test_exec_summary_uses_incident_language_not_raw_vuln_class_id():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    summary = out.split("## 1. Executive summary")[1].split("## 2.")[0]
    assert "autoescape" in summary.lower() or "codegen" in summary.lower()
    assert "codegen-injection" not in summary  # id stays out of the lead sentence


def test_top3_lists_at_most_three_highest_severity():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    top = out.split("## 2. Top 3 to fix")[1].split("## 3.")[0]
    assert "1. **[P0]" in top
    assert "`gen.py:8`" in top
    assert "_Fix:_" in top


def test_findings_table_has_remediation_and_confidence_columns():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    assert "Remediation" in out and "Confidence" in out
    assert "shell=False" in out  # remediation column rendered
    assert "medium" in out       # confidence value rendered


def test_every_p0_has_a_reproducible_proof():
    result = _sample_result()
    out = client_report.render_client_report(result, client_name="Acme")
    appendix = out.split("## 4. Critical evidence appendix")[1].split("## 5.")[0]
    p0s = [f for f in result.findings if f.severity == Severity.P0]
    assert p0s, "sample should have a P0 finding to prove the rule"
    assert appendix.count("**Reproducible proof:**") == len(p0s)
    for f in p0s:
        assert f"`{f.file}:{f.line}`" in appendix


def test_no_p0_findings_says_so_plainly():
    r = ScanResult(target="/repos/clean-mcp-server", files_scanned=5)
    r.add(_finding(Severity.P2))
    out = client_report.render_client_report(r, client_name="Acme")
    appendix = out.split("## 4. Critical evidence appendix")[1].split("## 5.")[0]
    assert "No P0" in appendix or "no p0" in appendix.lower()


def test_scope_method_quotes_capability_statement_and_discloses_gap():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    assert client_report.CAPABILITY_STATEMENT in out
    # tool-scope-creep and secret-leak-via-tool-response shipped 2026-07-19
    # and are now BUILT detectors -- they must appear in the built-detector
    # table, not the not-yet-built disclosure.
    assert "tool-scope-creep" in out
    assert "secret-leak-via-tool-response" in out
    built = out.split("**Built and checked in this scan:**")[1].split("**NOT yet built")[0]
    assert "tool-scope-creep" in built
    assert "secret-leak-via-tool-response" in built
    # the genuinely-remaining gaps must still be disclosed honestly
    assert "not yet" in out.lower() or "NOT yet" in out
    # Taint tracking v1 shipped 2026-07-21 (one cross-file import hop; raised
    # to two hops 2026-07-22). The disclosed remaining gap is now DEEP/multi-hop
    # cross-file taint tracking (third hop+, cross-repo, sanitizer-aware) --
    # still surfaced honestly.
    assert "cross-file" in out.lower() and "taint tracking" in out.lower()
    assert "Git-history secret scanning" in out


def test_fix_lane_plan_doubles_as_next_quote():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    plan = out.split("## 7. Ranked fix-lane plan")[1]
    assert "next" in out.split("## 7. Ranked fix-lane plan")[1].split("\n")[0].lower() \
        or "quote" in plan.lower()
    for n in ("1.", "2.", "3."):
        assert n in plan


def test_counts_are_generated_not_hand_typed():
    out = client_report.render_client_report(_sample_result(), client_name="Acme")
    assert "Findings: 3 total" in out
    assert "P0: 1, P1: 1, P2: 1, P3: 0" in out


def test_empty_findings_render_without_crashing():
    r = ScanResult(target="/repos/empty", files_scanned=3)
    out = client_report.render_client_report(r, client_name="Acme")
    assert "Findings: 0 total" in out
    assert "No P0" in out or "no p0" in out.lower()


def test_default_client_name_when_omitted():
    out = client_report.render_client_report(_sample_result())
    assert "# MCP Server Security Audit -- the client" in out


# --------------------------------------------------------------------- #
# Zero-effector rail -- this module only reads a ScanResult and returns a
# string; it must never write/delete/execute against the scanned target.
# --------------------------------------------------------------------- #

_EFFECTOR_VERBS = (
    "write", "delete", "remove", "kill", "restart", "arm", "repair",
    "fix", "patch", "post", "send", "exec", "spawn", "mutate",
    "rewrite", "modify",
)


def test_client_report_module_has_no_effector_shaped_symbol():
    offenders = [
        n for n in dir(client_report)
        if not n.startswith("_")
        and any(v in n.lower() for v in _EFFECTOR_VERBS)
    ]
    assert offenders == [], offenders
