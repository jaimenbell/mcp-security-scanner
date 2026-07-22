"""Structural + egress-safety tests for the Managed MCP Watch composite
GitHub Action (action/action.yml).

These lock the spec's egress rules (SAAS-TIER-SPEC.md section 3 + gate G5)
into CI:

  * the counts webhook is OFF by default (empty input);
  * the ONLY step that performs network egress is the webhook step;
  * the webhook step transmits the counts-summary file ONLY -- never the
    client report or the raw findings JSON;
  * the report artifact is uploaded client-side (actions/upload-artifact),
    never POSTed anywhere.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ACTION_FILE = Path(__file__).parent.parent / "action" / "action.yml"


def _load():
    return yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))


def _steps():
    return _load()["runs"]["steps"]


def test_action_file_exists_and_parses():
    action = _load()
    assert action["name"]
    assert action["description"]
    assert action["runs"]["using"] == "composite"


def test_fail_on_defaults_to_p1():
    action = _load()
    assert action["inputs"]["fail-on"]["default"] == "P1"


def test_counts_webhook_off_by_default():
    action = _load()
    assert action["inputs"]["counts-webhook-url"]["default"] == ""


def test_webhook_step_is_conditional_on_nonempty_url():
    steps = _steps()
    webhook_steps = [s for s in steps if "curl" in s.get("run", "")]
    assert len(webhook_steps) == 1, (
        "exactly one step may perform network egress"
    )
    cond = webhook_steps[0].get("if", "")
    assert "counts-webhook-url" in cond and "!=" in cond and "''" in cond


def test_only_the_webhook_step_has_network_egress():
    """No step other than the single webhook step may contain a network
    client invocation or a literal URL."""
    steps = _steps()
    egress_tokens = ("curl", "wget", "Invoke-WebRequest", "Invoke-RestMethod",
                    "urllib", "requests.", "http://", "https://")
    offenders = []
    for i, step in enumerate(steps):
        run = step.get("run", "")
        hits = [t for t in egress_tokens if t in run]
        if hits:
            offenders.append((i, step.get("name", "?"), hits))
    assert len(offenders) == 1, f"unexpected egress surface: {offenders}"


def test_webhook_posts_only_the_counts_summary():
    steps = _steps()
    webhook = next(s for s in steps if "curl" in s.get("run", ""))
    run = webhook["run"]
    assert "mcp-scan-summary.json" in run
    # The full report and the raw findings JSON must never be transmitted.
    assert "mcp-scan-report" not in run
    assert "mcp-scan-findings.json" not in run.split("curl", 1)[1], (
        "raw findings JSON appears in the curl invocation"
    )


def test_report_uploaded_client_side_only():
    steps = _steps()
    upload_steps = [s for s in steps
                    if "upload-artifact" in str(s.get("uses", ""))]
    assert len(upload_steps) == 1
    path = upload_steps[0]["with"]["path"]
    assert "report-path" in path or "mcp-scan-report" in path


def test_scanner_installed_from_pinned_action_checkout():
    """G1: the scanner installs from the action's own pinned checkout --
    no `-e`, no MCP_SCANNER_FLEET_ROOT."""
    steps = _steps()
    install = next(s for s in steps if "pip install" in s.get("run", ""))
    assert "github.action_path" in install["run"]
    assert " -e " not in install["run"]
    all_runs = "\n".join(s.get("run", "") for s in steps)
    assert "MCP_SCANNER_FLEET_ROOT" not in all_runs


def test_gate_runs_last_so_red_builds_still_ship_artifact_and_counts():
    steps = _steps()

    def index_of(pred):
        return next(i for i, s in enumerate(steps) if pred(s))

    gate = index_of(lambda s: "--fail-on" in s.get("run", ""))
    upload = index_of(lambda s: "upload-artifact" in str(s.get("uses", "")))
    webhook = index_of(lambda s: "curl" in s.get("run", ""))
    assert upload < gate
    assert webhook < gate
    assert gate == len(steps) - 1


def test_gate_uses_fail_on_input():
    steps = _steps()
    gate = next(s for s in steps if "--fail-on" in s.get("run", ""))
    assert "inputs.fail-on" in gate["run"]
    assert "inputs.fail-on" in gate.get("if", ""), (
        "gate must be skippable by setting fail-on to empty"
    )
