from pathlib import Path

import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import JobHazardsDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_job"), [JobHazardsDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_job"), [JobHazardsDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


# --- job-overbroad-scope ---------------------------------------------------

def test_write_all_permissions_flagged(vuln):
    assert "job-overbroad-scope" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "job-overbroad-scope"]
    assert any(f.file.endswith("deploy.yml") and f.severity == Severity.P1 for f in hits)


def test_icacls_everyone_full_control_flagged(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "job-overbroad-scope"]
    assert any(f.file.endswith("deploy.ps1") for f in hits)


def test_clean_scope_quiet(clean):
    assert [f for f in clean.findings if f.vuln_class == "job-overbroad-scope"] == []


# --- job-destructive-no-confirm ---------------------------------------------

def test_destructive_rm_no_confirm_flagged(vuln):
    assert "job-destructive-no-confirm" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "job-destructive-no-confirm"]
    assert any(f.file.endswith("deploy.sh") for f in hits)
    assert any(f.file.endswith("deploy.yml") for f in hits)


def test_confirm_false_powershell_flagged(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "job-destructive-no-confirm"]
    assert any(f.file.endswith("deploy.ps1") and f.severity == Severity.P0 for f in hits)


def test_clean_destructive_quiet_with_confirm_gate(clean):
    assert [f for f in clean.findings if f.vuln_class == "job-destructive-no-confirm"] == []


# --- job-unverified-success --------------------------------------------------

def test_or_true_swallow_flagged(vuln):
    assert "job-unverified-success" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "job-unverified-success"]
    assert any(f.file.endswith("deploy.sh") for f in hits)


def test_continue_on_error_flagged(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "job-unverified-success"]
    assert any(f.file.endswith("deploy.yml") for f in hits)


def test_empty_catch_flagged(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "job-unverified-success"]
    assert any(f.file.endswith("deploy.ps1") for f in hits)


def test_clean_verification_quiet(clean):
    assert [f for f in clean.findings if f.vuln_class == "job-unverified-success"] == []


# --- file-type coverage: scanner reads job/wrapper/IaC files at all --------

def test_scanner_reads_yaml_sh_ps1(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_job"))
    scanned_rel = {f.rel for f in __import__("mcp_scanner.scanner", fromlist=["build_context"]).build_context(str(fixtures_dir / "vuln_job"))[0].files}
    assert any(rel.endswith(".yml") for rel in scanned_rel)
    assert any(rel.endswith(".sh") for rel in scanned_rel)
    assert any(rel.endswith(".ps1") for rel in scanned_rel)
