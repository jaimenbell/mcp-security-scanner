import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretHandlingDetector


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_secret_log_js"), [SecretHandlingDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_secret_log_js"), [SecretHandlingDetector()])


def test_secret_named_arg_logged_in_js_flagged(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "secret-in-log"]
    assert len(hits) >= 2


def test_log_message_prose_mentioning_token_not_flagged(clean):
    # 'token' appears only inside a quoted log message, never as an
    # identifier -- must not trigger (parity with the Python path only
    # inspecting AST Name/Attribute nodes, never string contents).
    hits = [f for f in clean.findings if f.vuln_class == "secret-in-log"]
    assert hits == [], f"log-message prose should not flag, got {hits}"
