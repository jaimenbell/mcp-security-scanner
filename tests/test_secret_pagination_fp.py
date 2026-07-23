"""Wave-1 FP class 1a: pagination/continuation-cursor field names must not
trip the secret-name heuristic (secret-leak-via-tool-response, secret-in-log)
-- but a genuinely credential-named field/variable must still flag. Evidence:
today's ecosystem scan (staged/ecosystem-scan-2026-07-23) hit this on
awslabs/mcp's ``next_token`` tool-response field and its ``next_token``
mention in a log line -- both anonymized into these fixtures."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretLeakResponseDetector, SecretHandlingDetector
from mcp_scanner.detectors.secret_handling import _is_pagination_cursor_name, _name_looks_secret


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_pagination_field_not_flagged_python():
    r = scan_repo(
        "tests/fixtures/vuln_secret_leak_pagination", [SecretLeakResponseDetector()]
    )
    hits = [
        f for f in r.findings
        if "next_token" in (f.detail or "") or "'cursor'" in (f.detail or "") or "'next_token'" in (f.detail or "")
    ]
    assert hits == [], f"pagination cursor fields must not flag, got {hits}"


def test_real_credential_still_flagged_alongside_pagination_python():
    r = scan_repo(
        "tests/fixtures/vuln_secret_leak_pagination", [SecretLeakResponseDetector()]
    )
    hits = [f for f in r.findings if "access_token" in (f.detail or "")]
    assert hits, "a real credential field must still flag even alongside a demoted pagination field"


def test_pagination_field_not_flagged_js():
    r = scan_repo(
        "tests/fixtures/vuln_secret_leak_pagination_js", [SecretLeakResponseDetector()]
    )
    hits = [
        f for f in r.findings
        if "nextToken" in (f.detail or "") or "cursor" in (f.detail or "").lower()
    ]
    assert hits == [], f"pagination cursor fields (JS) must not flag, got {hits}"


def test_real_credential_still_flagged_js():
    r = scan_repo(
        "tests/fixtures/vuln_secret_leak_pagination_js", [SecretLeakResponseDetector()]
    )
    hits = [f for f in r.findings if "access_token" in (f.detail or "")]
    assert hits, "a real credential field (JS) must still flag alongside a demoted pagination field"


def test_secret_in_log_pagination_field_not_flagged():
    # Real evidence shape: logger.debug(f'Received next_token: {next_token is
    # not None}') -- only a boolean is logged, but the pre-fix heuristic
    # flagged it purely on the identifier name `next_token`.
    import ast
    from mcp_scanner.detectors.base import RepoContext, SourceFile
    from pathlib import Path

    src = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(next_token):\n"
        "    logger.debug(f'Received next_token: {next_token is not None}')\n"
        "def g(api_key):\n"
        "    logger.info(f'key is {api_key}')\n"
    )
    tree = ast.parse(src)
    f = SourceFile(path=Path("x.py"), rel="x.py", text=src, tree=tree, lines=src.splitlines())
    ctx = RepoContext(root=Path("."), files=[f], tracked=set(), is_git=False)
    findings = SecretHandlingDetector().run(ctx)
    logs = [fi for fi in findings if fi.vuln_class == "secret-in-log"]
    assert len(logs) == 1, f"expected only the api_key log to flag, got {logs}"
    assert "api_key" in logs[0].snippet or "key" in logs[0].snippet.lower()


# --- unit-level guard on the shared name-shape helper itself ---------------

def test_pagination_cursor_name_shape():
    for name in ("next_token", "page_token", "next_page_token",
                 "continuation_token", "cursor", "next_cursor",
                 "result_next_token", "nextToken", "pageToken", "resultNextCursor"):
        assert _is_pagination_cursor_name(name), f"{name} should be pagination-shaped"


def test_pagination_cursor_name_shape_excludes_real_credentials():
    for name in ("access_token", "refresh_token", "auth_token", "api_key",
                 "client_secret", "session_token", "bearer_token",
                 "page_token_secret"):
        assert not _is_pagination_cursor_name(name), f"{name} must NOT be treated as pagination"


def test_name_looks_secret_still_flags_real_credentials():
    for name in ("access_token", "SECRET_KEY", "api_key", "password"):
        assert _name_looks_secret(name), f"{name} must still be recognized as a secret name"
