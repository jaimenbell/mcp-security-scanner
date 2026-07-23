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
    # NAME-based check specifically (title "Secret-named value returned")
    # -- distinct from the P1-5 value-shape backstop below, which
    # legitimately DOES flag a resolved literal mentioning these same
    # variable names in its own finding text.
    r = scan_repo(
        "tests/fixtures/vuln_secret_leak_pagination", [SecretLeakResponseDetector()]
    )
    hits = [
        f for f in r.findings
        if f.title == "Secret-named value returned from a tool response"
        and ("next_token" in f.detail or "cursor" in f.detail)
    ]
    assert hits == [], f"pagination cursor fields must not flag by name, got {hits}"


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


def test_jwt_value_under_pagination_name_still_flags_by_shape():
    # Round-2 N-vote P1-5 repro: pagination-name demotion removed the ONLY
    # signal for a bearer/JWT-shaped secret assigned to a pagination-named
    # variable (real JWT under `next_token` went 2 findings -> 0). A
    # value-shape backstop must catch it independent of the name.
    r = scan_repo(
        "tests/fixtures/vuln_secret_leak_pagination", [SecretLeakResponseDetector()]
    )
    hits = [f for f in r.findings if "JWT" in (f.title or "") or "JWT" in (f.detail or "")]
    assert hits, f"a JWT-shaped value under a pagination-named variable must still flag, got {r.findings}"


def test_bearer_pattern_does_not_flag_obviously_fake_test_fixture_value():
    # Live fleet-sweep catch (post P1-5, found during this same round-2
    # pass): the new Bearer-prefixed backstop pattern flagged github-mcp's
    # OWN test fixture, "Bearer github_pat_fake_test_token_1234" -- an
    # obviously-named fake value. Real secrets essentially never spell out
    # "fake"/"test"/"dummy" as a substring.
    import ast
    from mcp_scanner.detectors.base import RepoContext, SourceFile
    from mcp_scanner.detectors import SecretHandlingDetector
    from pathlib import Path

    src = 'AUTH_HEADER = "Bearer github_pat_fake_test_token_1234"\n'
    tree = ast.parse(src)
    f = SourceFile(path=Path("x.py"), rel="x.py", text=src, tree=tree, lines=src.splitlines())
    ctx = RepoContext(root=Path("."), files=[f], tracked=set(), is_git=False)
    findings = SecretHandlingDetector().run(ctx)
    hits = [fi for fi in findings if fi.vuln_class == "hardcoded-secret"]
    assert hits == [], f"an obviously-fake Bearer test fixture must not flag, got {hits}"


def test_bearer_pattern_still_flags_a_real_looking_token():
    import ast
    from mcp_scanner.detectors.base import RepoContext, SourceFile
    from mcp_scanner.detectors import SecretHandlingDetector
    from pathlib import Path

    src = 'AUTH_HEADER = "Bearer xK9pQm2vN8rL5wYs3Tz7Ab1Cd4Ef6Gh0Ij9Kl2Mn5Op8Qr1St"\n'
    tree = ast.parse(src)
    f = SourceFile(path=Path("x.py"), rel="x.py", text=src, tree=tree, lines=src.splitlines())
    ctx = RepoContext(root=Path("."), files=[f], tracked=set(), is_git=False)
    findings = SecretHandlingDetector().run(ctx)
    hits = [fi for fi in findings if fi.vuln_class == "hardcoded-secret"]
    assert hits, "a real-looking (non-fake-marked) Bearer token must still flag"


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
