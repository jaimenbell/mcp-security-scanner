from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors import SecretLeakResponseDetector
from mcp_scanner.models import Severity

import pytest


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_secret_leak"), [SecretLeakResponseDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_secret_leak"), [SecretLeakResponseDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_os_environ_dump_flagged(vuln):
    assert "secret-leak-via-tool-response" in _classes(vuln)
    hits = [f for f in vuln.findings if "environ" in f.detail.lower()]
    assert hits
    assert any(f.severity == Severity.P0 for f in hits)


def test_secret_named_value_flagged(vuln):
    hits = [f for f in vuln.findings if "token" in f.detail.lower() and "environ" not in f.detail.lower()]
    assert hits


def test_hardcoded_secret_literal_flagged(vuln):
    hits = [f for f in vuln.findings if "OpenAI-style" in f.title or "sk-" in f.detail]
    assert hits
    assert any(f.severity == Severity.P0 for f in hits)


def test_clean_responses_quiet(clean):
    assert clean.findings == [], (
        f"non-secret tool responses must not be flagged, got: "
        f"{[(f.vuln_class, f.file, f.line, f.title) for f in clean.findings]}"
    )


def test_edge_case_word_secret_in_unrelated_string_value_not_flagged():
    """A dict that merely contains the word 'secret' inside an unrelated
    string VALUE (not a credential) must not false-positive."""
    det = SecretLeakResponseDetector()
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.py"
        p.write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n\n"
            "@mcp.tool(name='get_message')\n"
            "async def get_message_tool() -> dict:\n"
            "    return {'ok': True, 'note': 'this operation kept no secret in the log'}\n",
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        findings = det.run(ctx)
        assert findings == []


def test_edge_case_partial_name_overlap_not_flagged():
    """A variable whose name shares only a glued substring with the
    secret-name heuristic (tokenizer, passwordless) is not a credential and
    must not false-positive."""
    det = SecretLeakResponseDetector()
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.py"
        p.write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n\n"
            "@mcp.tool(name='get_info')\n"
            "async def get_info_tool() -> dict:\n"
            "    tokenizer_version = 'bpe-v2'\n"
            "    passwordless_mode = True\n"
            "    return {'tokenizer_version': tokenizer_version, 'passwordless_mode': passwordless_mode}\n",
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        findings = det.run(ctx)
        assert findings == []


def test_whole_object_dump_flagged():
    det = SecretLeakResponseDetector()
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.py"
        p.write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n\n"
            "@mcp.tool(name='get_config')\n"
            "async def get_config_tool() -> dict:\n"
            "    return {'cfg': config}\n",
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        findings = det.run(ctx)
        assert findings
        assert any(f.vuln_class == "secret-leak-via-tool-response" for f in findings)
