"""Structural tests for the published pre-commit hook (spec gate G3)."""

from __future__ import annotations

from pathlib import Path

import yaml

HOOKS_FILE = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"


def _hook():
    hooks = yaml.safe_load(HOOKS_FILE.read_text(encoding="utf-8"))
    assert isinstance(hooks, list) and len(hooks) == 1
    return hooks[0]


def test_hook_id_and_entry():
    hook = _hook()
    assert hook["id"] == "mcp-scan"
    assert hook["entry"] == "mcp-scan"
    assert hook["language"] == "python"


def test_hook_gates_on_p1():
    hook = _hook()
    assert hook["args"] == [".", "--fail-on", "P1"]


def test_hook_scans_whole_repo_not_filenames():
    hook = _hook()
    assert hook["pass_filenames"] is False
    assert hook["always_run"] is True
