"""Repo scanner — builds a RepoContext and runs every detector over it."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from .detectors import ALL_DETECTORS
from .detectors.base import Detector, RepoContext, SourceFile
from .models import ScanResult
from .reachability import grade_result
from .taint import grade_result as grade_taint

# Files we parse for AST / regex. Everything else is ignored except for the
# tracked-file secret check (which uses the git manifest, not content).
_SCAN_SUFFIXES = {
    ".py", ".pyw", ".j2", ".jinja", ".jinja2", ".js", ".mjs", ".cjs", ".ts",
    ".mts", ".cts", ".jsx", ".tsx",
    # scheduled-job / wrapper / IaC-CI surfaces (Phase 1 depth build,
    # 2026-07-21): cron/systemd wrappers, GitHub Actions workflows, and
    # Windows scheduled-task/deploy scripts -- the reliability-retainer
    # pitch's "cron, systemd, GitHub Actions, your Railway/deploy configs"
    # promise requires the scanner to actually read these file types.
    ".yml", ".yaml", ".ps1", ".sh", ".bash", ".bat", ".cmd",
    ".service", ".timer",
}
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".egg-info",
    "store.chroma", "store-bge.chroma",
}
_MAX_BYTES = 1_500_000


def _git_tracked(root: Path) -> tuple[set[str], bool]:
    """Return (tracked-relpaths, is_git_repo)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return set(), False
        tracked = {line.strip().replace("\\", "/") for line in out.stdout.splitlines() if line.strip()}
        return tracked, True
    except (OSError, subprocess.SubprocessError):
        return set(), False


def _iter_source_paths(root: Path, tracked: set[str], is_git: bool):
    if is_git and tracked:
        for rel in tracked:
            p = root / rel
            if p.suffix.lower() in _SCAN_SUFFIXES and p.is_file():
                yield p, rel
        return
    # Non-git fallback: walk the tree.
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _SCAN_SUFFIXES:
            continue
        if any(part in _SKIP_DIRS or part.endswith(".egg-info") for part in p.parts):
            continue
        yield p, p.relative_to(root).as_posix()


def build_context(target: str) -> tuple[RepoContext, list[str]]:
    root = Path(target).resolve()
    errors: list[str] = []
    tracked, is_git = _git_tracked(root)
    files: list[SourceFile] = []

    for path, rel in _iter_source_paths(root, tracked, is_git):
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            errors.append(f"read error {rel}: {e}")
            continue
        tree = None
        if path.suffix.lower() in (".py", ".pyw"):
            try:
                tree = ast.parse(text, filename=str(path))
            except SyntaxError as e:
                errors.append(f"parse error {rel}: {e}")
        files.append(SourceFile(
            path=path, rel=rel, text=text, tree=tree, lines=text.splitlines()
        ))

    ctx = RepoContext(root=root, files=files, tracked=tracked, is_git=is_git)
    return ctx, errors


def scan_repo(target: str, detectors: list[Detector] | None = None) -> ScanResult:
    """Scan one repo path and return a ScanResult."""
    detectors = detectors if detectors is not None else ALL_DETECTORS
    ctx, errors = build_context(target)
    result = ScanResult(target=str(Path(target).resolve()), files_scanned=len(ctx.files))
    result.errors.extend(errors)
    for det in detectors:
        try:
            for finding in det.run(ctx):
                result.add(finding)
        except Exception as e:  # a detector crash must not sink the whole scan
            result.errors.append(f"detector {det.name} crashed: {e}")
    # Post-detector pass: label each finding with tool-reachability and nudge
    # confidence accordingly. Guarded so a grading bug can never sink a scan.
    try:
        grade_result(ctx, result)
    except Exception as e:
        result.errors.append(f"reachability grading crashed: {e}")
    # Second post-detector pass: tool-parameter taint tracking. Runs after
    # reachability (its confidence axis is orthogonal) and is guarded so a
    # taint bug can never sink a scan.
    try:
        grade_taint(ctx, result)
    except Exception as e:
        result.errors.append(f"taint grading crashed: {e}")
    return result
