"""Detector base class + the shared file-context object detectors operate on."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding


@dataclass
class SourceFile:
    """One source file handed to detectors, parsed once and shared."""

    path: Path                 # absolute path on disk
    rel: str                   # repo-relative posix path
    text: str
    tree: ast.AST | None = None       # parsed AST for .py files, else None
    lines: list[str] = field(default_factory=list)

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def line_at(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""


@dataclass
class RepoContext:
    """Everything a detector might need about the repo under scan."""

    root: Path
    files: list[SourceFile]
    tracked: set[str]          # git-tracked repo-relative posix paths
    is_git: bool

    def has_tracked(self, rel: str) -> bool:
        return rel in self.tracked


class Detector:
    """Base class. Subclasses set ``name`` and implement ``run``."""

    name: str = "detector"

    def run(self, ctx: RepoContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError
