"""Stable finding identity.

``finding_id`` is the short hash of (vuln_class, repo-relative file,
normalized title) -- deliberately EXCLUDING the line number: lines shift
between re-scans, while class+file+title is the stable spine. This lets a
human triage annotation (triage.toml) written against one scan still apply
to a later re-scan of the same repo, and later becomes the Managed-Watch
trending key.

Collisions (two findings sharing the same class+file+title triple, e.g. the
same pattern flagged on two lines of one file) get a ``-2``/``-3``...
suffix assigned by original order of appearance, so every finding in a scan
has a unique id while the FIRST occurrence keeps the bare hash.

Presentation-layer only: nothing here changes detection logic.
"""
from __future__ import annotations

import hashlib


def _normalize_title(title: str) -> str:
    """Collapse whitespace and case -- cosmetic title edits keep the id."""
    return " ".join(title.split()).lower()


def compute_finding_id(vuln_class: str, file: str, title: str) -> str:
    """12-hex-char stable id of (vuln_class, file, normalized title)."""
    spine = "\n".join((vuln_class, file.replace("\\", "/"), _normalize_title(title)))
    return hashlib.sha256(spine.encode("utf-8")).hexdigest()[:12]


def assign_finding_ids(triples: list[tuple[str, str, str]]) -> list[str]:
    """Assign a unique finding_id to each (vuln_class, file, title) triple.

    The first occurrence of a colliding triple keeps the bare hash; the
    second gets ``-2``, the third ``-3``, ... in original list order.
    """
    seen: dict[str, int] = {}
    ids: list[str] = []
    for vuln_class, file, title in triples:
        base = compute_finding_id(vuln_class, file, title)
        n = seen.get(base, 0) + 1
        seen[base] = n
        ids.append(base if n == 1 else f"{base}-{n}")
    return ids
