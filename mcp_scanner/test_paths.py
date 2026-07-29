"""The ONE shared test/spec/fixture-path classifier.

Every detector and post-pass that needs to ask "is this file a test harness
rather than production attack surface?" asks it HERE. There is deliberately
one implementation, because the alternative -- the same carve-out
re-implemented in some detectors and forgotten in the rest -- fails silently
and is worse than having no carve-out at all.

WHAT THIS ANSWERS, AND WHAT IT DOES NOT
---------------------------------------
It answers exactly one question: does this repo-relative path name a
test/spec/fixture file? It carries NO opinion about the consequence, and a
True answer is never on its own a licence to suppress anything. Per README's
one law, a target-controllable signal like a path may only demote confidence
and tag a finding, or (in ``reachability.py``) select the pre-existing
``Reachability.CLI_ONLY`` grade whose own definition already names "a test
file" as a non-tool entrypoint. Callers must not turn a True here into a
``continue``.

TWO MARKER FAMILIES
-------------------
1. **Directory segments** -- ``tests/``, ``__tests__/``, ``testdata/``,
   ``spec/``, ``mocks/``, ``fixtures/`` ... This is the form that lived in
   ``secret_handling.py`` from 2026-07-23 (self-signed test-cert demotion,
   then hardcoded-secret test-path demotion) and it is preserved verbatim so
   those two behaviours are bit-for-bit unchanged by the promotion.

2. **Filename markers** -- ``*.test.ts``, ``*.spec.js``, ``*.e2e-spec.ts``,
   ``*_test.go``, ``test_*.py``, ``conftest.py``. NEW on 2026-07-29. The
   held-out precision measurement found 7 of 58 false positives in
   airtable-mcp-server's ``src/e2e.test.ts`` -- a vitest e2e harness sitting
   beside its subject, which is the dominant JS/TS/Go convention and which
   the directory-only form could never see.

BOUNDARY (honest, stated once): this is a PATH-SHAPE heuristic, not proof.
A repo can name a production module ``foo.test.ts``, and a repo can hide a
real credential under ``tests/``. That is precisely why callers demote and
label rather than drop -- see ``_compose_demotion``'s pair rule in
``secret_handling.py`` and the ``CLI_ONLY`` fallback in ``reachability.py``.
"""

from __future__ import annotations

import re

# --- family 1: directory segments -----------------------------------------
# Preserved verbatim from secret_handling._TEST_PATH_MARKER (2026-07-23) so
# promoting it changes nothing about the two behaviours already built on it.
_TEST_DIR_MARKER = re.compile(
    r"(^|/)(tests?|__tests__|testdata|test-data|testserver|fixtures?|spec|mocks?)(/|$)",
    re.IGNORECASE,
)

# --- family 2: filename markers (added 2026-07-29) -------------------------
# Anchored at the FILENAME, and every alternative requires a real separator
# ('.', '-', '_', or a path boundary) on the marker's leading edge. That
# separator requirement is what keeps `latest/`, `protest/`, `attest.ts`,
# `testimonials.ts`, `greatest_hits.py` and `specification/` out -- a marker
# glued into a longer word is not a marker.
_TEST_FILE_MARKER = re.compile(
    r"""
      [.\-](?:test|spec)\.[A-Za-z0-9]+$   # foo.test.ts, foo.spec.js, foo.e2e-spec.ts
    | _test\.[A-Za-z0-9]+$                 # handler_test.go
    | (?:^|/)test_[^/]*\.pyw?$             # test_thing.py  (pytest/unittest)
    | (?:^|/)conftest\.pyw?$               # conftest.py
    """,
    re.IGNORECASE | re.VERBOSE,
)


def is_test_path(rel: str) -> bool:
    """True when ``rel`` names a test/spec/fixture file.

    ``rel`` is a repo-relative path; both posix and Windows separators are
    accepted so a hand-built ``RepoContext`` or a Windows caller gets the
    same answer as the scanner's own (already posix) ``SourceFile.rel``.
    """
    if not rel:
        return False
    norm = rel.replace("\\", "/")
    return bool(_TEST_DIR_MARKER.search(norm) or _TEST_FILE_MARKER.search(norm))
