"""The ONE shared test/spec-path classifier (``mcp_scanner.test_paths``).

Born 2026-07-29 out of the held-out precision measurement (0 true / 58
findings on 5 third-party MCP servers). Two of the five false-positive
classes were "this file is a test harness, not production attack surface":

* airtable-mcp-server ``src/e2e.test.ts`` -- 6 ``execSync`` hits + 1 SSRF hit,
  every one of them in a vitest e2e harness. The pre-existing classifier
  (``secret_handling._TEST_PATH_MARKER``) matched DIRECTORY segments only, so
  a test file that lives beside its subject -- the dominant JS/TS convention
  -- was invisible to it.
* firecrawl ``tests/*.test.mjs`` and neon ``mcp/__tests__/*.bench.test.ts``,
  which the directory-segment form already caught.

WHY THIS MODULE EXISTS AT ALL (the sibling-project lesson, 2026-07-29): a
carve-out implemented in 2 of 6 detectors and not the rest is worse than no
carve-out, because the inconsistency is invisible. There is now exactly ONE
implementation, imported by everything that needs it, and this file pins its
behaviour so a second copy can't quietly drift in.

SCOPE IS PART OF THE RULE (stated with the pattern, not after it): this
classifier answers ONE question -- "is this path a test/spec/fixture file?".
It says nothing about what a caller should DO with that answer, and the
answer is never on its own a licence to suppress. Per README's one law, the
callers use it to DEMOTE and TAG (secret_handling) or to assign the existing
``Reachability.CLI_ONLY`` grade (reachability), never to drop a finding.
"""

import pytest

from mcp_scanner.test_paths import is_test_path


# --- directory-segment markers (behaviour inherited from secret_handling) ---
@pytest.mark.parametrize("rel", [
    "tests/mcp-smoke.test.mjs",
    "test/helper.py",
    "mcp/__tests__/refresh-concurrency.bench.test.ts",
    "pkg/testdata/cassette.yaml",
    "pkg/test-data/cassette.yaml",
    "tests/testserver/cert.pem",
    "spec/openapi.yaml",
    "src/mocks/handlers.ts",
    "fixtures/seed.json",
    "app/fixture/data.json",
])
def test_directory_segment_markers_are_test_paths(rel):
    assert is_test_path(rel) is True, f"{rel!r} should classify as a test path"


# --- filename markers: the NEW behaviour this module adds ------------------
# Every one of these is a real path from the 2026-07-29 measurement or the
# dominant convention of the ecosystem it comes from. None of them has a
# test DIRECTORY segment, so the pre-existing directory-only regex missed
# all of them.
@pytest.mark.parametrize("rel", [
    "src/e2e.test.ts",            # airtable-mcp-server, 7 findings
    "src/airtableService.test.ts",
    "lib/client.spec.js",
    "lib/client.test.mjs",
    "components/Button.test.tsx",
    "components/Button.spec.tsx",
    "pkg/handler_test.go",
    "mcp_scanner/test_paths.py",  # python `test_*.py`
    "some/dir/conftest.py",
    "src/foo.e2e-spec.ts",
])
def test_filename_markers_are_test_paths(rel):
    assert is_test_path(rel) is True, f"{rel!r} should classify as a test path"


# --- the recall half: production paths must NOT classify -------------------
# Precision is satisfiable by silence -- a classifier that returns True for
# everything would pass the two blocks above. These are the real production
# files from the SAME five measured repos that still carried findings after
# the fix, plus the near-miss shapes most likely to be over-matched.
@pytest.mark.parametrize("rel", [
    "src/monitor.ts",                     # firecrawl, real SSRF surface
    "src/airtableService.ts",             # airtable, real SSRF surface
    "mcp/tools/handlers/docs.ts",         # neon
    "mcp/neon-client.ts",                 # neon
    "lib/oauth/client.ts",                # neon
    "app/api/[transport]/route.ts",       # neon
    "scripts/start-server.ts",            # notion
    "build-mcpb.sh",                      # airtable build script (NOT a test)
    "src/protest/handler.ts",             # 'test' glued inside a longer word
    "src/latest/index.ts",                # 'test' as a suffix of 'latest'
    "src/contested/api.py",               # 'test' inside 'contested'
    "src/attest.ts",                      # 'test' inside 'attest'
    "src/testimonials.ts",                # 'test' as a prefix of a real word
    "specification/schema.json",          # 'spec' as a prefix of a real word
    "src/greatest_hits.py",               # 'test' glued mid-identifier
])
def test_production_paths_are_not_test_paths(rel):
    assert is_test_path(rel) is False, f"{rel!r} must NOT classify as a test path"


def test_windows_separators_are_normalised():
    """Callers pass ``SourceFile.rel`` (posix) but a hand-built context or a
    Windows caller can pass backslashes; the classifier must not depend on
    which one it got."""
    assert is_test_path(r"mcp\__tests__\thing.ts") is True
    assert is_test_path(r"src\e2e.test.ts") is True
    assert is_test_path(r"src\monitor.ts") is False


def test_secret_handling_uses_the_shared_classifier_not_its_own_copy():
    """The anti-drift pin. ``secret_handling`` had the only implementation;
    after promotion it must delegate to this module rather than keep a
    parallel copy that can diverge (the exact failure the sibling project
    hit: carve-out present in 2 of 6 detectors)."""
    from mcp_scanner.detectors import secret_handling

    assert secret_handling._is_test_fixture_path is is_test_path, (
        "secret_handling._is_test_fixture_path must BE the shared "
        "test_paths.is_test_path, not a second implementation of it"
    )


def test_shared_classifier_covers_the_paths_the_old_directory_only_form_missed():
    """Regression pin with DIFFERENT values on the two sides: the old form is
    re-derived here explicitly rather than imported, so this test cannot pass
    vacuously by both sides referring to the same (new) object."""
    import re

    old_directory_only = re.compile(
        r"(^|/)(tests?|__tests__|testdata|test-data|testserver|fixtures?|spec|mocks?)(/|$)",
        re.IGNORECASE,
    )
    missed_by_old = "src/e2e.test.ts"
    assert old_directory_only.search(missed_by_old) is None, (
        "fixture drift: this path is supposed to be one the OLD form missed"
    )
    assert is_test_path(missed_by_old) is True
