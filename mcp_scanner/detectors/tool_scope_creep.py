"""Detector 5 — write-tools-on-by-default / tool-scope-creep.

MCP tools are registered via ``@mcp.tool()`` / ``@server.tool()`` decorators
(FastMCP and equivalents), a completely different shape from the Flask/FastAPI
HTTP-verb decorators ``auth_posture.py`` already checks. None of the 4
existing detectors ever look at tool registration, so a mutating tool with
zero gating sails through untouched.

This detector:

1. Finds every ``@mcp.tool()`` / ``@server.tool()``-decorated function.
2. Classifies it as *mutating* by name/verb heuristic (``write_``, ``delete_``,
   ``create_``, ``execute_``, ``run_``, ``send_``, ...) OR by body content —
   a direct dangerous sink call (subprocess/os.system/file-write/HTTP
   post-put-delete-patch/etc.), including **one hop** through a helper
   function it plainly delegates to (the real shape of the operator's own
   fleet: a thin ``@mcp.tool()`` wrapper in ``server.py`` that calls a
   decorated helper in a separate ``groups/*.py`` module — see github-mcp's
   ``write.py`` / desktop-mcp's ``groups/record.py``, both resolved via the
   import-aware one-hop resolver below).
3. Flags a mutating tool with **no visible gate**: no gate decorator / env-flag
   opt-in / permission check on the tool function itself, and no gate found
   on the (one-hop) helper it delegates to.

Honesty note (round 2, 2026-07-23, later same day — supersedes the
same-file-only note this docstring briefly carried earlier the same day):
one-hop resolution is BOUNDED and IMPORT-AWARE, not a real call graph or
transitive dataflow proof. Resolution order per call, first match wins:

  1. **Import-aware.** ``local(...)`` / ``local.attr(...)`` where ``local``
     is bound by an explicit, statically-resolvable same-repo import in the
     calling file — ``import mod [as alias]``, ``from x.y import z [as w]``,
     and their relative-import equivalents (``from . import submodule`` /
     ``from .pkg.mod import name`` / ``from ..pkg import name``). This is
     what makes the github-mcp/desktop-mcp ``groups/*.py`` shape above
     resolve correctly: exactly one target file, named from the import
     statement itself — never a repo-wide guess.
  2. **Same-file class-qualified (cheap disambiguation).**
     ``ClassName().method(...)`` / ``ClassName.method(...)`` / a
     ``self.method(...)``/``cls.method(...)`` call from within a method of
     that same class — resolved to that EXACT class's own method, never
     confused with an unrelated same-named method on a different class in
     the same file.
  3. **Same-file bare name (fallback).** Every function in the calling
     file sharing the call's bare short name is a candidate. Genuinely
     ambiguous when more than one exists (e.g. two different classes with
     an identically-named method, neither qualified in a way step 2 can
     resolve): sink detection is OR'd across candidates (over-flag-safe —
     any one of them containing a sink is enough to flag); gate credit is
     AND'd across candidates (credited ONLY if every candidate is gated —
     disagreement withholds credit, the conservative direction for a
     security scanner, never a unioned false-clean).

Disclosed residual, stated rather than silently missed: a hop that resolves
to NEITHER an explicit same-repo import NOR a same-file candidate (a helper
imported from a genuinely third-party/external package, or reassigned/
re-exported in a way this static pass can't see) is an honest miss — gate is
not credited AND the sink is not followed for that call. For a tool whose
own name already matches the mutating-verb heuristic this still surfaces the
finding (over-flag, the direction this detector accepts everywhere); for a
tool with a non-mutating name whose ENTIRE mutating behavior lives only
behind that one unresolvable hop, this is a genuine, disclosed miss (see
``tests/fixtures/vuln_tool_scope_unresolvable_external_hop``).

History: round 1 (closing the README's named follow-up) found the
PRE-EXISTING decorator-registered path's ``func_index``/``gated_names``
were built REPO-WIDE by bare short function name in ``run()`` — an N-vote
refuter proved live that an unrelated, never-imported, same-named gated
helper anywhere else in the repo could silence a genuinely ungated mutating
tool's own one-hop helper (false NEGATIVE, the worse direction for this
detector's primary target class). Round 1's fix scoped resolution
same-file-only, but two further N-vote refuters proved THAT over-corrected:
(a) it silently severed the cross-file SINK hop too, not just the gate hop,
for a non-mutating-named tool with a real, reachable, ungated sink one hop
through an explicit import (total silence, not just an over-flag); (b) the
same-file bare-name union still let an unrelated same-named method on a
DIFFERENT class in the same file silence a genuinely ungated one. Round 2
(this version) replaced same-file-only with the bounded, import-aware,
one-hop resolver described above, closing both — see
``_resolve_call_targets`` for the implementation. The low-level SDK dispatch
path (below) is intentionally NOT touched by round 2 and stays same-file-only
via ``_build_function_index_for_file`` — a cleanly reusable follow-up, not
attempted here.

Low-level MCP SDK coverage (2026-07-23): this detector used to consume only
``extract_tool_registry``'s ``source == "js-regex"`` entries and re-derive
its own decorator walk directly for Python — a repo using ONLY the low-level
SDK shape (``Server()`` + a single ``@server.call_tool()`` dispatch function,
no ``@mcp.tool()`` decorators anywhere) got zero coverage regardless of how
many ungated mutating tools it registered. Fixed via
``tool_registry.dispatch_segments``: for each file gated on
``_file_imports_mcp`` with exactly one ``@server.call_tool()`` handler (zero
or ambiguous -> skip, never guess a root), the handler body is split into
per-tool branches (the "effective body" scope-creep analysis needs). A
branch attributable to one specific literal tool name (``if name == "x":``)
is classified/attributed to that tool exactly like a decorator-registered
one; a branch that isn't (an ``in (...)`` test, the final ``else``, code
outside the if/elif chain, or no dispatch shape at all) is attributed to the
dispatch handler itself — never a guessed tool name — mirroring
``secret_leak_response.py``'s identical low-level-SDK extension. Known
boundary, disclosed rather than silently left: only a literal ``==`` if/elif
walk is recognized as attributable dispatch; a dict-keyed dispatch table or
``match``/``case`` statement falls back to whole-handler attribution. A gate
found anywhere in the handler's own decorator/body text (module-level env
gate, or a shared pre-dispatch permission check that runs before every
branch) is treated as gating every branch in that handler — a deliberately
coarse, disclosed heuristic (same breadth already accepted for the existing
module-level gate), not per-branch dataflow proof.

Round 3 -- sink-substring-fix lane (2026-07-23, sink-classification fix +
severity calibration; N-vote-hardened over TWO passes the same day --
the round-1 fix below was itself proven wrong and replaced by round 2, see
the correction after this section). ``_is_mutating_sink_call`` used a bare
SUBSTRING test -- ``if "subprocess" in name`` -- against the call's own
dotted/bare name.
A HELPER FUNCTION whose name merely contains the word "subprocess" (e.g.
``_run_subprocess``) matched that test even when its body never touches the
real ``subprocess`` module at all -- reproduced live against vllm-ops-mcp:
``get_gpu_status``/``get_service_status``/``get_serve_config`` each
delegate, via ``from . import probes`` + ``probes.get_gpu_status()`` (the
one-hop-resolved call), to ``probes.py``'s same-named function, whose OWN
body then calls a helper literally named ``_run_subprocess`` -- producing 3
false P1/HIGH findings. The ``_MUTATING_SINK_SHORT`` fallback (HTTP verbs,
subprocess/os short names) had the identical bug one level down:
exact-equality on the call's bare short name with no requirement that the
call even be an attribute access -- a bare call to a user-defined function
literally named ``run`` or ``post`` matched it too.

Round 1's fix (commit 2df84e1, SUPERSEDED -- see the round-2 N-vote fix
comment above ``_SinkFileCtx`` for the full correction) replaced both with
``_SINK_DOTTED_EXACT`` for exact ``module.attr`` pairs, plus gating the
short-name fallback behind ``"." in name`` (a rendered-string syntax-shape
proxy for "is this an attribute access"). Two N-vote refuters proved THIS
over-corrected on both sides live: (P0) blanket-excluding every bare
``Name`` call also silenced REAL sinks reached via a direct stdlib import
(``from os import remove; remove(path)``); (P1) even for genuine attribute
calls, ``_dotted`` collapses to the bare leaf whenever the receiver isn't a
plain ``Name`` (``Path(x).unlink()``, ``requests.Session().post(url)``),
so the "." gate silently missed those too. Round 2 replaced the syntax-shape
proxy with RESOLUTION -- see ``_SinkFileCtx``/``_build_sink_file_ctx``/
``_resolved_sink_name`` immediately below, and their preceding comment block
for the complete history. This closes the false-positive class
categorically without reopening either refuter's gap: a user-defined
function whose NAME contains or equals a sink word is never, by itself, a
sink UNLESS it's genuinely unresolvable (over-flag-safe fallback, matching
this detector's pre-existing philosophy).

Verified live fleet outcome (not the outcome originally hypothesized --
stated precisely because the difference matters): vllm-ops-mcp's REAL call
chain is ``get_gpu_status_tool`` -(one resolved hop, import-aware)->
``probes.get_gpu_status`` -(a SECOND hop)-> ``_run_subprocess`` -(a THIRD
call)-> ``subprocess.run(...)``. This detector's one-hop resolver (round 2,
explicitly documented as "BOUNDED... not a real call graph or transitive
dataflow proof") only inspects the FIRST resolved hop's own body for a sink
-- it does not recursively resolve a second hop. Before this fix, the
substring bug was accidentally providing false "reach": scanning
``probes.get_gpu_status``'s body found the bare call ``_run_subprocess(...)``
and misclassified it AS the sink via name substring, without ever needing to
look inside ``_run_subprocess`` itself. After the fix, that bare call is
correctly seen as "just a name" -- and the real ``subprocess.run`` one hop
further in is out of this resolver's bound. The honest result, confirmed via
a live before/after fleet sweep (see the sink-substring-fix lane report),
is that all 3 vllm-ops-mcp findings go to ZERO -- not because of any
suppression logic added by this fix, but as an exposed side effect of an
ALREADY-EXISTING, already-disclosed one-hop-only limitation that the
substring bug had been accidentally papering over. This is the same class of
disclosed residual as the unresolvable-external-hop case above (a real,
stated miss, never a guess in either direction) -- extending the resolver to
follow a second hop is explicitly out of scope for this lane (a
structural/architectural change to ``_resolve_call_targets``, not a sink-
classification fix; round 1/round 2 above show that even ONE hop took two
N-vote passes to get right, so a deeper resolver is its own follow-up lane,
not attempted here).

Independent of that fleet-specific outcome, this fix ALSO introduces a
severity/confidence CALIBRATION for the general one-hop-reachable case
(e.g. a tool that calls a `subprocess`-wrapping helper directly, same file
or via an explicit import, with no second hop needed) -- this axis is real
and pinned by its own tests, it simply doesn't fire on vllm-ops-mcp's
specific two-hop shape. ``subprocess.run``/``Popen``/``call``/
``check_output``/``check_call`` accept a literal argv LIST with no shell
metacharacter interpretation unless ``shell=True`` is explicitly passed (the
well-known, AST-visible signature of real shell-injection risk -- a string
command interpreted by ``/bin/sh``). A one-hop-resolved subprocess call
without ``shell=True`` -- a fixed argv list executed directly -- is
calibrated to P2/MEDIUM rather than P1/HIGH via ``_is_high_risk_sink_call``;
``os.system``/``os.popen`` stay unconditionally high-risk (always
shell-interpreted by construction, no argv-list form exists), as do
``os.remove``/``unlink``/``rmdir``/``shutil.rmtree``/``move``, the HTTP
verbs, sendmail, and open-for-write. A direct (same-body) or one-hop
``shell=True`` sink is unchanged at P1/HIGH (see ``vuln_tool_scope``'s
``run_shell`` and ``vuln_tool_scope_cross_file_sink_import``'s
``sync_repo``, both pinned). See
``tests/test_tool_scope_creep_sink_substring_fix.py`` for all pinned cases
(benign-named helper stays quiet; a genuinely one-hop-reachable subprocess
call without ``shell=True`` calibrates to P2; direct/cross-file
``shell=True`` sinks are unchanged at P1/HIGH).

This calibration RESOLVES module aliases and bare stdlib-symbol imports
before checking ``shell=True`` (``_resolved_sink_name``, round-2 N-vote fix,
refuter A item 4) -- ``import subprocess as sp; sp.run(cmd)`` (no
``shell=True``) correctly calibrates to P2 exactly like the un-aliased
spelling, not an unconditional P1 (pinned in
``tests/test_tool_scope_creep_sink_substring_fix_round2.py``, which also
pins every refuter repro above as a permanent regression test, plus the
``subprocess.getoutput``/``getstatusoutput`` recognition and the removed
dead ``subprocess.popen`` (lowercase -- no such callable exists) entry, and
a dedicated two-hop-miss fixture, ``clean_tool_scope_two_hop_probe_miss``,
modeled directly on vllm-ops-mcp's real shape so the zero-findings outcome
above has an actual regression guard, not just prose).

Disclosed, out-of-scope follow-ups: (1) extending the one-hop resolver to a
bounded second hop (would restore a P2-level finding for vllm-ops-mcp's real
shape) -- a separate, larger initiative, not attempted here; (2) the JS/TS
line-window path (``_JS_MUTATING_SINK``) has an analogous ``shell:
true``-vs-argv-array distinction for ``child_process.spawn``/``execFile`` it
does not yet make (``exec``/``execSync`` ARE always shell-interpreted, same
as ``os.system``, so those two stay correctly high-risk as-is) -- not
attempted here, scoped out per this lane's HARD RAILS
(``_is_mutating_sink_call`` + its direct tests/docs only).
"""

from __future__ import annotations

import ast
import re
import tokenize
import io
from dataclasses import dataclass, field

from ..models import Finding, Severity, Confidence
from ..tool_registry import (
    _dotted,
    _is_tool_decorator,
    _declared_tool_name,
    extract_tool_registry,
    _is_call_tool_decorator,
    _file_imports_mcp,
    _decorated_in_file,
    dispatch_segments,
)
from .. import js_util
from .base import Detector, RepoContext, SourceFile

# --- mutating-by-name heuristic ------------------------------------------
_MUTATING_VERB = re.compile(
    r"^(write|delete|remove|create|add|update|modify|set|insert|upload|"
    r"execute|run|send|post|put|patch|restart|kill|terminate|spawn|exec|"
    r"drop|revoke|grant|rename|purge|wipe|comment)_",
    re.IGNORECASE,
)

# --- mutating-by-body heuristic (dangerous sinks) ------------------------
_MUTATING_SINK_SHORT = {
    "run", "call", "Popen", "check_output", "check_call",   # subprocess
    "system", "popen",                                       # os.system/popen
    "remove", "unlink", "rmdir", "rmtree", "move",           # filesystem delete/move
    "post", "put", "delete", "patch",                        # HTTP-mutate verbs
    "sendmail", "send_mail",                                 # messaging
}

# Exact `module.attr` dotted-path sink matches (round 3, 2026-07-23; set
# corrected in the round-2 N-vote fix pass same day -- see
# `_is_mutating_sink_call`'s docstring). Matched against the RESOLVED
# canonical name (module aliases and bare stdlib-symbol imports collapsed to
# their real `module.attr` spelling by `_resolved_sink_name`), never a raw
# rendered string. `subprocess.popen` (lowercase) was a dead entry removed in
# the N-vote pass -- no such callable exists (only `os.popen`);
# `subprocess.getoutput`/`getstatusoutput` added -- both real, always
# shell-interpreted (no `shell=` kwarg exists on either), so they are
# intentionally NOT in `_SUBPROCESS_RUN_LIKE` below and stay unconditionally
# high-risk via `_is_high_risk_sink_call`'s fallthrough.
_SINK_DOTTED_EXACT = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir",
    "shutil.rmtree", "shutil.move",
}

# subprocess.* calls needing the shell=True check for HIGH-risk calibration
# (round 3) -- os.system/os.popen are excluded because they are ALWAYS
# shell-interpreted by construction (no argv-list form exists), so they stay
# unconditionally high-risk.
_SUBPROCESS_RUN_LIKE = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
}

# --- gate hints -----------------------------------------------------------
_GATE_HINT = re.compile(
    r"(gated|require[_-]?write|requires?[_-]?permission|permission[_-]?group|"
    r"group_enabled|check_permission|policy_refusal|requires?_auth|"
    r"auth_required|authz|rbac|is_authorized|verify_permission|tool_group|"
    r"write_group|input_group)",
    re.IGNORECASE,
)
_ENV_OPT_IN = re.compile(
    r"(os\.environ(\.get)?|os\.getenv)\s*\(\s*[\"'][A-Z0-9_]*"
    r"(ENABLE|ALLOW|PERMIT|OPT_IN)[A-Z0-9_]*[\"']",
    re.IGNORECASE,
)

# --- JS/TS parity ----------------------------------------------------------
# No AST for JS/TS in this scanner (see js_util). Tool bodies aren't
# delimited without a parser, so the "body" a JS tool is graded on is a
# capped line window from its registration to the next registration (or 40
# lines, whichever is shorter) -- a same-file, no-real-scope heuristic,
# consistent with this detector's existing one-hop/name-based honesty note.
_JS_MUTATING_SINK = re.compile(
    r"\b(?:child_process\.)?(?:exec|execSync|spawn|execFile)(?:Sync)?\s*\(|"
    r"\bfs\.(?:unlink|rmdir|rm|writeFile|appendFile)(?:Sync)?\s*\(|"
    r"\baxios\.(?:post|put|delete|patch)\s*\(|"
    r"\bfetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|DELETE|PATCH)[\"']|"
    r"\bprocess\.kill\s*\(|"
    r"\bsendMail\s*\(",
    re.IGNORECASE,
)
_JS_ENV_OPT_IN = re.compile(
    r"process\.env(?:\.|\[)\s*[\"']?[A-Z0-9_]*(ENABLE|ALLOW|PERMIT|OPT_IN)[A-Z0-9_]*",
    re.IGNORECASE,
)
_JS_WINDOW_MAX_LINES = 40


def _unparse(node: ast.AST) -> str:
    return ast.unparse(node) if hasattr(ast, "unparse") else ""


# --------------------------------------------------------------------- #
# Round-2 N-vote fix pass (2026-07-23, later same day than round 3 below):
# TWO refuters proved live that the first cut's "." in name proxy was a
# SYNTAX-SHAPE test standing in for "is this a real attribute access",
# which is exactly the class of shortcut this file's own history keeps
# re-learning not to take. Fixed by RESOLVING what the callee actually is,
# using machinery this repo already owns (`_build_import_map`, the same-file
# function index), instead of inferring it from how the rendered string
# happens to look.
#
#   P0 (refuter A): the "." gate blanket-EXCLUDED every bare Name call --
#   including a bare call to a REAL sink imported directly (`from os import
#   remove; remove(path)`, `from shutil import rmtree; rmtree(d)`, `from
#   subprocess import run; run(cmd, shell=True)`). Base (pre-this-lane) code
#   caught all of these via `short in _MUTATING_SINK_SHORT` with no
#   attribute-ness requirement at all; the first cut's blanket exclusion
#   silenced them completely -- a straight regression, both detection paths.
#
#   P1 (refuter B): even restricted to attribute calls, `_dotted` collapses
#   to the bare LEAF name whenever the receiver isn't a plain `Name` --
#   `Path(x).unlink()`, `requests.Session().post(url)`, `get_proc().run(cmd)`
#   all render as just "unlink"/"post"/"run" (no "." at all), so the "." in
#   name gate silently missed every one of them despite being genuine,
#   idiomatic attribute-call sink shapes. `Path(x).unlink()` in particular is
#   THE idiomatic Python file-delete call.
#
# Fix, per call shape:
#
#   * A real ``ast.Attribute`` access (``isinstance(call.func,
#     ast.Attribute)``) -- checked STRUCTURALLY, never by whether the
#     rendered name happens to contain a "." -- matches the short-name
#     fallback (``_MUTATING_SINK_SHORT``) regardless of what the receiver
#     is, closing P1. A resolvable module alias (``import subprocess as
#     sp; sp.run(...)``) is canonicalized to its real ``module.attr``
#     spelling first (``_resolved_sink_name``) so exact-set matching and the
#     shell=True severity axis both see through the alias.
#   * A bare ``Name`` call is RESOLVED, never blanket-included or
#     blanket-excluded (closing P0):
#       1. bound by a direct stdlib-sink import (``from os import remove``,
#          ``from subprocess import run``, ...) -- canonicalized to its real
#          ``module.attr`` spelling and checked against ``_SINK_DOTTED_EXACT``
#          exactly like the dotted spelling. This is the fix that makes both
#          refuter A's repro AND the shell=True calibration axis see through
#          a bare stdlib import.
#       2. resolvable to a REPO-INTERNAL function (a same-file ``def``, or an
#          explicit same-repo import per ``_build_import_map``) -- NOT a
#          sink by itself; this is the original ``_run_subprocess`` false
#          positive's correct fix -- the one-hop resolver inspects that
#          function's REAL body elsewhere (see ``_inspect_body``), this
#          function only classifies the call site itself.
#       3. unresolvable (neither of the above -- an opaque/dynamic/external
#          name this pass cannot prove safe) -- falls through to the same
#          ``_MUTATING_SINK_SHORT`` short-name test as an attribute call,
#          over-flag-safe, restoring base's pre-existing catch on shapes
#          nothing here can resolve.
#
# See ``_SinkFileCtx``/``_build_sink_file_ctx``/``_resolved_sink_name`` for
# the resolution machinery, and ``tests/test_tool_scope_creep_sink_substring_
# fix.py`` for every refuter repro pinned as a regression test.
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class _SinkFileCtx:
    """Per-file resolution context threaded into sink classification so it
    can RESOLVE a callee instead of guessing from syntax shape.

    ``module_aliases``: local module-alias name -> canonical sink module
    (``"sp"`` -> ``"subprocess"`` from ``import subprocess as sp``) --
    restricted to ``_SINK_MODULES`` only, never a general import graph.

    ``symbol_aliases``: local bare name -> canonical ``"module.attr"``
    (``"remove"`` -> ``"os.remove"`` from ``from os import remove``,
    ``"rm"`` -> ``"os.remove"`` from ``from os import remove as rm``) --
    same restriction.

    ``local_names``: bare names resolvable to something REPO-INTERNAL (a
    same-file function definition, or an explicit same-repo import per
    ``_build_import_map``) -- used only to decide that an unresolved-looking
    bare call is "someone's own function, not a raw external/stdlib call",
    never to prove it safe (the one-hop resolver still inspects its body)."""
    module_aliases: dict[str, str] = field(default_factory=dict)
    symbol_aliases: dict[str, str] = field(default_factory=dict)
    local_names: frozenset[str] = field(default_factory=frozenset)


_SINK_MODULES = ("os", "subprocess", "shutil")


def _build_sink_file_ctx(
    f: SourceFile,
    files_by_rel: dict[str, SourceFile] | None = None,
    local_func_names: set[str] | None = None,
) -> _SinkFileCtx:
    """Build ``f``'s sink-resolution context. ``files_by_rel`` is optional --
    when omitted (the low-level-SDK path, which stays same-file-only by
    existing convention), ``local_names`` is just ``local_func_names``
    (same-file function definitions) with no cross-file import resolution;
    when provided, it's unioned with ``_build_import_map(f,
    files_by_rel)``'s keys -- any name ``_build_import_map`` records is
    already, by its own construction, bound to a file INSIDE this scanned
    repo (stdlib modules are never scanned-repo files), so its keys are
    exactly "resolvable to something repo-internal", never a guess."""
    module_aliases: dict[str, str] = {}
    symbol_aliases: dict[str, str] = {}
    if f.tree is not None:
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in _SINK_MODULES and alias.asname:
                        module_aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.module in _SINK_MODULES:
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        local = alias.asname or alias.name
                        symbol_aliases[local] = f"{node.module}.{alias.name}"
    local_names: set[str] = set(local_func_names or ())
    if files_by_rel is not None:
        local_names |= set(_build_import_map(f, files_by_rel).keys())
    return _SinkFileCtx(
        module_aliases=module_aliases,
        symbol_aliases=symbol_aliases,
        local_names=frozenset(local_names),
    )


def _canonicalize_dotted(name: str, module_aliases: dict[str, str]) -> str:
    """Rewrite ``name``'s head module component via ``module_aliases`` when
    aliased (``"sp.run"`` -> ``"subprocess.run"`` for ``import subprocess as
    sp``). Non-aliased or bare names pass through untouched."""
    if "." not in name or not module_aliases:
        return name
    head, _, rest = name.partition(".")
    return f"{module_aliases[head]}.{rest}" if head in module_aliases else name


def _resolved_sink_name(call: ast.Call, ctx: "_SinkFileCtx | None") -> tuple[str, bool]:
    """Returns ``(canonical_name, is_attr)``: the callee's real dotted
    ``module.attr`` spelling when resolvable via ``ctx`` (a module alias for
    an attribute call, or a direct stdlib-sink import for a bare call), else
    the raw ``_dotted`` rendering unchanged. Shared by
    ``_is_mutating_sink_call`` (breadth) and ``_is_high_risk_sink_call``
    (severity calibration) so both see through the identical aliasing --
    closing the aliased-import calibration gap (round-2 N-vote fix, refuter
    A item 4): ``import subprocess as sp; sp.run(cmd)`` (no ``shell=True``)
    now correctly calibrates to P2, not an unconditional P1."""
    name = _dotted(call.func)
    is_attr = isinstance(call.func, ast.Attribute)
    if ctx is None:
        return name, is_attr
    if is_attr:
        return _canonicalize_dotted(name, ctx.module_aliases), is_attr
    if name in ctx.symbol_aliases:
        return ctx.symbol_aliases[name], is_attr
    return name, is_attr


def _is_mutating_sink_call(call: ast.Call, ctx: "_SinkFileCtx | None" = None) -> bool:
    """True when ``call`` is a dangerous sink, matched STRUCTURALLY -- never
    by substring, and never by whether a rendered string happens to contain
    a "." (see the round-2 N-vote fix comment above ``_SinkFileCtx`` for the
    full history of why that proxy was wrong on both sides). ``ctx`` (when
    provided) resolves module aliases, direct stdlib-sink imports, and
    repo-internal bare names; omitting it (``ctx=None``) degrades gracefully
    to "no resolution available" -- exact dotted/attribute-short-name
    matching still applies, only the bare-name resolution steps are skipped
    (every existing call site in this file now passes a real ``ctx``)."""
    name = _dotted(call.func)
    if not name:
        return False
    is_attr = isinstance(call.func, ast.Attribute)
    canon, _ = _resolved_sink_name(call, ctx)
    short = name.split(".")[-1] if "." in name else name

    if canon in _SINK_DOTTED_EXACT:
        return True

    if is_attr:
        # Structural: ANY real attribute access matches the short-name
        # fallback regardless of what the receiver is (fixes refuter B's
        # Path(x).unlink() / requests.Session().post() / get_proc().run()
        # -- _dotted collapses all three to a bare leaf with no "."; gating
        # on the rendered string's punctuation was the bug, not this test).
        if short in _MUTATING_SINK_SHORT:
            return True
    else:
        local_names = ctx.local_names if ctx is not None else frozenset()
        if name in local_names:
            # Resolvable to a repo-internal function (same-file def, or an
            # explicit same-repo import) -- not a sink BY ITSELF; the
            # one-hop resolver inspects its real body elsewhere. This is
            # the correct fix for the original _run_subprocess false
            # positive (the substring-fix lane's original bug).
            return False
        if short in _MUTATING_SINK_SHORT:
            # Unresolvable bare name (not a known stdlib-sink import, not a
            # repo-internal function) -- over-flag-safe fallback, restores
            # base's pre-existing catch on a bare call this pass can't
            # prove safe (fixes refuter A's P0: `from os import remove;
            # remove(path)` etc. are caught earlier via `canon`, but a
            # genuinely opaque bare `run(...)`/`post(...)` with no
            # resolvable origin at all still needs to over-flag, matching
            # base's original, pre-this-lane behavior).
            return True

    if short == "open":
        mode = None
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            mode = call.args[1].value
        for kw in call.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        if isinstance(mode, str) and any(c in mode for c in "wax"):
            return True
    return False


def _is_shell_true(call: ast.Call) -> bool:
    """True when ``call`` passes a truthy ``shell=`` keyword -- the
    well-known, AST-visible signature of real shell-injection risk for
    ``subprocess.run``/``Popen``/``call``/``check_output``/``check_call``
    (a string command interpreted by ``/bin/sh``, vs. a fixed argv LIST with
    no shell metacharacter interpretation when ``shell`` is absent/False)."""
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
            return True
    return False


def _is_high_risk_sink_call(call: ast.Call, ctx: "_SinkFileCtx | None" = None) -> bool:
    """A stricter subset of ``_is_mutating_sink_call``, used ONLY for
    SEVERITY/CONFIDENCE calibration -- never for the is-this-a-sink-at-all
    classification, which stays exactly as broad (over-flag-safe) via
    ``_is_mutating_sink_call``. The one axis where "is it a sink" and "is it
    HIGH severity" honestly diverge is ``subprocess.run``/``Popen``/
    ``call``/``check_output``/``check_call``: these accept a literal argv
    LIST with no shell interpretation unless ``shell=True`` is explicitly
    passed (see ``_is_shell_true``). Its absence -- a fixed argv list
    executed directly, e.g. vllm-ops-mcp's ``_run_subprocess(["nvidia-smi",
    "--query-gpu=..."], ...)`` read-only probe -- is a materially
    lower-risk shape than a shell-interpreted string command. Resolution
    (``_resolved_sink_name``) is applied FIRST so a module-aliased
    (``sp.run``) or bare-stdlib-imported (``from subprocess import run``)
    call is calibrated identically to the plain ``subprocess.run`` spelling
    -- round-2 N-vote fix, refuter A item 4. This is NOT a suppression:
    ``_is_mutating_sink_call`` still returns True for it (the finding still
    surfaces), only its severity/confidence are calibrated down (see
    ``run()``/``_scan_low_level_sdk()``). ``subprocess.getoutput``/
    ``getstatusoutput`` (always shell-interpreted, no ``shell=`` kwarg
    exists on either) are deliberately excluded from ``_SUBPROCESS_RUN_LIKE``
    and fall through to unconditional high-risk, same as ``os.system``/
    ``os.popen``/``os.remove``/``unlink``/``rmdir``/``shutil.rmtree``/
    ``move``/HTTP verbs/sendmail/open-for-write."""
    canon, _ = _resolved_sink_name(call, ctx)
    if canon in _SUBPROCESS_RUN_LIKE:
        return _is_shell_true(call)
    return _is_mutating_sink_call(call, ctx)


def _body_has_mutating_sink(node: ast.AST, ctx: "_SinkFileCtx | None" = None) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _is_mutating_sink_call(sub, ctx):
            return True
    return False


def _body_has_high_risk_sink(node: ast.AST, ctx: "_SinkFileCtx | None" = None) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _is_high_risk_sink_call(sub, ctx):
            return True
    return False


def _source_segment(f: SourceFile, node: ast.AST) -> str:
    try:
        seg = ast.get_source_segment(f.text, node)
        if seg:
            return seg
    except Exception:
        pass
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", start)
    if start is None:
        return ""
    return "\n".join(f.lines[start - 1:end])


def _strip_py_comments(src: str) -> str:
    """Best-effort comment-stripped copy of ``src`` so a ``# TODO: needs
    auth_required check`` comment never counts as gate evidence (P0 fix --
    comment text was previously indistinguishable from real gate code to the
    ``_GATE_HINT``/``_ENV_OPT_IN`` regex search). Falls back to the original
    text if tokenizing fails (e.g. an indented source segment -- a method
    body sliced out on its own -- isn't independently tokenizable); that
    fallback is no worse than the prior behavior, never better."""
    try:
        lines = src.splitlines(keepends=True)
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type != tokenize.COMMENT:
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            if srow == erow and 0 < srow <= len(lines):
                line = lines[srow - 1]
                lines[srow - 1] = line[:scol] + line[ecol:]
        return "".join(lines)
    except Exception:
        return src


def _node_has_gate(f: SourceFile, node: ast.AST) -> bool:
    deco_src = " ".join(_unparse(d) for d in getattr(node, "decorator_list", []))
    if _GATE_HINT.search(deco_src):
        return True
    body_src = _strip_py_comments(_source_segment(f, node))
    return bool(_GATE_HINT.search(body_src) or _ENV_OPT_IN.search(body_src))


def _module_level_env_gate(f: SourceFile) -> bool:
    """A top-level ``if not <env opt-in>: raise/return/sys.exit`` guard."""
    if f.tree is None:
        return False
    for node in f.tree.body:
        if isinstance(node, ast.If):
            cond_src = _unparse(node.test)
            if _ENV_OPT_IN.search(cond_src) or _GATE_HINT.search(cond_src):
                return True
    return False


# --------------------------------------------------------------------- #
# Round-2 N-vote fix (2026-07-23, later same day): bounded, one-hop,
# import-aware call resolution for the decorator path.
#
# The round-1 same-file-only fix (closing the original repo-wide
# gate-index-collision follow-up) was itself proven to over-correct by two
# live refuter repros: (P0-1) it severed the cross-file SINK hop, not just
# the gate hop, silencing a genuinely ungated real sink reached through an
# explicit, same-repo import; (P0-2) same-file bare-name resolution still
# unioned gate status across UNRELATED same-named methods on different
# classes in one file.
#
# This resolver restores cross-file coverage, but only for an EXPLICIT,
# statically-provable same-repo import -- never a guess, never transitive
# (one hop only): ``import mod [as alias]``, ``from x.y import z [as w]``,
# and their relative-import equivalents (``from . import submodule`` /
# ``from .pkg.mod import name`` / ``from ..pkg import name``). A same-file
# call through a class instance/class name it can cheaply prove
# (``ClassName().method(...)`` / ``ClassName.method(...)``) is resolved to
# that EXACT class's own method, never confused with a same-named method on
# an unrelated class in the same file. Everything else falls back to the
# pre-existing same-file bare-name heuristic, now paired with an explicit
# ambiguity rule: when more than one same-file bare-name candidate exists
# and they disagree on gate status, the call's gate credit is withheld
# (over-flag, the conservative direction for a security scanner) rather
# than unioned.
# --------------------------------------------------------------------- #
def _dir_parts(rel: str) -> list[str]:
    parts = rel.split("/")
    return parts[:-1]


def _module_files(parts: list[str]) -> tuple[str, str]:
    """The two candidate repo-relative paths a dotted module ``parts`` could
    resolve to: a plain module file, or a package's ``__init__.py``."""
    base = "/".join(parts)
    return f"{base}.py", f"{base}/__init__.py"


def _resolve_from_import_base(
    base_dir_parts: list[str], module: str | None, level: int
) -> list[str] | None:
    """The dotted-path parts an ``ImportFrom`` node's ``module``/``level``
    point at, BEFORE appending an individual imported name -- ``None`` when
    unresolvable (a relative import walking above the repo root, or an
    absolute import with no module string, e.g. a bare ``from . import
    x`` has ``module=None`` and is handled by the ``level`` branch)."""
    if level and level > 0:
        parts = list(base_dir_parts)
        for _ in range(level - 1):
            if not parts:
                return None
            parts.pop()
        if module:
            parts = parts + module.split(".")
        return parts
    if not module:
        return None
    return module.split(".")


def _build_import_map(
    f: SourceFile, files_by_rel: dict[str, SourceFile]
) -> dict[str, tuple[SourceFile, str | None]]:
    """local binding name -> ``(resolved_file, symbol)`` for every explicit,
    statically-resolvable same-repo import in file ``f``. ``symbol`` is
    ``None`` when the local name is bound to ``resolved_file`` AS A MODULE
    (a submodule import, e.g. ``from .groups import write`` -- attribute
    access on the local name resolves a function defined in that file);
    it is the real defined name when the local name is bound directly to a
    symbol living in ``resolved_file`` (e.g. ``from .groups.write import
    delete_file``).

    Bounded and honest: only ``import x[.y][ as z]`` and ``from x[.y] import
    z [as w]`` (absolute or relative) resolving to a file actually present
    in this scan are recorded. A dynamic import, a re-export, a name
    reassigned after import, or a target outside the scanned repo is simply
    ABSENT from this map -- callers must treat that as an honest miss, never
    guess a target."""
    out: dict[str, tuple[SourceFile, str | None]] = {}
    if f.tree is None:
        return out
    base_dir_parts = _dir_parts(f.rel)
    for node in ast.walk(f.tree):
        if isinstance(node, ast.ImportFrom):
            target_parts = _resolve_from_import_base(base_dir_parts, node.module, node.level or 0)
            if target_parts is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                # Prefer the SUBMODULE reading first (`from .groups import
                # write` -- "write" is groups/write.py, the dominant real
                # fleet shape): does target_parts + [alias.name] resolve to
                # an actual file?
                sub_py, sub_pkg = _module_files(target_parts + [alias.name])
                if sub_py in files_by_rel:
                    out[local] = (files_by_rel[sub_py], None)
                    continue
                if sub_pkg in files_by_rel:
                    out[local] = (files_by_rel[sub_pkg], None)
                    continue
                # Otherwise: a plain "from module import symbol" -- the
                # symbol is defined directly IN the resolved module file.
                mod_py, mod_pkg = _module_files(target_parts)
                if mod_py in files_by_rel:
                    out[local] = (files_by_rel[mod_py], alias.name)
                elif mod_pkg in files_by_rel:
                    out[local] = (files_by_rel[mod_pkg], alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                local = alias.asname or parts[0]
                if alias.asname is None and len(parts) > 1:
                    # ``import pkg.sub`` with no alias binds only the TOP
                    # package name per real Python semantics, which cannot
                    # usefully resolve a specific submodule file here --
                    # an honest miss rather than a guessed target.
                    continue
                mod_py, mod_pkg = _module_files(parts)
                if mod_py in files_by_rel:
                    out[local] = (files_by_rel[mod_py], None)
                elif mod_pkg in files_by_rel:
                    out[local] = (files_by_rel[mod_pkg], None)
    return out


def _class_methods_in_file(f: SourceFile) -> dict[tuple[str, str], ast.AST]:
    """``(ClassName, method_name) -> FunctionDef/AsyncFunctionDef`` for every
    method defined directly in a class body in file ``f`` -- used only for
    the cheap ``ClassName().method(...)`` / ``ClassName.method(...)``
    call-site disambiguation (P0-2 fix)."""
    out: dict[tuple[str, str], ast.AST] = {}
    if f.tree is None:
        return out
    for node in ast.walk(f.tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[(node.name, item.name)] = item
    return out


def _enclosing_class_name(f: SourceFile, node: ast.AST) -> str | None:
    """Name of the ``ClassDef`` whose body directly contains ``node`` as a
    method, or ``None`` -- used only for the cheap ``self.``/``cls.``
    call-site disambiguation (a tool function that is itself a class
    method, calling a sibling method on its own instance/class)."""
    if f.tree is None:
        return None
    for candidate in ast.walk(f.tree):
        if isinstance(candidate, ast.ClassDef) and node in candidate.body:
            return candidate.name
    return None


def _find_functions_named(f: SourceFile, name: str) -> list[ast.AST]:
    """Every ``FunctionDef``/``AsyncFunctionDef`` in file ``f`` (any nesting
    depth) named ``name``."""
    if f.tree is None:
        return []
    return [
        n for n in ast.walk(f.tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    ]


class ToolScopeCreepDetector(Detector):
    name = "tool-scope-creep"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        # Round-2 N-vote fix (2026-07-23, later same day): repo-wide index
        # of every scanned file by its rel path, shared by every file's
        # import-map resolution below (see the module-level docstring for
        # the full history: round 1 scoped this same-file-only, which
        # over-corrected -- severing genuinely resolvable cross-file hops
        # too; round 2 restores them, bounded to explicit same-repo
        # imports only, never a guess).
        files_by_rel: dict[str, SourceFile] = {sf.rel: sf for sf in ctx.files}

        for f in ctx.files:
            if f.tree is None:
                continue
            module_gate = _module_level_env_gate(f)
            # Same-file bare-name fallback (round-1 convention, still used
            # when a call resolves via neither an explicit import nor a
            # cheap class-qualified disambiguation -- see
            # _resolve_call_targets).
            func_index = self._build_function_index_for_file(f)
            import_map = _build_import_map(f, files_by_rel)
            class_methods = _class_methods_in_file(f)
            # Round-2 N-vote fix (2026-07-23, sink-substring-fix lane):
            # per-file sink-resolution context (module aliases, direct
            # stdlib-sink imports, repo-internal bare names) -- see
            # `_SinkFileCtx`. Per-candidate-file contexts (a one-hop target
            # in a DIFFERENT file) are built lazily inside `_inspect_body`.
            f_sink_ctx = _build_sink_file_ctx(f, files_by_rel, local_func_names=set(func_index.keys()))
            for node in ast.walk(f.tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                tool_deco = None
                for deco in node.decorator_list:
                    if _is_tool_decorator(deco):
                        tool_deco = deco
                        break
                if tool_deco is None:
                    continue

                tool_name = _declared_tool_name(tool_deco, node.name)
                by_name = bool(_MUTATING_VERB.match(tool_name)) or bool(_MUTATING_VERB.match(node.name))
                sink_hit, indirect_gate, high_risk_hit = self._inspect_body(
                    node, f, files_by_rel, import_map, class_methods, func_index, f_sink_ctx
                )
                is_mutating = by_name or sink_hit
                if not is_mutating:
                    continue

                gated = _node_has_gate(f, node) or indirect_gate or module_gate
                if gated:
                    continue

                # Round 3 (2026-07-23): severity/confidence are keyed on
                # high_risk_hit, not the broader sink_hit -- see
                # `_is_high_risk_sink_call` for the one deliberate axis where
                # they diverge (subprocess without shell=True).
                sev = Severity.P1 if high_risk_hit else Severity.P2
                conf = Confidence.HIGH if high_risk_hit else Confidence.MEDIUM
                findings.append(Finding(
                    vuln_class=self.name,
                    title=f"Mutating tool '{tool_name}' has no visible permission gate",
                    severity=sev, confidence=conf,
                    file=f.rel, line=node.lineno,
                    detail=(
                        f"'{tool_name}' is registered as an MCP tool and looks mutating "
                        f"({'a dangerous sink is reachable from its body' if sink_hit else 'by its name'}), "
                        "but neither the tool function, its file, nor a directly-called "
                        "helper shows a permission-group gate, env-flag opt-in, or "
                        "explicit auth check. Any caller (the LLM, or anything that can "
                        "reach this MCP server) can invoke it unconditionally."
                    ),
                    remediation=(
                        "Gate every mutating tool behind an explicit, default-OFF "
                        "env flag and/or permission-group check enforced at the "
                        "function level (not just documented) — e.g. a "
                        "`@gated_write`-style decorator on the tool or the helper "
                        "it calls, checked before any side effect runs."
                    ),
                    snippet=f.line_at(node.lineno),
                ))
            if _file_imports_mcp(f):
                findings.extend(self._scan_low_level_sdk(f))
        findings.extend(self._scan_js(ctx))
        return findings

    # --- low-level MCP SDK: call_tool dispatch handler --------------------
    def _scan_low_level_sdk(self, f: SourceFile) -> list[Finding]:
        handlers = _decorated_in_file(f, _is_call_tool_decorator)
        if len(handlers) != 1:
            # Zero, or more than one, call_tool handler in this file --
            # never guess a root (mirrors _extract_low_level_sdk).
            return []
        handler = handlers[0]
        # Same-file-only (see _build_function_index_for_file docstring) --
        # this handler gets its own fresh index built from ITS file, same
        # convention the decorator path in run() now uses for its file too.
        file_func_index = self._build_function_index_for_file(f)
        file_gated_names = self._build_gate_index(file_func_index)
        # Round-2 N-vote fix (2026-07-23): same-file-only sink-resolution
        # context (this path stays same-file-only by pre-existing
        # convention, see _build_function_index_for_file's docstring) --
        # still resolves module aliases and direct stdlib-sink imports
        # written in THIS file, and treats this file's own function names
        # as repo-internal (not raw external calls).
        file_sink_ctx = _build_sink_file_ctx(f, local_func_names=set(file_func_index.keys()))
        module_gate = _module_level_env_gate(f)
        decorator_src = " ".join(_unparse(d) for d in getattr(handler, "decorator_list", []))
        decorator_gate = bool(_GATE_HINT.search(decorator_src))

        segments = dispatch_segments(handler)
        # 2026-07-23 P0-1 N-vote fix: gate detection is now PER-BRANCH. A
        # gate hint anywhere in the handler's FULL body text used to gate
        # every branch (a hint in one branch silenced an ungated sibling --
        # the refuter's live repro: an `is_authorized` check in a read_file
        # branch silenced delete_file's own ungated os.remove() in the same
        # handler). Only a genuinely shared segment (statements BEFORE the
        # if/elif dispatch chain, ``shared=True`` from ``dispatch_segments``
        # -- e.g. a `if not check_permission(name): raise` guard that runs
        # unconditionally for every branch) legitimately gates every OTHER
        # segment too; the handler's own decorator and any module-level gate
        # still apply repo/file-wide as before.
        shared_prefix_gate = any(
            shared and self._stmts_have_gate(f, stmts) for _, stmts, shared in segments
        )
        shared_gate = module_gate or decorator_gate or shared_prefix_gate

        out: list[Finding] = []
        for tool_name, stmts, _shared in segments:
            sink_hit, indirect_gate, high_risk_hit = self._inspect_stmts(
                stmts, file_func_index, file_gated_names, file_sink_ctx
            )
            by_name = bool(tool_name) and bool(_MUTATING_VERB.match(tool_name))
            is_mutating = by_name or sink_hit
            if not is_mutating:
                continue

            gated = shared_gate or indirect_gate or self._stmts_have_gate(f, stmts)
            if gated:
                continue

            # Round 3 (2026-07-23): see the matching comment in run() --
            # severity/confidence key on high_risk_hit, not sink_hit.
            sev = Severity.P1 if high_risk_hit else Severity.P2
            conf = Confidence.HIGH if high_risk_hit else Confidence.MEDIUM
            line = stmts[0].lineno if stmts else handler.lineno
            if tool_name:
                subject = f"Tool '{tool_name}'"
                title = f"Mutating tool '{tool_name}' has no visible permission gate"
            else:
                subject = f"An unattributed branch of the '{handler.name}' dispatch handler"
                title = (
                    f"Mutating branch of low-level dispatch handler '{handler.name}' "
                    "has no visible permission gate (tool not attributable)"
                )
            out.append(Finding(
                vuln_class=self.name,
                title=title,
                severity=sev, confidence=conf,
                file=f.rel, line=line,
                detail=(
                    f"{subject} looks mutating "
                    f"({'a dangerous sink is reachable from its body' if sink_hit else 'by its name'}), "
                    "but no permission-group gate, env-flag opt-in, or explicit auth check is "
                    "visible on the dispatch handler, this branch, or a directly-called helper. "
                    "Any caller (the LLM, or anything that can reach this MCP server) can invoke "
                    "it unconditionally."
                ),
                remediation=(
                    "Gate every mutating tool behind an explicit, default-OFF env flag and/or "
                    "permission-group check enforced before any side effect runs — e.g. a shared "
                    "check at the top of the dispatch handler, or per-branch, checked before the "
                    "sink executes."
                ),
                snippet=f.line_at(line),
            ))
        return out

    def _inspect_stmts(
        self,
        stmts: list[ast.stmt],
        func_index: dict,
        gated_names: set,
        sink_ctx: "_SinkFileCtx | None" = None,
    ) -> tuple[bool, bool, bool]:
        """Same one-hop helper-delegation logic as ``_inspect_body``, scoped
        to a ``dispatch_segments`` branch (a list of statements) instead of a
        single function node. Returns (sink_hit, indirect_gate,
        high_risk_hit) -- ``high_risk_hit`` (round 3, 2026-07-23) mirrors
        ``_inspect_body``'s severity-calibration signal; see
        ``_is_high_risk_sink_call``. ``sink_ctx`` (round-2 N-vote fix pass)
        is same-file-only by this path's pre-existing convention, so a
        single context is reused for both the direct statements and every
        resolved same-file candidate below."""
        sink_hit = any(_body_has_mutating_sink(s, sink_ctx) for s in stmts)
        high_risk_hit = any(_body_has_high_risk_sink(s, sink_ctx) for s in stmts)
        indirect_gate = False
        for stmt in stmts:
            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue
                dotted = _dotted(sub.func)
                short = dotted.split(".")[-1] if dotted else ""
                if not short or short not in func_index:
                    continue
                for _cf, cnode in func_index[short]:
                    if not sink_hit and _body_has_mutating_sink(cnode, sink_ctx):
                        sink_hit = True
                    if not high_risk_hit and _body_has_high_risk_sink(cnode, sink_ctx):
                        high_risk_hit = True
                    if short in gated_names:
                        indirect_gate = True
        return sink_hit, indirect_gate, high_risk_hit

    def _stmts_have_gate(self, f: SourceFile, stmts: list[ast.stmt]) -> bool:
        if not stmts:
            return False
        body_src = _strip_py_comments("\n".join(_source_segment(f, s) for s in stmts))
        return bool(_GATE_HINT.search(body_src) or _ENV_OPT_IN.search(body_src))

    # --- JS/TS: line-window sink/gate regex (no AST available) -----------
    def _scan_js(self, ctx: RepoContext) -> list[Finding]:
        regs = [r for r in extract_tool_registry(ctx) if r.source == "js-regex"]
        if not regs:
            return []
        by_file: dict[str, list] = {}
        for r in regs:
            by_file.setdefault(r.file, []).append(r)

        out: list[Finding] = []
        for f in ctx.files:
            if f.rel not in by_file:
                continue
            regs_in_file = sorted(by_file[f.rel], key=lambda r: r.line)
            for idx, r in enumerate(regs_in_file):
                start = r.line
                next_line = (
                    regs_in_file[idx + 1].line if idx + 1 < len(regs_in_file) else len(f.lines) + 1
                )
                end = min(next_line - 1, start + _JS_WINDOW_MAX_LINES, len(f.lines))
                window_lines = f.lines[start - 1:end]
                window = "\n".join(window_lines)
                # Comment-stripped copy used ONLY for gate-hint matching (P0
                # fix): a '// TODO: needs auth_required check' comment must
                # never count as gate evidence. Sink matching stays on the
                # raw window -- a sink pattern glued inside a comment is an
                # over-flag, the direction this scanner already accepts.
                gate_window = "\n".join(
                    js_util.code_part(raw) for raw in window_lines
                    if not js_util.is_comment_line(raw)
                )

                tool_label = r.name if r.name and r.name != "(inline)" else "(unnamed tool)"
                by_name = bool(_MUTATING_VERB.match(tool_label))
                sink_hit = bool(_JS_MUTATING_SINK.search(window))
                if not (by_name or sink_hit):
                    continue

                gated = bool(_GATE_HINT.search(gate_window)) or bool(_JS_ENV_OPT_IN.search(gate_window))
                if gated:
                    continue

                sev = Severity.P1 if sink_hit else Severity.P2
                conf = Confidence.HIGH if sink_hit else Confidence.MEDIUM
                out.append(Finding(
                    vuln_class=self.name,
                    title=f"Mutating tool '{tool_label}' has no visible permission gate",
                    severity=sev, confidence=conf,
                    file=f.rel, line=r.line,
                    detail=(
                        f"'{tool_label}' is registered as an MCP tool (JS/TS "
                        f"regex-detected) and looks mutating "
                        f"({'a dangerous sink appears in its body window' if sink_hit else 'by its name'}), "
                        "but no permission-group gate or env-flag opt-in was found in "
                        "the line window from its registration to the next tool "
                        "registration (or 40 lines, whichever is shorter -- there is "
                        "no JS/TS AST in this scanner to delimit the real function "
                        "body)."
                    ),
                    remediation=(
                        "Gate every mutating tool behind an explicit, default-OFF "
                        "env flag and/or permission-group check enforced before any "
                        "side effect runs."
                    ),
                    snippet=f.line_at(r.line),
                ))
        return out

    # --- helpers ------------------------------------------------------
    def _resolve_call_targets(
        self,
        call: ast.Call,
        f: SourceFile,
        calling_node: ast.AST,
        files_by_rel: dict[str, SourceFile],
        import_map: dict[str, tuple[SourceFile, str | None]],
        class_methods: dict[tuple[str, str], ast.AST],
        same_file_func_index: dict,
    ) -> list[tuple[SourceFile, ast.AST]] | None:
        """Resolve one call's target function(s), bounded, one hop, no
        transitivity (round-2 N-vote fix). Returns a list of every
        candidate ``(file, FunctionDef)`` a genuinely mutating-tool-relevant
        call could reach when resolvable at all, or ``None`` when the call
        cannot be resolved by this pass -- an honest miss, never guessed
        (gate is not credited and sink is not followed for THIS call; see
        the module docstring for the disclosed residual on non-mutating-
        named tools).

        Resolution order, first match wins:

          1. IMPORT-AWARE -- ``local(...)`` or ``local.attr(...)`` where
             ``local`` is bound by an explicit same-repo import in this
             file (see ``_build_import_map``). Unambiguous by construction:
             exactly one target file, matched by name in it.
          2. SAME-FILE CLASS-QUALIFIED (cheap disambiguation) --
             ``ClassName().method(...)`` / ``ClassName.method(...)`` /
             ``self.method(...)`` or ``cls.method(...)`` from within a
             method of the SAME class -- resolves to that exact class's
             own method, never confused with an unrelated same-named
             method on a different class in the same file (P0-2 fix).
          3. SAME-FILE BARE NAME -- the pre-existing fallback: every
             function in this file sharing the call's bare short name is a
             candidate. Genuinely ambiguous when more than one exists;
             callers apply an OR-for-sink / AND-for-gate rule across the
             returned candidates (over-flag on disagreement, never a
             unioned false gate credit)."""
        dotted = _dotted(call.func)
        if not dotted:
            return None
        parts = dotted.split(".")

        # -- 1. import-aware -------------------------------------------
        head = parts[0]
        if head in import_map:
            target_file, symbol = import_map[head]
            if symbol is None:
                # `head` is bound to a MODULE file (submodule import) --
                # the real function is the call's own last attribute.
                if len(parts) == 2:
                    found = _find_functions_named(target_file, parts[1])
                    return [(target_file, n) for n in found] if found else None
                return None
            # `head` is bound directly to a symbol defined in target_file --
            # only a bare call on that exact name is within this one-hop
            # scope (a further `.attr` on it is out of bounds).
            if len(parts) == 1:
                found = _find_functions_named(target_file, symbol)
                return [(target_file, n) for n in found] if found else None
            return None

        # -- 2. same-file class-qualified (cheap disambiguation) --------
        func_node = call.func
        if isinstance(func_node, ast.Attribute):
            method_name = func_node.attr
            receiver = func_node.value
            class_name: str | None = None
            if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name):
                class_name = receiver.func.id           # ClassName().method(...)
            elif isinstance(receiver, ast.Name) and receiver.id not in ("self", "cls"):
                class_name = receiver.id                 # ClassName.method(...)
            elif isinstance(receiver, ast.Name) and receiver.id in ("self", "cls"):
                class_name = _enclosing_class_name(f, calling_node)
            if class_name is not None and (class_name, method_name) in class_methods:
                return [(f, class_methods[(class_name, method_name)])]

        # -- 3. same-file bare name (fallback) --------------------------
        short = parts[-1]
        if short and short in same_file_func_index:
            return [(cf, cn) for cf, cn in same_file_func_index[short]]
        return None

    def _sink_ctx_for_file(
        self,
        cf: SourceFile,
        files_by_rel: dict[str, SourceFile],
        cache: dict[str, "_SinkFileCtx"],
    ) -> "_SinkFileCtx":
        """Lazily build (and cache) ``cf``'s own sink-resolution context --
        a one-hop-resolved candidate can live in a DIFFERENT file than the
        tool being inspected, and bare-name resolution must be evaluated
        against THAT file's own imports/function definitions, never the
        original tool's file's context (round-2 N-vote fix)."""
        cached = cache.get(cf.rel)
        if cached is not None:
            return cached
        local_names = set(self._build_function_index_for_file(cf).keys())
        built = _build_sink_file_ctx(cf, files_by_rel, local_func_names=local_names)
        cache[cf.rel] = built
        return built

    def _inspect_body(
        self,
        node: ast.AST,
        f: SourceFile,
        files_by_rel: dict[str, SourceFile],
        import_map: dict[str, tuple[SourceFile, str | None]],
        class_methods: dict[tuple[str, str], ast.AST],
        same_file_func_index: dict,
        f_sink_ctx: "_SinkFileCtx | None" = None,
    ) -> tuple[bool, bool, bool]:
        """Return (sink_hit, indirect_gate, high_risk_hit) considering one
        hop through any helper function this tool's body plainly calls --
        import-aware first, then same-file (round-2 N-vote fix; see
        ``_resolve_call_targets``). ``high_risk_hit`` (round 3, 2026-07-23)
        is a strict subset of ``sink_hit`` used only for severity/confidence
        calibration -- see ``_is_high_risk_sink_call``; it never widens or
        narrows ``sink_hit``/``indirect_gate``, which keep their pre-round-3
        over-flag-safe semantics unchanged. ``f_sink_ctx`` (round-2 N-vote
        fix pass) resolves ``f``'s own bare/aliased calls; a resolved
        candidate living in a DIFFERENT file gets its OWN freshly-built
        context via ``_sink_ctx_for_file``, never ``f``'s -- a bare name is
        only "repo-internal" relative to the file it's written in."""
        sink_hit = _body_has_mutating_sink(node, f_sink_ctx)
        high_risk_hit = _body_has_high_risk_sink(node, f_sink_ctx)
        indirect_gate = False
        candidate_ctx_cache: dict[str, "_SinkFileCtx"] = {}
        if f_sink_ctx is not None:
            candidate_ctx_cache[f.rel] = f_sink_ctx
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            candidates = self._resolve_call_targets(
                sub, f, node, files_by_rel, import_map, class_methods, same_file_func_index
            )
            if not candidates:
                continue
            candidates = [(cf, cn) for cf, cn in candidates if cn is not node]
            if not candidates:
                continue
            any_sink = any(
                _body_has_mutating_sink(cn, self._sink_ctx_for_file(cf, files_by_rel, candidate_ctx_cache))
                for cf, cn in candidates
            )
            any_high_risk = any(
                _body_has_high_risk_sink(cn, self._sink_ctx_for_file(cf, files_by_rel, candidate_ctx_cache))
                for cf, cn in candidates
            )
            all_gated = all(_node_has_gate(cf, cn) for cf, cn in candidates)
            if any_sink and not sink_hit:
                sink_hit = True
            if any_high_risk and not high_risk_hit:
                high_risk_hit = True
            # Ambiguous candidates that disagree on gate status withhold
            # credit for THIS call (over-flag-safe, P0-2 fix) rather than
            # unioning any single gated candidate's status onto the whole
            # bare name.
            if all_gated:
                indirect_gate = True
        return sink_hit, indirect_gate, high_risk_hit

    def _build_function_index_for_file(self, f: SourceFile) -> dict:
        """name -> [(SourceFile, FunctionDef/AsyncFunctionDef), ...] within
        this ONE file only. Shared by both the decorator-registered path
        (``run()``) and the low-level SDK dispatch path (``_scan_low_level_sdk``)
        for their one-hop helper-delegation gate resolution.

        2026-07-23 history: first added same-file-only for the low-level SDK
        path only (self-caught during the P0-2 N-vote fix pass), while the
        pre-existing decorator-registered path still built its own index
        REPO-WIDE by bare short function name -- an N-vote refuter then
        proved live that an unrelated, never-imported, same-named gated
        helper elsewhere in the repo could silence a genuinely ungated
        decorator-registered mutating tool (false NEGATIVE, worse direction
        than a false positive). The decorator path was moved onto this same
        same-file-only index the same day, closing that gap; the old
        repo-wide ``_build_function_index`` is retired. Same-file-only
        matches the same-file-only ``Tool()``<->dispatcher correlation
        precedent already shipped for reachability: a helper in another file
        that isn't provably reachable this way is an honest miss (the tool
        then flags as ungated -- the over-flag direction this detector's own
        docs already accept), disclosed, never a guessed hit."""
        idx: dict[str, list[tuple[SourceFile, ast.AST]]] = {}
        if f.tree is None:
            return idx
        for node in ast.walk(f.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                idx.setdefault(node.name, []).append((f, node))
        return idx

    def _build_gate_index(self, func_index: dict) -> set:
        gated: set[str] = set()
        for name, entries in func_index.items():
            for f, node in entries:
                if _node_has_gate(f, node):
                    gated.add(name)
                    break
        return gated
