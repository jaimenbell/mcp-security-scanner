"""Detector 7 -- job-hazards: scheduled-job / wrapper / IaC-CI reliability hazards.

Every existing detector (1-6) reads *MCP server* source (Python tool
handlers, Jinja templates, JS/TS). None of them ever look at the files the
reliability-retainer audit pitch actually promises to sweep: cron wrappers,
systemd units, GitHub Actions workflows, and PowerShell/bash/batch deploy
scripts. This detector -- plus the ``scanner.py`` file-type extension that
ships alongside it -- closes that gap.

Three sub-checks, one detector (mirrors ``secret_handling.py``'s shape: one
``Detector`` subclass, multiple ``vuln_class`` ids):

1. ``job-overbroad-scope`` -- a token/permission/ACL grant scoped wider than
   any single job plausibly needs: GitHub Actions ``permissions: write-all``,
   ``icacls ... /grant Everyone:F``, ``chmod 777``, or an IAM-policy-shaped
   ``"Action": "*"`` / ``"Resource": "*"`` pair.
2. ``job-destructive-no-confirm`` -- a destructive call (``rm -rf``,
   ``Remove-Item -Recurse -Force``, ``terraform destroy``, ``kubectl delete``,
   ``git push --force``, ``git reset --hard``, ``DROP TABLE/DATABASE``,
   ``docker system prune``/``volume rm``, ``schtasks /delete``,
   ``aws s3 rm --recursive``) with no confirm-before-destroy gate. An
   explicit ``-Confirm:$false`` (actively disabling PowerShell's own
   built-in prompt) is the strongest negative signal and escalates to P0;
   the mere absence of any dry-run/prompt/confirm hint anywhere in the file
   (same-file heuristic, consistent with this repo's other detectors) is P1.
3. ``job-unverified-success`` -- a job that can report "done" without
   verifying what it touched: an empty ``catch {}`` block (PowerShell
   silent-swallow), ``continue-on-error: true`` on a workflow step,
   ``|| true`` masking a command's exit code, or a bare ``; exit 0`` tacked
   onto a command that can fail.

Honesty note: same as every other detector in this repo -- these are
same-file regex heuristics over cron/systemd/CI/wrapper text, not a real
parser for YAML/PowerShell/bash semantics, and not proof any flagged call is
actually reachable or actually undesired. Over-flagging is by design; a
human confirms each candidate (see PRODUCT.md / the retainer pitch this
detector makes literally true).
"""

from __future__ import annotations

import re

from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

# --- job/wrapper/IaC file surface -----------------------------------------
_JOB_SUFFIXES = {".yml", ".yaml", ".ps1", ".sh", ".bash", ".bat", ".cmd", ".service", ".timer"}

# --- 1. overbroad credential/token/ACL scope --------------------------------
_WRITE_ALL_PERMS = re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.IGNORECASE | re.MULTILINE)
_ICACLS_EVERYONE_FULL = re.compile(r"icacls\b.*\bEveryone\b\s*:?\s*\(?F\)?", re.IGNORECASE)
_CHMOD_777 = re.compile(r"\bchmod\b\s+(-R\s+)?777\b")
_IAM_WILDCARD_ACTION = re.compile(r'"Action"\s*:\s*"\*"')
_IAM_WILDCARD_RESOURCE = re.compile(r'"Resource"\s*:\s*"\*"')

# --- 2. destructive calls ---------------------------------------------------
_DESTRUCTIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\b", re.IGNORECASE), "rm -rf"),
    (re.compile(r"\brm\s+-[a-z]*f[a-z]*r[a-z]*\b", re.IGNORECASE), "rm -fr"),
    (re.compile(r"Remove-Item\b.*-Recurse\b.*-Force\b", re.IGNORECASE), "Remove-Item -Recurse -Force"),
    (re.compile(r"\bterraform\s+destroy\b", re.IGNORECASE), "terraform destroy"),
    (re.compile(r"\bkubectl\s+delete\b", re.IGNORECASE), "kubectl delete"),
    (re.compile(r"\bdocker\s+(system\s+prune|volume\s+rm)\b", re.IGNORECASE), "docker prune/volume rm"),
    (re.compile(r"\bgit\s+push\s+(--force\b|-f\b)", re.IGNORECASE), "git push --force"),
    (re.compile(r"\bgit\s+reset\s+--hard\b", re.IGNORECASE), "git reset --hard"),
    (re.compile(r"\bDROP\s+(TABLE|DATABASE)\b", re.IGNORECASE), "DROP TABLE/DATABASE"),
    (re.compile(r"schtasks\s+/delete\b", re.IGNORECASE), "schtasks /delete"),
    (re.compile(r"\baws\s+s3\s+rm\b.*--recursive\b", re.IGNORECASE), "aws s3 rm --recursive"),
    # --- backlog #1 (2026-07-21 fleet self-audit): PowerShell-native
    # destructive-task patterns. 'Remove-Item -Recurse -Force' was already
    # covered above (verified, no change needed).
    #
    # Two candidate siblings were evaluated and deliberately NOT added, both
    # for the same reason -- reversible (no data/task loss, just a state
    # flip or a process restart) AND confirmed, via live regression scan, to
    # fire on legitimate fleet code with no real reliability signal:
    #   - 'Disable-ScheduledTask': fires in 5+ tracked register_*.ps1
    #     scripts under the "register disabled, operator arms later"
    #     convention (shared repo).
    #   - 'Stop-Process -Force': fires on exit-strategy-portal's
    #     consumer_smoke.ps1:44, a `finally`-block cleanup of the script's
    #     OWN throwaway child process -- a normal teardown pattern, not a
    #     hazard.
    # Both would have regressed the zero-new-findings fleet gate.
    (re.compile(r"\bUnregister-ScheduledTask\b", re.IGNORECASE), "Unregister-ScheduledTask"),
]
_CONFIRM_FALSE = re.compile(r"-Confirm\s*:\s*\$false", re.IGNORECASE)
_INLINE_CONFIRM_GATE = re.compile(r"-WhatIf\b|--dry-run\b|-Confirm\b(?!\s*:\s*\$false)", re.IGNORECASE)
_FILE_CONFIRM_HINT = re.compile(
    r"(dry[_-]?run|read\s+-p\b|Read-Host\b|\bconfirm|\bapproval\b)", re.IGNORECASE
)

# --- in-body confirmation-gate idioms (FP-wave-2, 2026-07-23 ecosystem scan) -
# Some MCP servers/wrappers implement their OWN confirm-before-destroy gate
# inline rather than via the SDK's -Confirm/--dry-run flag: a REAL control-flow
# gate (early throw/exit/raise/return-of-nonsuccess) on a boolean param named
# force/yes/confirm/proceed/acknowledge. Recognise those as an equivalent
# safety control. CONSERVATIVE BY DESIGN -- the negated param check AND a
# control-flow exit must both be present and close together (bounded window),
# so a param merely *existing* is never mistaken for a gate. False-negative
# risk (missing a real gate -> we keep flagging) is cheaper than false-positive
# risk (inventing a gate -> we hide a real hazard). The param allowlist
# excludes 'destructiveHint', so a target's self-declaration can never enter
# through this suppression path (see the destructiveHint doctrine below).
_GATE_PARAM = r"(?:confirm|force|yes|proceed|acknowledge|i_am_sure)"
_GATE_EXIT = (
    r"(?:throw|raise|die|abort|sys\.exit|exit\s+[1-9]|"
    r"return\s+(?:[1-9]|false|none|[\"']))"
)
_INBODY_CONFIRM_GATE = re.compile(
    "(?:"
    + r"if[^\n]{0,10}?(?:-not|!\s*|\bnot\b)[^\n]{0,60}?\b" + _GATE_PARAM + r"\b"
    + r"[\s\S]{0,120}?\b" + _GATE_EXIT
    + r"|"
    + r"if\s+\[\s*-z\s+\"?\$\{?" + _GATE_PARAM + r"[\s\S]{0,120}?\b" + _GATE_EXIT
    + ")",
    re.IGNORECASE,
)
# NOTE (FP-wave-2 adjudication, 2026-07-23): a bare `are you sure` alternation
# was removed here. Unlike the two structural alternatives above (which require a
# negated boolean param AND a control-flow exit close together), a naked phrase
# match binds to no param and no control flow -- it "invents a gate" from
# unrelated display copy or a comment anywhere in the file (whole-file
# .search(f.text)), suppressing genuine unguarded destructive calls. That
# contradicts this regex's own conservative contract and a security scanner's
# honesty guarantee. Regression fixtures: tests/test_job_hazards_inbody_gate.py
# ::test_bare_areyousure_phrase_does_not_suppress.

# --- destructiveHint doctrine (FP-wave-2, 2026-07-23) ------------------------
# A target declaring the MCP 'destructiveHint: true' annotation is a SELF-
# declaration: informational only. Doctrine ("our curated judgments may demote;
# the target's self-declarations only reduce confidence, never visibility"):
# it may appear as CONTEXT on a finding but must NEVER suppress or downgrade
# severity/confidence. Implemented as a pure detail-string addendum -- it
# touches no severity, no confidence, and no suppression branch.
_DESTRUCTIVE_HINT_DECL = re.compile(r"\bdestructiveHint\b\s*[:=]\s*(?:true|True|1)\b")
_DESTRUCTIVE_HINT_NOTE = (
    " Context: this tool self-declares the MCP 'destructiveHint: true' "
    "annotation. That self-declaration is informational only -- it is recorded "
    "here as context and does not reduce the severity, confidence, or "
    "visibility of this finding."
)

# --- benign-idempotent-register suppressor (backlog #1) ---------------------
# The fleet's own register_*.ps1 scripts legitimately unregister-then-
# reregister the SAME task name (idempotent re-registration on every run).
# That pattern is benign and must not flag, even though it uses
# -Confirm:$false. Matched by task-name TOKEN equality (variable name or
# quoted literal) between the Unregister-ScheduledTask call and a LATER
# Register-ScheduledTask call in the same file -- a same-file regex
# heuristic, not a real PowerShell parser, consistent with this detector's
# stated honesty note.
_TASKNAME_ARG = re.compile(r"-TaskName\s+(\S+)", re.IGNORECASE)
_REGISTER_CALL = re.compile(r"\bRegister-ScheduledTask\b", re.IGNORECASE)


def _taskname_token(line_text: str) -> str | None:
    m = _TASKNAME_ARG.search(line_text)
    if not m:
        return None
    return m.group(1).strip("'\"`,")


def _has_matching_reregister(full_text: str, task_token: str, after_pos: int) -> bool:
    for m in _REGISTER_CALL.finditer(full_text, after_pos):
        window = full_text[m.end(): m.end() + 500]
        tn = _TASKNAME_ARG.search(window)
        if tn and tn.group(1).strip("'\"`,") == task_token:
            return True
    return False


def _line_start_offsets(lines: list[str]) -> list[int]:
    offsets = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    return offsets

# --- 3. success-reported-without-verification -------------------------------
_OR_TRUE = re.compile(r"\|\|\s*true\b")
_EXIT_0_AFTER_CMD = re.compile(r";\s*exit\s+0\s*$")
_CONTINUE_ON_ERROR = re.compile(r"continue-on-error\s*:\s*true", re.IGNORECASE)
_EMPTY_CATCH = re.compile(r"catch\s*\{\s*\}", re.IGNORECASE)

# --- unverified-success suppressor (backlog #2) ------------------------------
# An empty catch {} should not flag when the SAME file verifiably checks
# success downstream: a variable set in the try block, then asserted after
# (e.g. 'if (-not $ok) { throw ... }'). Implemented conservatively -- only
# this narrow, well-defined idiom suppresses; anything else keeps the flag
# (over-flag by design, per this detector's honesty note).
_DOWNSTREAM_SUCCESS_GUARD = re.compile(
    r"if\s*\(\s*(?:-not\s+\$\w+|!\s*\$\w+)\s*\)\s*\{[^}]*\b(throw|exit\s+1)\b",
    re.IGNORECASE | re.DOTALL,
)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# --- comment-line awareness (precision fix, 2026-07-21 fleet self-audit) -----
# A destructive/scope pattern that only appears in a full-comment line is
# documentation or a safety-tool's own pattern list -- never executed, never a
# hazard. Suppressing full-comment lines is a pure-precision win (zero recall
# cost: a real call would not be commented out). Only *full* comment lines are
# skipped; a real command with a trailing comment (`rm -rf x  # note`) still
# matches, so live code is never masked.
_HASH_COMMENT_SUFFIXES = {".sh", ".bash", ".ps1", ".yml", ".yaml", ".service", ".timer"}
_BATCH_COMMENT_SUFFIXES = {".bat", ".cmd"}
_REM_PREFIX = re.compile(r"^\s*rem\b", re.IGNORECASE)


def _is_comment_line(line: str, suffix: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return False
    if suffix in _HASH_COMMENT_SUFFIXES and stripped.startswith("#"):
        return True
    if suffix in _BATCH_COMMENT_SUFFIXES and (stripped.startswith("::") or _REM_PREFIX.match(line)):
        return True
    return False


# --- inline comment-tail stripping (backlog #4, 2026-07-21 fleet self-audit) -
# A destructive/scope pattern that only appears in a trailing ` # comment`
# tail is documentation, not a hazard -- strip the tail before matching. This
# is additive to (not a replacement for) the full-comment-line skip above: a
# real command with a trailing comment (`rm -rf x  # note`) still matches,
# because the pattern lives in the code part before the '#', which this
# strips *out* of, not away.
_INLINE_HASH_TAIL = re.compile(r"(?<=\s)#.*$")


def _code_part(line: str, suffix: str) -> str:
    if suffix in _HASH_COMMENT_SUFFIXES:
        return _INLINE_HASH_TAIL.sub("", line)
    return line


class JobHazardsDetector(Detector):
    name = "job-hazards"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        for f in ctx.files:
            if f.suffix not in _JOB_SUFFIXES:
                continue
            findings.extend(self._scope(f))
            findings.extend(self._destructive(f))
            findings.extend(self._unverified(f))
        return findings

    # --- 1. overbroad scope ------------------------------------------------
    def _scope(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        for m in _WRITE_ALL_PERMS.finditer(f.text):
            line = _line_of(f.text, m.start())
            out.append(self._f(
                "job-overbroad-scope", "GitHub Actions job grants write-all permissions",
                Severity.P1, Confidence.HIGH, f, line,
                "'permissions: write-all' grants this workflow write access to every "
                "GitHub API scope (contents, packages, issues, actions, ...) instead of "
                "the one or two scopes the job actually needs.",
                "Declare an explicit least-privilege 'permissions:' block naming only "
                "the scopes this job uses (e.g. 'contents: read', 'deployments: write').",
            ))
        for i, line_text in enumerate(f.lines, start=1):
            if _is_comment_line(line_text, f.suffix):
                continue
            code_line = _code_part(line_text, f.suffix)
            if _ICACLS_EVERYONE_FULL.search(code_line) or _CHMOD_777.search(code_line):
                out.append(self._f(
                    "job-overbroad-scope", "Filesystem ACL grants full control to everyone",
                    Severity.P1, Confidence.HIGH, f, i,
                    "Grants full read/write/execute to every local user/principal "
                    "instead of the specific service account the job runs as.",
                    "Grant the specific service principal only (e.g. "
                    "'icacls path /grant DeployService:F'), never 'Everyone'/777.",
                ))
        if _IAM_WILDCARD_ACTION.search(f.text) and _IAM_WILDCARD_RESOURCE.search(f.text):
            line = _line_of(f.text, _IAM_WILDCARD_ACTION.search(f.text).start())
            out.append(self._f(
                "job-overbroad-scope", "IAM-style policy grants '*' action on '*' resource",
                Severity.P1, Confidence.MEDIUM, f, line,
                "A policy document scopes both Action and Resource to wildcard, "
                "granting the credential far more than any single job needs.",
                "Scope Action/Resource to exactly what the job calls; least-privilege "
                "per job, not a blanket grant reused across jobs.",
            ))
        return out

    # --- 2. destructive call, no confirm gate -------------------------------
    def _destructive(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        offsets = _line_start_offsets(f.lines)
        hint_note = _DESTRUCTIVE_HINT_NOTE if _DESTRUCTIVE_HINT_DECL.search(f.text) else ""
        for i, line_text in enumerate(f.lines, start=1):
            if _is_comment_line(line_text, f.suffix):
                continue
            code_line = _code_part(line_text, f.suffix)
            for pat, label in _DESTRUCTIVE_PATTERNS:
                if not pat.search(code_line):
                    continue
                if label == "Unregister-ScheduledTask" and self._benign_reregister(f, code_line, offsets[i - 1]):
                    break  # idempotent unregister-then-reregister of the same task: benign
                if _CONFIRM_FALSE.search(code_line):
                    out.append(self._f(
                        "job-destructive-no-confirm",
                        f"Destructive call ({label}) with confirmation explicitly disabled",
                        Severity.P0, Confidence.HIGH, f, i,
                        f"'{label}' runs with '-Confirm:$false', actively suppressing "
                        "the built-in confirmation prompt in front of a destructive call."
                        + hint_note,
                        "Remove '-Confirm:$false' (or add an explicit dry-run/prompt "
                        "gate) so a human or an env-flag confirms before this runs.",
                    ))
                    break
                if _INLINE_CONFIRM_GATE.search(code_line):
                    break  # gated inline (-WhatIf / --dry-run / -Confirm)
                if _FILE_CONFIRM_HINT.search(f.text):
                    break  # same-file heuristic: a confirm/dry-run gate exists somewhere
                if _INBODY_CONFIRM_GATE.search(f.text):
                    break  # in-body control-flow gate on a force/confirm param (FP-wave-2)
                out.append(self._f(
                    "job-destructive-no-confirm",
                    f"Destructive call ({label}) with no confirm-before-destroy gate",
                    Severity.P1, Confidence.MEDIUM, f, i,
                    f"'{label}' is a destructive/irreversible call and no dry-run flag, "
                    "confirmation prompt, or env-gated approval was found anywhere in "
                    "this file."
                    + hint_note,
                    "Add a dry-run flag, an interactive/approval confirm step, or an "
                    "explicit env-gated opt-in before this call runs.",
                ))
                break
        return out

    @staticmethod
    def _benign_reregister(f: SourceFile, code_line: str, line_start: int) -> bool:
        """True iff this Unregister-ScheduledTask call names a task that a
        LATER Register-ScheduledTask call in the same file re-registers under
        the identical token (variable or quoted literal) -- the fleet's
        idempotent register_*.ps1 convention (backlog #1 suppressor)."""
        token = _taskname_token(code_line)
        if not token:
            return False
        return _has_matching_reregister(f.text, token, line_start)

    # --- 3. success reported without verification ---------------------------
    def _unverified(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        for i, line_text in enumerate(f.lines, start=1):
            if _is_comment_line(line_text, f.suffix):
                continue
            code_line = _code_part(line_text, f.suffix)
            if _OR_TRUE.search(code_line):
                out.append(self._f(
                    "job-unverified-success", "Command's exit status masked with '|| true'",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "'|| true' forces this step to always succeed regardless of "
                    "whether the command actually failed.",
                    "Remove '|| true'; let the job fail loudly, or explicitly check "
                    "and log the real exit code before deciding to continue.",
                ))
            if _EXIT_0_AFTER_CMD.search(code_line):
                out.append(self._f(
                    "job-unverified-success", "Script exits 0 unconditionally after a command",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "An explicit 'exit 0' tacked onto a preceding command reports "
                    "success to the caller/scheduler regardless of what the command "
                    "actually did.",
                    "Propagate the real exit code ('exit $?' / check '$LASTEXITCODE') "
                    "instead of hardcoding success.",
                ))
            if _CONTINUE_ON_ERROR.search(code_line):
                out.append(self._f(
                    "job-unverified-success", "Workflow step continues on error unconditionally",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "'continue-on-error: true' lets this step fail without failing the "
                    "job or surfacing the failure -- a downstream step can report "
                    "overall success on top of a step that silently didn't work.",
                    "Remove 'continue-on-error', or capture the step outcome and gate "
                    "on it explicitly later in the job.",
                ))
        # backlog #2 suppressor: an empty catch is not a hazard when the same
        # file verifiably checks success downstream (conservative -- narrow
        # idiom only, over-flag otherwise).
        if not _DOWNSTREAM_SUCCESS_GUARD.search(f.text):
            for m in _EMPTY_CATCH.finditer(f.text):
                line = _line_of(f.text, m.start())
                out.append(self._f(
                    "job-unverified-success", "Empty catch block silently swallows a failure",
                    Severity.P1, Confidence.HIGH, f, line,
                    "An empty PowerShell 'catch {}' block discards the exception with no "
                    "log, no rethrow, and no failure signal -- the wrapper can exit 0 even "
                    "though the guarded operation threw.",
                    "Log the exception and rethrow (or explicitly set a non-zero exit "
                    "code) instead of an empty catch block.",
                ))
        return out

    def _f(self, vc, title, sev, conf, f: SourceFile, line, detail, remediation) -> Finding:
        return Finding(
            vuln_class=vc, title=title, severity=sev, confidence=conf,
            file=f.rel, line=line, detail=detail, remediation=remediation,
            snippet=f.line_at(line),
        )
