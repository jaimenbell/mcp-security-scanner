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
]
_CONFIRM_FALSE = re.compile(r"-Confirm\s*:\s*\$false", re.IGNORECASE)
_INLINE_CONFIRM_GATE = re.compile(r"-WhatIf\b|--dry-run\b|-Confirm\b(?!\s*:\s*\$false)", re.IGNORECASE)
_FILE_CONFIRM_HINT = re.compile(
    r"(dry[_-]?run|read\s+-p\b|Read-Host\b|\bconfirm|\bapproval\b)", re.IGNORECASE
)

# --- 3. success-reported-without-verification -------------------------------
_OR_TRUE = re.compile(r"\|\|\s*true\b")
_EXIT_0_AFTER_CMD = re.compile(r";\s*exit\s+0\s*$")
_CONTINUE_ON_ERROR = re.compile(r"continue-on-error\s*:\s*true", re.IGNORECASE)
_EMPTY_CATCH = re.compile(r"catch\s*\{\s*\}", re.IGNORECASE)


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
            if _ICACLS_EVERYONE_FULL.search(line_text) or _CHMOD_777.search(line_text):
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
        for i, line_text in enumerate(f.lines, start=1):
            if _is_comment_line(line_text, f.suffix):
                continue
            for pat, label in _DESTRUCTIVE_PATTERNS:
                if not pat.search(line_text):
                    continue
                if _CONFIRM_FALSE.search(line_text):
                    out.append(self._f(
                        "job-destructive-no-confirm",
                        f"Destructive call ({label}) with confirmation explicitly disabled",
                        Severity.P0, Confidence.HIGH, f, i,
                        f"'{label}' runs with '-Confirm:$false', actively suppressing "
                        "the built-in confirmation prompt in front of a destructive call.",
                        "Remove '-Confirm:$false' (or add an explicit dry-run/prompt "
                        "gate) so a human or an env-flag confirms before this runs.",
                    ))
                    break
                if _INLINE_CONFIRM_GATE.search(line_text):
                    break  # gated inline (-WhatIf / --dry-run / -Confirm)
                if _FILE_CONFIRM_HINT.search(f.text):
                    break  # same-file heuristic: a confirm/dry-run gate exists somewhere
                out.append(self._f(
                    "job-destructive-no-confirm",
                    f"Destructive call ({label}) with no confirm-before-destroy gate",
                    Severity.P1, Confidence.MEDIUM, f, i,
                    f"'{label}' is a destructive/irreversible call and no dry-run flag, "
                    "confirmation prompt, or env-gated approval was found anywhere in "
                    "this file.",
                    "Add a dry-run flag, an interactive/approval confirm step, or an "
                    "explicit env-gated opt-in before this call runs.",
                ))
                break
        return out

    # --- 3. success reported without verification ---------------------------
    def _unverified(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        for i, line_text in enumerate(f.lines, start=1):
            if _is_comment_line(line_text, f.suffix):
                continue
            if _OR_TRUE.search(line_text):
                out.append(self._f(
                    "job-unverified-success", "Command's exit status masked with '|| true'",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "'|| true' forces this step to always succeed regardless of "
                    "whether the command actually failed.",
                    "Remove '|| true'; let the job fail loudly, or explicitly check "
                    "and log the real exit code before deciding to continue.",
                ))
            if _EXIT_0_AFTER_CMD.search(line_text):
                out.append(self._f(
                    "job-unverified-success", "Script exits 0 unconditionally after a command",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "An explicit 'exit 0' tacked onto a preceding command reports "
                    "success to the caller/scheduler regardless of what the command "
                    "actually did.",
                    "Propagate the real exit code ('exit $?' / check '$LASTEXITCODE') "
                    "instead of hardcoding success.",
                ))
            if _CONTINUE_ON_ERROR.search(line_text):
                out.append(self._f(
                    "job-unverified-success", "Workflow step continues on error unconditionally",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "'continue-on-error: true' lets this step fail without failing the "
                    "job or surfacing the failure -- a downstream step can report "
                    "overall success on top of a step that silently didn't work.",
                    "Remove 'continue-on-error', or capture the step outcome and gate "
                    "on it explicitly later in the job.",
                ))
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
