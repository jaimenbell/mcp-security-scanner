"""Detector registry."""

from __future__ import annotations

from .base import Detector, RepoContext, SourceFile
from .codegen_injection import CodegenInjectionDetector
from .param_injection import ParamInjectionDetector
from .auth_posture import AuthPostureDetector
from .secret_handling import SecretHandlingDetector
from .tool_scope_creep import ToolScopeCreepDetector
from .secret_leak_response import SecretLeakResponseDetector

ALL_DETECTORS: list[Detector] = [
    CodegenInjectionDetector(),
    ParamInjectionDetector(),
    AuthPostureDetector(),
    SecretHandlingDetector(),
    ToolScopeCreepDetector(),
    SecretLeakResponseDetector(),
]

__all__ = [
    "Detector", "RepoContext", "SourceFile", "ALL_DETECTORS",
    "CodegenInjectionDetector", "ParamInjectionDetector",
    "AuthPostureDetector", "SecretHandlingDetector",
    "ToolScopeCreepDetector", "SecretLeakResponseDetector",
]
