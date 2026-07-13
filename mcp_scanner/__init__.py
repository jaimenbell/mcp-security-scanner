"""mcp-scanner — static security scanner for MCP servers.

Detects the vulnerability classes found real in a fleet-wide audit of production
MCP servers: codegen/template injection, tool-parameter injection surfaces,
auth/network posture gaps, and secret handling.
"""

from __future__ import annotations

from .models import Finding, Severity, Confidence, ScanResult
from .scanner import scan_repo, build_context
from .reporting import render_markdown, render_json

__version__ = "0.1.0"
__all__ = [
    "Finding", "Severity", "Confidence", "ScanResult",
    "scan_repo", "build_context", "render_markdown", "render_json",
    "__version__",
]
