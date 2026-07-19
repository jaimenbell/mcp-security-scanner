"""Write-group gating primitive, modeled on the operator's own fleet pattern
(github-mcp's config.gated_write / desktop-mcp's config.gated)."""
from __future__ import annotations

import os
from functools import wraps

ENABLE_WRITE_ENV = "DEMO_MCP_ENABLE_WRITE"


def _write_enabled() -> bool:
    return os.environ.get(ENABLE_WRITE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def gated_write(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _write_enabled():
            return {
                "ok": False,
                "error": {
                    "type": "policy_refusal",
                    "message": f"Set {ENABLE_WRITE_ENV}=1 to enable write-group tools.",
                },
            }
        return fn(*args, **kwargs)
    return wrapper
