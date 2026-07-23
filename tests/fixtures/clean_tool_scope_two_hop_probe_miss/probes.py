"""Second hop -- see server.py's module docstring for the full shape this
pins. `get_status`'s only call is the bare `_run_subprocess`, a
repo-internal function (same file); the real sink is a THIRD call, inside
`_run_subprocess`'s own body, one hop beyond this detector's bound."""
from __future__ import annotations

import subprocess


def _run_subprocess(args: list[str], timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def get_status() -> dict:
    rc, stdout, _stderr = _run_subprocess(["nvidia-smi", "--query-gpu=index,name"], 10.0)
    return {"ok": rc == 0, "raw": stdout}
