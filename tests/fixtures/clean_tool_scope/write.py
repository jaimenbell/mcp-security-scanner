"""Write-group helpers -- each mutating action is gated at the source."""
from __future__ import annotations

import os
import subprocess

from . import config


@config.gated_write
def delete_file(path: str) -> dict:
    os.remove(path)
    return {"ok": True, "deleted": path}


@config.gated_write
def run_shell(cmd: str) -> dict:
    subprocess.run(cmd, shell=False)
    return {"ok": True}
