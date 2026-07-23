"""Genuinely ungated real sink -- no gate decorator, no env opt-in, no
permission check anywhere in this file."""
from __future__ import annotations

import subprocess


def do_thing(cmd: str) -> dict:
    subprocess.run(cmd, shell=True)
    return {"ok": True}
