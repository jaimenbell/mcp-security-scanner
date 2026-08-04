"""The class whose instance the server binds. Its `purge_entry` carries a
real, ungated `os.remove` sink."""
from __future__ import annotations

import os


class ConnectionRegistry:
    def purge_entry(self, path: str) -> None:
        os.remove(path)
