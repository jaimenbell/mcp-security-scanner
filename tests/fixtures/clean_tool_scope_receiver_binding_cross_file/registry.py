"""The repo-internal class whose instance the server binds. Its `remove` is an
in-memory dict drop -- no sink anywhere in this file."""
from __future__ import annotations


class ConnectionRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, str] = {}

    def remove(self, key: str) -> None:
        self._entries.pop(key, None)
