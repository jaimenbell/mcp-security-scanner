"""Mirrors rag-mcp's ``lock.py`` -- the flagged sink lives inside a method
whose only caller is an operator-argv CLI path (``cli.py``), never a
registered MCP tool."""
import os


class ReingestLock:
    def __init__(self, db_path):
        self.db_path = db_path

    def acquire(self):
        # CLI_ONLY: only caller is cli.py's _cmd_ingest, itself only called
        # from cli.py's argv-main -- zero MCP-tool-registered callers reach
        # this line.
        os.system("acquire-lock " + self.db_path)
        return self
