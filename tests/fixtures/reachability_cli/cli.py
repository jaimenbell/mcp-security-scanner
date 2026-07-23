"""Mirrors rag-mcp's ``cli.py`` -- an operator-supplied argv entrypoint that
calls into ``lock.py``, with no connection to the registered MCP tool in
``server.py``."""
import sys

from lock import ReingestLock


def _cmd_ingest(args):
    lock = ReingestLock(args.db).acquire()
    return lock


def main():
    _cmd_ingest(sys.argv)


if __name__ == "__main__":
    main()
