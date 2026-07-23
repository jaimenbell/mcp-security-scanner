import os


def shared_sink(target):
    # REACHABLE via server.py's tool. Also called from cli.py below -- a
    # mixed tool+CLI caller set must still grade REACHABLE, never CLI_ONLY.
    os.system("shared " + target)
