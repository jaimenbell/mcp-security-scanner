"""UNCALLED case for the same fixture repo: a sink with zero callers
anywhere -- not even from the CLI path."""
import os


def _never_called(target):
    os.system("dead-cli " + target)
