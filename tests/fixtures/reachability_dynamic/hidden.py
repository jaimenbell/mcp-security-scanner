"""A helper with zero STATIC callers anywhere in this repo -- it is only
ever reached, if at all, via ``server.py``'s dynamic ``getattr(...)(...)``
dispatch. Because that dispatch is unresolvable, this scanner cannot prove
whether the dynamic tool path reaches it or not -- the honest grade is
UNKNOWN, never UNCALLED (which would wrongly assert "definitely dead")."""
import os


def _hidden_helper(target):
    os.system("hidden " + target)
