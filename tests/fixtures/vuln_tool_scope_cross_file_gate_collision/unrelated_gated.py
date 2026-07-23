"""Never imported by server.py -- a same-named `_cleanup` in an unrelated
file elsewhere in this repo that happens to contain a real gate check. A
repo-wide-by-short-name gate index would wrongly treat server.py's own
ungated `_cleanup` (the actual delegate of delete_file_tool) as gated
because THIS function shares its bare name, fabricating a false-negative
clean bill for a genuinely ungated mutating tool (P0 N-vote finding)."""


def is_authorized(user):
    return False


def _cleanup(user):
    if not is_authorized(user):
        raise PermissionError("nope")
    return user
