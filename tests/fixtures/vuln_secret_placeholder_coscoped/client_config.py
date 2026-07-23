"""Round-2 N-vote P0-3(b) repro: the OLD pragma logic was LINE-scoped -- a
real ghp_ token co-located on the SAME LINE as a suppressed AWS placeholder
(and the same pragma comment) was masked entirely, because the whole line
was skipped once any suppress comment was seen. Each candidate secret value
on a line must be evaluated INDEPENDENTLY: the curated placeholder demotes
fully (our own judgment), the real ghp_ token must still flag."""

CREDS = ('AKIAIOSFODNN7EXAMPLE', 'ghp_RealTokenValueXXXXXXXXXXXXXXXXXXXXXX')  # pragma: allowlist secret
