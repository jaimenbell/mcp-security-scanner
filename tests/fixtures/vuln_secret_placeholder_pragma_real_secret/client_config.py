"""Round-2 N-vote P0-3(a) repro: a REAL (non-placeholder) AKIA-shaped key
with the maintainer's own suppress-convention comment. In an ADVERSARIAL
(third-party) scanning context, this pragma comment is ATTACKER-controlled
-- a malicious external repo could suppress an entire secret class with one
comment per line. This must NEVER fully vanish; it may only be demoted
(confidence, not visibility)."""

REAL_ACCESS_KEY = 'AKIA1234567890ABCDEF'  # pragma: allowlist secret
