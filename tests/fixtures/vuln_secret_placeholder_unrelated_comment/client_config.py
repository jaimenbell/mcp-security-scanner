"""Vuln fixture: a real AKIA-shaped key with an UNRELATED comment on the same
line (not the pragma/nosec suppress convention) -- must still flag. Proves
the suppress-comment recognition can't be tricked by any comment at all."""

REAL_LOOKING_ACCESS_KEY = 'AKIA9876543210FEDCBA'  # loaded at startup
