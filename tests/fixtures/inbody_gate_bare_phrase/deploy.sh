#!/bin/bash
set -euo pipefail

# An unrelated UI/display string containing the bare phrase, nowhere near the
# destructive call and bound to no param or control-flow exit. It must NOT be
# treated as a safety gate.
GREETING="Are you sure you want to leave the newsletter? Reply YES."
echo "$GREETING"

# Genuinely unguarded destructive call -- must still be flagged.
rm -rf /var/lib/app/data
