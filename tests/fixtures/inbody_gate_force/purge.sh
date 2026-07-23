#!/bin/bash
set -euo pipefail

if [ -z "${FORCE:-}" ]; then
  echo "set FORCE=1 to actually purge the cache" >&2
  exit 1
fi

rm -rf /var/lib/app/cache
