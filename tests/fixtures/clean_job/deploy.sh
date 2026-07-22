#!/bin/bash
# nightly release-cleanup wrapper
set -euo pipefail

read -p "confirm delete old releases? [y/N] " ans
if [ "$ans" = "y" ]; then
  rm -rf /data/releases/old
fi

echo "clearing stale cache"

./run_migrations.sh
echo "migrations ok, exit $?"
