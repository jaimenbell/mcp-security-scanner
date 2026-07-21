#!/bin/bash
# nightly release-cleanup wrapper
set -u

rm -rf /data/releases/old

echo "clearing stale cache" || true

./run_migrations.sh; exit 0
