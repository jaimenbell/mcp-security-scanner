#!/usr/bin/env bash
# This script documents dangerous patterns it deliberately avoids.
# rm -rf /data/releases/old   <- example of what NOT to do
# git reset  --hard is also destructive; never do this here.
echo "cleaning cache"
mkdir -p /data/releases/new
