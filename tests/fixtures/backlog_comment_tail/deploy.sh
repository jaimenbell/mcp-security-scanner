#!/bin/bash
# full-comment line mentioning rm -rf must stay silent (existing precision fix)
ls -la /data/staging  # looks similar to rm -rf but this line only lists files
rm -rf /data/staging  # tear down the staging directory after tests
echo "done"
