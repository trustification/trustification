#!/bin/bash

set -e

TAGS=$(git for-each-ref --sort=taggerdate --format '%(refname:short) %(taggerdate:short)' refs/tags | grep "nightly")
NOW=$(date +%s)
# 30 days = 24 * 3600 * 30
OLDEST=$((NOW - 2592000))

while read -r TAG; do
    T=$(echo -n "$TAG" | cut -d ' ' -f 1)
    D=$(echo -n "$TAG" | cut -d ' ' -f 2)
    D=$(date -d "$D" +%s)
    if [ $OLDEST -gt "$D" ]; then
      echo "Deleting tag: $T"
      echo git tag -d "$T"
      echo git push origin ":$T"
    fi
done <<< "$TAGS"
