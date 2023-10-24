#!/usr/bin/env sh
set -e
TESTDIR=${1:-/tests}
TESTS=$(ls $TESTDIR)

for t in $TESTS
do
    echo "Running ${t}"
    ${TESTDIR}/${t} --nocapture
done
