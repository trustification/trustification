#!/usr/bin/env bash

# this file is "sourced" from `init.sh`, so we can use everything that was declared in there.

# create testing client, as this script is expected to only run in a local developer setup, we ignore the
# re-running aspect
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing.json" "${CLIENT_OPTS[@]}"
