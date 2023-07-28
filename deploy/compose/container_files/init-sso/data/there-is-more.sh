#!/usr/bin/env bash

# this file is "sourced" from `init.sh`, so we can use everything that was declared in there.

CLIENT_OPTS=()

# create testing client, as this script is expected to only run in a local developer setup, we ignore the
# re-running aspect
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing-user.json" "${CLIENT_OPTS[@]}"
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing-manager.json" "${CLIENT_OPTS[@]}"

# default role for service account of services
kcadm add-roles -r "${REALM}" --uusername service-account-testing-manager --rolename chicken-manager
