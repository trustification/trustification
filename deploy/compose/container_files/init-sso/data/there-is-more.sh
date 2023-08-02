#!/usr/bin/env bash

# this file is "sourced" from `init.sh`, so we can use everything that was declared in there.

# reset CLIENT_OPTS, to keep using the same pattern
CLIENT_OPTS=()

# create testing client, as this script is expected to only run in a local developer setup, we ignore the
# re-running aspect
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing-user.json" "${CLIENT_OPTS[@]}"
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing-manager.json" "${CLIENT_OPTS[@]}"

# we use the default walker client, but reset the client secret to a pre-shared value, for testing only
ID=$(kcadm get clients -r "${REALM}" --query "clientId=walker" --fields id --format csv --noquotes)
kcadm update "clients/${ID}" -r "${REALM}" -s "secret=ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS" # notsecret

# default role for service account of services
kcadm add-roles -r "${REALM}" --uusername service-account-testing-manager --rolename chicken-manager
