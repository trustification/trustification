#!/usr/bin/env bash

set -exo pipefail

trap break INT

kcadm() { local cmd="$1" ; shift ; "$KCADM_PATH" "$cmd" --config /tmp/kcadm.config "$@" ; }

die() {
    echo "$*" 1>&2
    false
}

# TODO: once podman compose works, stop polling
while ! kcadm config credentials config --server "$KEYCLOAK_URL" --realm master --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" &> /dev/null; do
  echo "Waiting for Keycloak to start up..."
  sleep 5
done

echo "Keycloak ready"

# now we can do the actual work

# create realm
REALM_OPTS=()
REALM_OPTS+=(-s enabled=true)
REALM_OPTS+=(-s "displayName=Trusted Content")
REALM_OPTS+=(-s registrationAllowed=true)
REALM_OPTS+=(-s resetPasswordAllowed=true)
REALM_OPTS+=(-s loginWithEmailAllowed=false)
#REALM_OPTS+=(-s identityProviders='{{ mustToJson .Values.keycloak.identityProviders }}')
if kcadm get "realms/${REALM}" &> /dev/null ; then
  # exists -> update
  kcadm update "realms/${REALM}" "${REALM_OPTS[@]}"
else
  # need to create
  kcadm create realms -s "realm=${REALM}" "${REALM_OPTS[@]}"
fi

# create realm roles
kcadm create roles -r "${REALM}" -s name=chicken-user || true
kcadm create roles -r "${REALM}" -s name=chicken-admin || true
# add chicken-user as default role
kcadm add-roles -r "${REALM}" --rname "default-roles-${REALM}" --rolename chicken-user

# create clients - frontend
ID=$(kcadm get clients -r "${REALM}" --query "clientId=frontend" --fields id --format csv --noquotes)
CLIENT_OPTS=()
CLIENT_OPTS+=(-s 'redirectUris=["http://localhost:*"]')
if [[ -n "$ID" ]]; then
  # TODO: replace with update once https://github.com/keycloak/keycloak/issues/12484 is fixed
  # kcadm update "clients/${ID}" -r "${REALM}" -f /etc/init-data/client.json "${CLIENT_OPTS[@]}"
  kcadm delete "clients/${ID}" -r "${REALM}"
  kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-frontend.json" "${CLIENT_OPTS[@]}"
else
  kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-frontend.json" "${CLIENT_OPTS[@]}"
fi

# create user
ID=$(kcadm get users -r "${REALM}" --query "username=${CHICKEN_ADMIN}" --fields id --format csv --noquotes)
if [[ -n "$ID" ]]; then
  kcadm update "users/$ID" -r "${REALM}" -s enabled=true
else
  kcadm create users -r "${REALM}" -s "username=${CHICKEN_ADMIN}" -s enabled=true
fi

# set role
kcadm add-roles -r "${REALM}" --uusername "${CHICKEN_ADMIN}" --rolename chicken-admin

# set password
ID=$(kcadm get users -r "${REALM}" --query "username=${CHICKEN_ADMIN}" --fields id --format csv --noquotes)
kcadm update "users/${ID}/reset-password" -r "${REALM}" -s type=password -s "value=${CHICKEN_ADMIN_PASSWORD}" -s temporary=false -n

echo SSO initializion complete
