#!/usr/bin/env bash

set -e
set -x
set -o pipefail

: "${API_URL:=http://localhost:8080}"
: "${BACKEND_JSON:="{}"}"
: "${BACKEND_JSON_FILE:=/etc/config/console/backend.json}"

echo "Setting backend endpoint:"

if [ -f "$BACKEND_JSON_FILE" ]; then
    echo "Using base config from file: $BACKEND_JSON_FILE"
    BACKEND_JSON="$(cat "$BACKEND_JSON_FILE")"
fi

# inject backend URL
echo "$BACKEND_JSON" | \
  jq --arg url "$API_URL" '. + {url: $url}' | \
  jq --arg url "$BOMBASTIC_URL" '. + {bombastic: $url}' | \
  jq --arg url "$VEXINATION_URL" '. + {vexination: $url}' | \
  jq --arg url "$ISSUER_URL" '. + {oidc: {issuer: $url}}' | \
  tee /endpoints/backend.json

echo "Final backend information:"
echo "---"
cat /endpoints/backend.json
echo "---"

exec /usr/sbin/nginx -g "daemon off;"
