#!/usr/bin/env bash

set -e
set -x
set -o pipefail

exec /usr/sbin/nginx -g "daemon off;"
