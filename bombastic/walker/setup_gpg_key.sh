#!/bin/bash

#fail on any subprocess failures
set -uo pipefail

usage() {
  echo "Usage: $0 <url_of_gpg_public_key>"
}


if [ $# -ne 1 ]; then
  echo "GPG key address must be passed as the only argument"
  usage
  exit 1
fi

if [ "$1" = "-h" ]; then
  usage
  exit 0
fi

# Import prodsec pubkey
# From https://access.redhat.com/security/team/contact/#contact
  curl --no-progress-meter --output gpg_key.txt "$1"
  gpg --import gpg_key.txt
  rm gpg_key.txt