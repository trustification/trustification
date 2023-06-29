#!/bin/bash

#fail on any subprocess failures
set -uo pipefail

usage() {
  echo "Usage: $0 [options] <url_of_gpg_public_key>"
  echo "Available options"
  echo "  -h     print this help"
  echo "  -w     path to a writable working directory"
}

WORKDIR=$(pwd)

# Get the options
while getopts ":hw:" option; do
   case $option in
      h) # display Help
         help
         exit 0
         ;;
      w) # specify work dir
         WORKDIR=$OPTARG
         ;;
      ?) usage
         exit 1
         ;;
   esac
done

# Shift the positional parameters
shift $((OPTIND - 1))

if [ $# -ne 1 ]; then
  echo "GPG key address must be passed as the only argument"
  usage
  exit 1
fi

# Import prodsec pubkey
# From https://access.redhat.com/security/team/contact/#contact
  curl --no-progress-meter --output gpg_key.txt "$1"
  gpg --homedir "$WORKDIR" --import gpg_key.txt
  rm gpg_key.txt