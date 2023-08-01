#!/bin/bash

#fail on any subprocess failures
set -uo pipefail

usage() { echo "Usage: $0 spdx_url bombastic_url" 1>&2; }

# Default variables
BOMBASTIC_API=""
BOMBASTIC_PATH="api/v1/sbom"
SOURCE=""
AUTHZ=""
WORKDIR=$(pwd)


###################################
# Help                            #
###################################
help()
{
   # Display Help
   echo "Get Sboms from prodsec and push to bombastic."
   echo
   echo "$0 [-h] SBOM_URL BOMBASTIC_API_URL"
   echo "options:"
   echo "   -h        Print this Help."
   echo "   -w        Path to a writable working directory"
   echo
   echo "example:"
   echo "$0 https://access.redhat.com/security/data/sbom/beta/spdx/3amp-2.json.bz2 localhost:8080"
   echo
}

# Get the options
while getopts ":hk:w:A:" option; do
   case $option in
      h) # display Help
         help
         exit 0
         ;;
      k) # specify API key
         AUTHZ="Authorization: Bearer $OPTARG"
         ;;
      A) # full authorization header
         AUTHZ="Authorization: $OPTARG"
         ;;
      w) # specify work dir
         WORKDIR=$OPTARG
         ;;
      \?) usage
         exit 1
         ;;
   esac
done

# Shift the positional parameters
shift $((OPTIND - 1))

if [ $# -ne 2 ] ; then
  echo "SPDX_URL and BOMBASTIC_URL are required arguments"
  usage
  exit 1
else
  SOURCE=$1
  BOMBASTIC_API=$2
fi


download_files()
{
    echo "Downloading files for $1"

    curl --no-progress-meter -O "$1" && \
    curl --no-progress-meter -O "$1".asc && \
    curl --no-progress-meter -O "$1".sha256
}

verify() {
     echo "verifying hash and signature for $1"

     sha256sum --check "$1".sha256 && \
     gpg -q --homedir "$WORKDIR" --verify "$1".asc  "$1" 2>/dev/null
}

cleanup()
{
  echo "cleanup $1"
  rm "$1"
  rm "$1".asc
  rm "$1".sha256

}


###################################
# Main                            #
###################################

cd "$WORKDIR" || exit 1

file=$(basename "$SOURCE")
if ! download_files "$SOURCE"; then
    echo "Error downloading files. Skipping" >&2
    cleanup "$file"
    exit 1
fi

if ! verify "$file"; then
    echo "Error verifying files. Skipping" >&2
    cleanup "$file"
    exit 1
fi

# All is well, let's upload that to bombastic
id=$(basename -s ".json.bz2" "$file")
echo "Uploading $id to bombastic"
if ! curl -f --no-progress-meter -X POST \
     -H "content-encoding: bzip2" \
     -H "transfer-encoding: chunked" \
     -H "content-type: application/json" \
     -H "$AUTHZ" \
     -T "$file" \
     "$BOMBASTIC_API""$BOMBASTIC_PATH"?id="$id"; then

       echo "Error uploading files to bombastic. Skipping" >&2
       cleanup "$file"
       exit 1
fi

cleanup "$file"
