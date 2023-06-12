#!/bin/bash

#fail on any subprocess failures
set -euo pipefail

usage() { echo "Usage: $0 [-s <url to index.txt>] bombastic_url" 1>&2; exit 1; }

if [ $# -lt 1 ]; then
    >&2 usage
fi

# Default variables
BOMBASTIC_API=${*: -1}
BOMBASTIC_PATH="/api/v1/sbom"
SOURCE="https://access.redhat.com/security/data/sbom/beta/index.txt"

###################################
# Help                            #
###################################
help()
{
   # Display Help
   echo "Get Sboms from prodsec and push to bombastic."
   echo
   echo "sbomwalker [OPTIONS] BOMBASTIC_API_URL"
   echo "options:"
   echo "s     Specify the source URL. Defaults to https://access.redhat.com/security/data/sbom/beta/index.txt"
   echo "h     Print this Help."
   echo
   echo "example:"
   echo "sbomwalker localhost:8080"
   echo "sbomwalker -s https://access.redhat.com/security/data/sbom/beta/index.txt localhost:8080"
   echo
}

# Get the options
while getopts ":h:s" option; do
   case $option in
      h) # display Help
         help
         exit 0
         ;;
      s) SOURCE=${OPTARG}
         ;;
      *) usage
         exit 1
         ;;
   esac
done



download_files()
{
    echo "Downloading files for $1"

    wget -nv "$1"
    wget -nv "$1".asc
    wget -nv "$1".sha256
}

verify() {
     echo "verifying hash and signature for $1"

     sha256sum --check "$1".sha256
     gpg -q --verify "$1".asc  "$1" 2>/dev/null
}

cleanup()
{
  echo "cleanup $1"
  rm "$1"
  rm "$1".asc
  rm "$1".sha256

}

# Import prodsec pubkey
setup_pubkey() {
  # From https://access.redhat.com/security/team/contact/#contact
  wget -nv https://access.redhat.com/sites/default/files/pages/attachments/dce3823597f5eac4.txt
  gpg --import dce3823597f5eac4.txt
  rm dce3823597f5eac4.txt
}


###################################
# Main                            #
###################################

setup_pubkey

# Download index file
wget -nv "$SOURCE" -O index.txt
base=$(dirname "$SOURCE")

# Loop through the entries
while read -r sbom; do

    sbom_url="$base"/"$sbom"
    download_files $sbom_url
    file=$(basename $sbom_url)
    verify $file

    # All is well, let's upload that to bombastic
    id=$(basename -s ".json.bz2" "$file")
    curl --fail -H "content-encoding: bzip2" \
         -H "transfer-encoding: chunked" \
         -H "content-type: application/json" \
         --data @"$file" \
         "$BOMBASTIC_API""$BOMBASTIC_PATH"?id="$id"
    echo

    cleanup "$file"
done < "index.txt"

rm index.txt