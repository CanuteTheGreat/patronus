#!/bin/sh
# fetch-etph.sh [dir]: download the pinned ETPhoneHome router package (etph.pin), verify its sha256, print its path.
# Idempotent; cached in <dir> (default $ETPH_CACHE or ./etph-cache). Used by the image build and by CI.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); . "$HERE/etph.pin"
D=${1:-${ETPH_CACHE:-./etph-cache}}; mkdir -p "$D"; F=$D/$ETPH_IPK
if [ -f "$F" ] && echo "$ETPH_SHA256  $F" | sha256sum -c - >/dev/null 2>&1; then echo "$F"; exit 0; fi
curl -fsSL -o "$F.part" "$ETPH_URL"; mv "$F.part" "$F"
echo "$ETPH_SHA256  $F" | sha256sum -c - >&2 || { rm -f "$F"; echo "fetch-etph: sha256 mismatch for $ETPH_IPK" >&2; exit 1; }
echo "$F"
