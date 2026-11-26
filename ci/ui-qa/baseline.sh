#!/usr/bin/env bash
# ci/ui-qa/baseline.sh fetch DIR            unpack the pinned baseline (ci/ui-qa/shots.pin) into DIR, sha256-checked
# ci/ui-qa/baseline.sh publish TAR VERSION  upload a reduced set as generic package patronus-ui-shots/VERSION
#                                           (needs FORGEJO_TOKEN with package write; prints the url + sha256 for the pin)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
pin() { sed -n "s/^$1 *= *//p" "$HERE/shots.pin" | head -1; }
API=${FORGEJO_API:-https://git.canutethegreat.com/api/packages/CanuteTheGreat/generic}
case "${1:-}" in
  fetch)
    d=${2:?dir}; mkdir -p "$d"; url=$(pin url); sum=$(pin sha256)
    if [ "$url" = none ]; then echo "baseline: none pinned"; exit 0; fi
    curl -fsSL --retry 3 -m 300 -o "$d/.base.tgz" "$url"
    got=$(sha256sum "$d/.base.tgz" | cut -d' ' -f1)
    [ "$got" = "$sum" ] || { echo "::error::baseline sha256 $got != pinned $sum"; exit 1; }
    tar -C "$d" -xzf "$d/.base.tgz"; rm -f "$d/.base.tgz"; echo "baseline: $(find "$d" -name '*.png' | wc -l) pages from $url";;
  publish)
    tar=${2:?tar}; ver=${3:?version}; : "${FORGEJO_TOKEN:?FORGEJO_TOKEN}"
    url="$API/patronus-ui-shots/$ver/ui-shots-$ver.tar.gz"
    code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: token $FORGEJO_TOKEN" --upload-file "$tar" "$url")
    case "$code" in 201|409) ;; *) echo "::warning::baseline upload HTTP $code"; exit 1;; esac
    echo "url = $url"; echo "sha256 = $(sha256sum "$tar" | cut -d' ' -f1)";;
  *) echo "usage: $0 fetch DIR | publish TAR VERSION" >&2; exit 2;;
esac
