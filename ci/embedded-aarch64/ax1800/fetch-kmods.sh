#!/bin/sh
# fetch-kmods.sh <board|virt> <dest-root> [cache-dir]: download the pinned OpenWrt kmod packages (kmods.pin), verify each
# sha256, extract them into <dest-root> (lib/modules/<kver>/*.ko + etc/modules.d) with apk v3. Needs apk-tools 3.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
T=${1:?usage: fetch-kmods.sh board|virt <dest-root> [cache]}; R=${2:?dest root}; C=${3:-${KMOD_CACHE:-./kmod-cache}}/$T
eval "$(grep -E '^KMOD_(URL_[a-z]+|VERSION)=' "$HERE/kmods.pin")"
eval "U=\${KMOD_URL_$T:?unknown target $T}"
mkdir -p "$C" "$R"
grep -E "^$T " "$HERE/kmods.pin" | while read -r _ p sha; do
  f=$C/$p-$KMOD_VERSION.apk
  if ! { [ -f "$f" ] && echo "$sha  $f" | sha256sum -c - >/dev/null 2>&1; }; then
    curl -fsSL -o "$f.part.$$" "$U/$p-$KMOD_VERSION.apk"; mv "$f.part.$$" "$f"
    echo "$sha  $f" | sha256sum -c - >/dev/null || { rm -f "$f"; echo "fetch-kmods: sha256 mismatch for $p ($T)" >&2; exit 1; }
  fi
  X=$(mktemp -d "${TMPDIR:-/tmp}/kmod.XXXXXX")
  apk extract --allow-untrusted --destination "$X" "$f" >/dev/null 2>&1 || { echo "fetch-kmods: cannot extract $p" >&2; exit 1; }
  # only the modules and their load-order file (apk's own package list stays out); replaces same-named stock files
  for d in lib/modules etc/modules.d etc/modules-boot.d; do [ -d "$X/$d" ] && { mkdir -p "$R/$d"; cp -a "$X/$d/." "$R/$d/"; }; done
  rm -rf "$X"
done
echo "fetch-kmods: $(grep -c "^$T " "$HERE/kmods.pin") packages ($T) into $R"
