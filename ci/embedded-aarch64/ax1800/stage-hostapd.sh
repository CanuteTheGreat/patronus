#!/bin/bash
# stage-hostapd.sh: INSIDE the builder image, build the Patronus hostapd package (hostapd/APKBUILD = Alpine 3.24's
# hostapd 2.11 + patronus-xbss.diff) with abuild. Output: /out/hostapd/<arch>/hostapd-2.11-r104.apk (+ -openrc, -doc),
# installed by stage-rootfs.sh in place of Alpine's package. Cached in /cache/hostapd by the hash of hostapd/ (a rebuild
# costs about 2 minutes). The packages are signed with a throwaway build key and installed with --allow-untrusted from
# this local path only (never from a repository).
set -euo pipefail
H=$(cd "$(dirname "$0")" && pwd)
STAMP=$(cat "$H"/hostapd/* | sha256sum | cut -c1-16)
C=/cache/hostapd/$STAMP
mkdir -p /out/hostapd
if ls "$C"/*/hostapd-2.11-r*.apk >/dev/null 2>&1; then
  echo "hostapd package cached ($STAMP)"
else
  command -v abuild >/dev/null || apk add --no-cache abuild libnl3-dev >/dev/null
  B=$(mktemp -d /tmp/hostapd-build.XXXX)
  cp -a "$H/hostapd/." "$B/"
  export ABUILD_USERDIR=$B/.abuild SRCDEST=/cache/hostapd-src REPODEST=$B/repo
  mkdir -p "$ABUILD_USERDIR" "$SRCDEST"
  # throwaway key (the apk is installed from a local file with --allow-untrusted, never via a repository)
  abuild-keygen -a -n > /out/build-hostapd.log 2>&1
  ( cd "$B" && abuild -F -r ) >> /out/build-hostapd.log 2>&1 || { tail -40 /out/build-hostapd.log; exit 1; }
  mkdir -p "$C"
  cp -a "$REPODEST"/*/. "$C/"   # <arch>/hostapd-*.apk
  rm -rf "$B"
fi
cp -a "$C"/. /out/hostapd/
ls -l /out/hostapd/*/hostapd-2.11-r*.apk
