#!/bin/sh
# wifi-kmods/fetch.sh <dest-root> [cache-dir]: put the image's rebuilt Wi-Fi modules (cfg80211, mac80211, ath, ath11k,
# ath11k_ahb: OpenWrt's own package + ./patches, built by build-kmods.sh) over the stock modules in <dest-root>.
# The tar is pinned by sha256 (wifi-kmods.pin); its MANIFEST must name the image's kernel release and every module's
# vermagic must equal the stock module it replaces (same kernel build), otherwise the build stops.
# WIFI_KMODS=stock keeps OpenWrt's unpatched modules (an image without airtime queue limits / fairness).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); R=${1:?usage: fetch.sh <dest-root> [cache]}; C=${2:-${KMOD_CACHE:-./kmod-cache}}/wifi
[ "${WIFI_KMODS:-patched}" = stock ] && { echo "wifi-kmods: WIFI_KMODS=stock, OpenWrt's modules kept"; exit 0; }
eval "$(grep -E '^(WIFI_KMODS_URL|WIFI_KMODS_SHA256|WIFI_KMODS_TAG)=' "$HERE/wifi-kmods.pin")"
mkdir -p "$C"; f=$C/wifi-kmods-$WIFI_KMODS_TAG.tar
if [ -n "${WIFI_KMODS_TAR:-}" ]; then cp "$WIFI_KMODS_TAR" "$f"
elif ! { [ -f "$f" ] && echo "$WIFI_KMODS_SHA256  $f" | sha256sum -c - >/dev/null 2>&1; }; then
  curl -fsSL -o "$f.part.$$" "$WIFI_KMODS_URL"; mv "$f.part.$$" "$f"; fi
echo "$WIFI_KMODS_SHA256  $f" | sha256sum -c - >/dev/null || { rm -f "$f"; echo "wifi-kmods: sha256 mismatch ($f)" >&2; exit 1; }
X=$(mktemp -d "${TMPDIR:-/tmp}/wifikmods.XXXXXX"); trap 'rm -rf "$X"' EXIT
tar xf "$f" -C "$X"
KV=$(ls "$R/lib/modules"); MKV=$(sed -n 's/^KVER=//p' "$X/MANIFEST")
[ "$KV" = "$MKV" ] || { echo "wifi-kmods: built for kernel $MKV, the image boots $KV" >&2; exit 1; }
vm() { strings "$1" | sed -n 's/^vermagic=//p' | head -1; }
for k in "$X/lib/modules/$KV"/*.ko; do
  n=$(basename "$k"); s=$R/lib/modules/$KV/$n
  [ -f "$s" ] || { echo "wifi-kmods: $n has no stock counterpart in the image" >&2; exit 1; }
  [ "$(vm "$k")" = "$(vm "$s")" ] || { echo "wifi-kmods: $n vermagic '$(vm "$k")' != stock '$(vm "$s")'" >&2; exit 1; }
  grep -q "^module $(sha256sum "$k" | cut -d' ' -f1) $n " "$X/MANIFEST" || { echo "wifi-kmods: $n not in MANIFEST" >&2; exit 1; }
  install -m644 "$k" "$s"; done
mkdir -p "$R/usr/share/patronus"; install -m644 "$X/MANIFEST" "$R/usr/share/patronus/wifi-kmods.manifest"
echo "wifi-kmods: $WIFI_KMODS_TAG ($(ls "$X/lib/modules/$KV" | tr '\n' ' ')) over the stock modules"
