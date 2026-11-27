#!/bin/sh
# make-wifi5-kmods.sh <out.tar>: the GL-AR750S 5 GHz driver + firmware set of wifi5.pin (OpenWrt 25.12.6 kmod-ath10k + linux-firmware
# QCA9887 firmware-5.bin), extracted from the release's own apk v3 packages (run it where apk-tools 3 exists, e.g. `docker run alpine:edge`,
# with network). Output tar: lib/modules/<kver>/ath10k_{core,pci}.ko, lib/firmware/ath10k/QCA9887/hw1.0/firmware-5.bin, etc/modules.d/ath10k.
# Publish it as the Forgejo generic package patronus-owrt-ath10k-ar750s/<kver>-<n>/<file> and pin its sha256 in wifi5.pin.
set -eu
OUT=${1:?usage: make-wifi5-kmods.sh <out.tar>}; HERE=$(cd "$(dirname "$0")/.." && pwd)
eval "$(grep -E '^(WIFI5_KMOD_URL|WIFI5_FW_URL)=' "$HERE/wifi5.pin")"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; mkdir -p "$W/root"
grep -E '^pkg ' "$HERE/wifi5.pin" | while read -r _ p v kind; do
  case "$kind" in kmod) u=$WIFI5_KMOD_URL;; fw) u=$WIFI5_FW_URL;; *) echo "bad kind $kind"; exit 1;; esac
  curl -fsSL -o "$W/$p.apk" "$u/$p-$v.apk"
  X=$W/x-$p; mkdir -p "$X"; apk extract --allow-untrusted --destination "$X" "$W/$p.apk" >/dev/null
  for d in lib/modules lib/firmware etc/modules.d; do if [ -d "$X/$d" ]; then mkdir -p "$W/root/$d"; cp -a "$X/$d/." "$W/root/$d/"; fi; done
done
tar -C "$W/root" --sort=name --owner=0 --group=0 --mtime=@0 -cf "$OUT" .
tar tf "$OUT"
sha256sum "$OUT"
