#!/bin/sh
# make-malta-kmods.sh <out.tar>: the netfilter kernel modules of OpenWrt's malta/be kernel (the kernel the Slate QEMU gate boots), extracted from the
# release's own kmod apk packages (apk v3: run it in an image that has apk-tools 3, e.g. the AX1800 builder, with network). Output tar holds
# lib/modules/<kver>/*.ko + etc/modules.d/* (no depmod: the bundle step runs it). The tar is published as the Forgejo generic package
# patronus-owrt-kernel-malta/<kver>-<rev>/<file>; its sha256 is pinned in kmods-malta.pin. Same package set as the AX1800 gate's virt kernel minus
# WireGuard and the bridge filter (the Slate image builds neither).
set -eu
OUT=${1:?usage: make-malta-kmods.sh <out.tar>}; HERE=$(cd "$(dirname "$0")/.." && pwd)
eval "$(grep -E '^(MALTA_KMOD_URL|MALTA_KMOD_VERSION)=' "$HERE/kmods-malta.pin")"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; mkdir -p "$W/root"
for p in $(grep -E '^pkg ' "$HERE/kmods-malta.pin" | cut -d' ' -f2); do
  curl -fsSL -o "$W/$p.apk" "$MALTA_KMOD_URL/$p-$MALTA_KMOD_VERSION.apk"
  X=$W/x-$p; mkdir -p "$X"; apk extract --allow-untrusted --destination "$X" "$W/$p.apk" >/dev/null
  for d in lib/modules etc/modules.d etc/modules-boot.d; do [ -d "$X/$d" ] && { mkdir -p "$W/root/$d"; cp -a "$X/$d/." "$W/root/$d/"; }; done
done
tar -C "$W/root" --sort=name --owner=0 --group=0 --mtime=@0 -cf "$OUT" .
sha256sum "$OUT"
