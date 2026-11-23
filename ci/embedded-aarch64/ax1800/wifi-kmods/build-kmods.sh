#!/bin/sh
# build-kmods.sh <out-dir>: rebuild the Wi-Fi kernel modules of the GL-AX1800 image (compat, cfg80211, mac80211, ath, ath11k,
# ath11k_ahb) from OpenWrt's own mac80211 package with the patches in ./patches applied, using the OpenWrt SDK of
# exactly the release whose kernel the image boots (sdk.pin). Output: <out-dir>/wifi-kmods-<tag>.tar with
# lib/modules/<kver>/*.ko and a MANIFEST (sdk sha256, patch sha256s, module sha256s + vermagic).
#
# Why: upstream ath11k advertises neither AQL nor airtime fairness, so every queued byte of a busy station sits in the
# hardware rings (no AQM, no per-station fairness): on a 2.4 GHz radio a slow station's download adds hundreds of ms to
# seconds of delay and takes most of the airtime. The patches (upstream series "ath11k: airtime queue limits, fairness and
# a driver TXQ scheduler" + the mac80211 round-number fix) bound that queue; docs/embedded-routers.md 12.20.
#
# Runs on an x86_64 Linux host (the SDK's host tools are x86_64), inside a throwaway container:
#   docker run --rm -v "$PWD:/w" -w /w debian:trixie sh /w/build-kmods.sh /w/out
# Needs network (SDK download, OpenWrt base feed at the release tag, backports tarball). Reproducible from the pins.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); OUT=${1:?usage: build-kmods.sh <out-dir>}; mkdir -p "$OUT"
eval "$(grep -E '^(SDK_URL|SDK_SHA256|OWRT_TAG|OWRT_BASE_REV|KVER|TAG)=' "$HERE/sdk.pin")"
if ! command -v make >/dev/null || ! command -v zstd >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends build-essential gawk \
    python3 python3-setuptools rsync unzip zstd file wget curl git perl ca-certificates libncurses-dev xz-utils bzip2 \
    patch diffutils findutils which >/dev/null
fi
W=${WORK:-/tmp/wifi-kmods}; mkdir -p "$W"; cd "$W"
if [ -n "${TREE:-}" ]; then
  # TREE=<OpenWrt build root of the release whose kernel the image boots> (ci/embedded-openwrt/build-owrt.sh output): same package, no SDK
  # download; its .config already selects the Wi-Fi modules and its kernel is the one the image boots (kernel.pin).
  cd "$TREE"; MPATH=package/kernel/mac80211
else
  f=$(basename "$SDK_URL")
  [ -s "$f" ] || curl -sfL -o "$f" "$SDK_URL"
  echo "$SDK_SHA256  $f" | sha256sum -c - >/dev/null || { echo "build-kmods: SDK sha256 mismatch" >&2; rm -f "$f"; exit 1; }
  [ -d sdk ] || { mkdir sdk; tar --zstd -xf "$f" -C sdk --strip-components=1; }
  cd sdk
  # the base feed at the release tag carries package/kernel/mac80211 (the SDK itself only has the toolchain + kernel tree)
  grep -q "^src-git --root=package base .*\^$OWRT_BASE_REV\$" feeds.conf.default || { echo "build-kmods: SDK feeds.conf does not pin base to $OWRT_BASE_REV" >&2; exit 1; }
  [ -d feeds/base ] || FORCE_UNSAFE_CONFIGURE=1 ./scripts/feeds update base >/dev/null
  ./scripts/feeds install kmod-ath11k-ahb >/dev/null
  MPATH=package/feeds/base/mac80211
fi
M=$(readlink -f "$MPATH"); [ -d "$M/patches/ath11k" ] || { echo "build-kmods: mac80211 package not found in the base feed" >&2; exit 1; }
# OpenWrt package patches that the pinned kernel makes wrong (ci/embedded-openwrt/patches/<kver>/DROP, same list the kernel build used): a
# patch that maps netns_immutable back to netns_local breaks mac80211 on a stable kernel that already has the rename
DROPF="$HERE/../../../embedded-openwrt/patches/$KVER/DROP"
if [ -f "$DROPF" ]; then for n in $(sed -e '/^#/d' -e '/^$/d' "$DROPF"); do rm -f "$M"/patches/*/"$n"; done; fi
# same overlay as the kernel build (ci/embedded-openwrt/patches/<kver>/mac80211/*.patch: backports build fixes the pinned kernel needs)
OVM="$HERE/../../../embedded-openwrt/patches/$KVER/mac80211"
if [ -d "$OVM" ]; then for p in "$OVM"/*.patch; do [ -e "$p" ] && cp "$p" "$M/patches/build/$(basename "$p")"; done; fi
# patches: ath11k/9xx-* go to the driver set, subsys/9xx-* to mac80211 (applied after OpenWrt's own, in name order)
for p in "$HERE"/patches/*.patch; do
  case $(basename "$p") in ath11k-*) d=ath11k;; mac80211-*) d=subsys;; *) echo "build-kmods: unknown patch $p" >&2; exit 1;; esac
  cp "$p" "$M/patches/$d/99$(basename "$p" | sed 's/^[a-z0-9]*-//; s/^/0-/')" ; done
ls "$M/patches/ath11k" | grep '^990-' >/dev/null || { echo "build-kmods: no patches staged" >&2; exit 1; }
if [ -z "${TREE:-}" ]; then
  cat > .config <<EOF
CONFIG_PACKAGE_kmod-ath11k-ahb=m
CONFIG_PACKAGE_kmod-ath11k=m
CONFIG_PACKAGE_kmod-mac80211=m
CONFIG_PACKAGE_kmod-cfg80211=m
CONFIG_PACKAGE_kmod-ath=m
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG_ALL=n
EOF
  make defconfig >/dev/null
fi

if [ "${REUSE_BUILD:-0}" != 1 ]; then  # REUSE_BUILD=1: only re-stage a finished build of this work dir
  make -j"$(nproc)" package/mac80211/clean >/dev/null 2>&1 || true
  make -j"$(nproc)" package/mac80211/compile V=s > "$OUT/build.log" 2>&1 || { tail -60 "$OUT/build.log"; exit 1; }
fi
B=$(ls -d build_dir/target-*/linux-*/mac80211-regular/backports-*/ | head -1)
[ -n "$B" ] || { echo "build-kmods: no mac80211-regular build dir" >&2; exit 1; }
KV=$(ls -d staging_dir/target-*/root-*/lib/modules/* 2>/dev/null | head -1); KV=${KVER:-$(basename "$KV")}
S=$W/stage; rm -rf "$S"; mkdir -p "$S/lib/modules/$KV"
for m in compat/compat net/wireless/cfg80211 net/mac80211/mac80211 drivers/net/wireless/ath/ath drivers/net/wireless/ath/ath11k/ath11k \
         drivers/net/wireless/ath/ath11k/ath11k_ahb; do
  # the copy OpenWrt packages (.pkgdir/kmod-*/lib/modules/<kv>/), i.e. what its own kmod-*.apk would install
  ko=$(find "$B/.pkgdir" -path "*/lib/modules/*/$(basename "$m").ko" | head -1); [ -n "$ko" ] || { echo "build-kmods: $m.ko not built" >&2; exit 1; }
  cp "$ko" "$S/lib/modules/$KV/"; done
# strip like OpenWrt does (debug info only) and record what was built
STRIP=$(ls staging_dir/toolchain-*/bin/*-openwrt-linux-musl-strip | head -1)
for k in "$S/lib/modules/$KV"/*.ko; do "$STRIP" --strip-debug "$k"; done
{ echo "TAG=$TAG"; echo "OWRT_TAG=$OWRT_TAG"; echo "OWRT_BASE_REV=$OWRT_BASE_REV"; echo "KVER=$KV"; echo "SDK_SHA256=$SDK_SHA256"
  for p in "$HERE"/patches/*.patch; do echo "patch $(sha256sum "$p" | cut -d' ' -f1) $(basename "$p")"; done
  for k in "$S/lib/modules/$KV"/*.ko; do echo "module $(sha256sum "$k" | cut -d' ' -f1) $(basename "$k") $(strings "$k" | sed -n 's/^vermagic=//p' | head -1)"; done
} > "$S/MANIFEST"
tar -C "$S" --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -cf "$OUT/wifi-kmods-$TAG.tar" .
sha256sum "$OUT/wifi-kmods-$TAG.tar"; cat "$S/MANIFEST"
