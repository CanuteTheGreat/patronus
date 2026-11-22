#!/bin/sh
# prep-check.sh <target...> [out-dir]: network + container test (not part of the host tests): prepare the pinned OpenWrt tree for each
# target (build-owrt.sh PREP_ONLY=1: kernel pin, DROP list, overlays, config symbols) and run patch-survey.sh against the pinned kernel
# tarball. Prints "prep-check <target>: N patches, 0 not applying" or the failing patches; exit 1 on any failure.
# Run in a throwaway debian:trixie container on an x86_64 host:  docker run --rm -v $PWD:/w -w /w debian:trixie sh /w/ci/embedded-openwrt/tests/prep-check.sh ax1800 virt slate
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); . "$HERE/kernel.pin"; rc=0
command -v patch >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq patch xz-utils >/dev/null; }
for t in "$@"; do
  case $t in ax1800) tp=qualcommax;; virt) tp=armsr;; slate) tp=ath79;; *) echo "unknown target $t"; exit 2;; esac
  W=${WORK:-/tmp/prep-$t}; rm -rf "$W"
  PREP_ONLY=1 WORK=$W sh "$HERE/build-owrt.sh" "$t" "$W/out" >"$W.log" 2>&1 || { tail -5 "$W.log"; rc=1; continue; }
  f=$W/src/dl/linux-$KERNEL_LINE.$KERNEL_PATCH.tar.xz
  mkdir -p "$W/src/dl"; [ -f "$f" ] || { curl -fsSL -o "$f" "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_LINE%%.*}.x/linux-$KERNEL_LINE.$KERNEL_PATCH.tar.xz" || { echo "no kernel tarball"; rc=1; continue; }; }
  echo "$KERNEL_SHA256  $f" | sha256sum -c - >/dev/null || { echo "kernel tarball sha mismatch"; rc=1; continue; }
  out=$(sh "$HERE/patch-survey.sh" "$W/src" "$f" "$W/src/target/linux/$tp/patches-$KERNEL_LINE")
  case $out in *", 0 not applying"*) echo "prep-check $t: $(echo "$out" | tail -1)";; *) echo "prep-check $t FAILED:"; echo "$out"; rc=1;; esac
done
exit $rc
