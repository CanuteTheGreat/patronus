#!/bin/sh
# build-owrt.sh <target> <out-dir>: build OpenWrt <OWRT_TAG> from source with the kernel of kernel.pin and collect the
# artefacts the embedded tier consumes (sysupgrade/kernel image, kmod apks, SDK). Runs in a throwaway debian:trixie
# container on an x86_64 host (see ci/embedded-openwrt/README.md):
#   docker run --rm --cpus 6 --memory 14g -v $PWD:/w -w /w debian:trixie sh /w/build-owrt.sh ax1800 /w/out
# <target>: ax1800 (qualcommax/ipq60xx glinet_gl-ax1800), virt (armsr/armv8 generic), slate (ath79/nand glinet_gl-ar750s-nor-nand)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); T=${1:?usage: build-owrt.sh <target> <out-dir>}; OUT=${2:?out dir}; mkdir -p "$OUT"
. "$HERE/kernel.pin"
case $T in
  ax1800) CFG="CONFIG_TARGET_qualcommax=y
CONFIG_TARGET_qualcommax_ipq60xx=y
CONFIG_TARGET_qualcommax_ipq60xx_DEVICE_glinet_gl-ax1800=y"; KPK=$HERE/kmods-ax1800.list;;
  virt)   CFG="CONFIG_TARGET_armsr=y
CONFIG_TARGET_armsr_armv8=y
CONFIG_TARGET_armsr_armv8_DEVICE_generic=y"; KPK=$HERE/kmods-virt.list;;
  slate)  CFG="CONFIG_TARGET_ath79=y
CONFIG_TARGET_ath79_nand=y
CONFIG_TARGET_ath79_nand_DEVICE_glinet_gl-ar750s-nor-nand=y"; KPK=$HERE/kmods-slate.list;;
  *) echo "build-owrt: unknown target $T" >&2; exit 2;;
esac
if ! command -v make >/dev/null || ! command -v zstd >/dev/null || ! command -v git >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends build-essential clang flex bison g++ gawk \
    gettext git libncurses-dev libssl-dev python3 python3-setuptools python3-dev rsync swig unzip zlib1g-dev file wget curl zstd xz-utils \
    ca-certificates libelf-dev patch diffutils findutils which perl libpython3-dev xsltproc >/dev/null
fi
export FORCE_UNSAFE_CONFIGURE=1 FORCE=1
W=${WORK:-/tmp/owrt-$T}; mkdir -p "$W"; cd "$W"
REUSED=1; [ -d src ] || { REUSED=0; git clone -q --depth 1 --branch "$OWRT_TAG" "$OWRT_GIT" src; }
cd src
K=target/linux/generic/kernel-$KERNEL_LINE
# the tag must still carry the stock version we replace (a moved tag or a wrong line is refused, never guessed)
grep -q "^LINUX_VERSION-$KERNEL_LINE = \.$OWRT_STOCK_PATCH\$" "$K" || grep -q "^LINUX_VERSION-$KERNEL_LINE = \.$KERNEL_PATCH\$" "$K" || { echo "build-owrt: $K does not carry .$OWRT_STOCK_PATCH" >&2; cat "$K" >&2; exit 1; }
sed -i -e "s/^LINUX_VERSION-$KERNEL_LINE = .*/LINUX_VERSION-$KERNEL_LINE = .$KERNEL_PATCH/" -e '/^LINUX_KERNEL_HASH-/d' "$K"
echo "LINUX_KERNEL_HASH-$KERNEL_LINE.$KERNEL_PATCH = $KERNEL_SHA256" >> "$K"
# patches/<line>.<patch>/: OpenWrt's own patches refreshed for exactly this kernel (stable moved a context OpenWrt's tag did not know).
# They replace the same-named file of the tag; a bump to another patch release finds no directory and builds the tag's patches as they are
# (fails loudly at the patch step when stable moved again: then a new directory is made, see README.md "When a patch no longer applies").
OV=$HERE/patches/$KERNEL_LINE.$KERNEL_PATCH
if [ -f "$OV/DROP" ]; then for n in $(sed -e '/^#/d' -e '/^$/d' "$OV/DROP"); do
  t=$(find target/linux package/kernel \( -path '*/patches*/*' -o -path '*/backport-*/*' -o -path '*/pending-*/*' -o -path '*/hack-*/*' \) -name "$n" 2>/dev/null | head -1)
  # a name already gone is fine only in a reused work dir (an earlier run dropped it); a fresh clone must find every name
  if [ -z "$t" ]; then [ "${REUSED:-0}" = 1 ] && { echo "build-owrt: $n already dropped"; continue; }; echo "build-owrt: DROP $n has no counterpart in the tag" >&2; exit 1; fi
  rm -f "$t"; echo "build-owrt: dropped $n"; done; fi
if [ -d "$OV" ]; then for p in "$OV"/*.patch; do [ -e "$p" ] || continue; n=$(basename "$p"); t=$(ls target/linux/generic/*-$KERNEL_LINE/"$n" 2>/dev/null | head -1)
  [ -n "$t" ] || { echo "build-owrt: overlay $n has no counterpart in the tag" >&2; exit 1; }; cp "$p" "$t"; echo "build-owrt: overlay $n"; done; fi
# config-<target> in the overlay dir: kernel symbols stable added that OpenWrt's target config does not know yet (a NEW symbol makes the
# non-interactive kernel configure fail: "Cortex-A725: 3821522 ... (NEW)"); appended once, with upstream's default
for f in "$OV"/config-*; do [ -e "$f" ] || continue; t=target/linux/${f##*/config-}/config-$KERNEL_LINE
  [ -f "$t" ] || { echo "build-owrt: $f: no $t" >&2; exit 1; }
  while read -r l; do [ -n "$l" ] || continue; sym=${l%%=*}; grep -q "^$sym=\|^# $sym is not set" "$t" || { echo "$l" >> "$t"; echo "build-owrt: $t += $l"; }; done < "$f"; done
# PREP_ONLY=1: stop here with the prepared tree (pin applied, patches dropped/refreshed): `patch-survey.sh` then proves every patch of the
# series applies to the real kernel tree without a 1-2 h build (tests/prep-check.sh)
[ "${PREP_ONLY:-0}" = 1 ] && { echo "build-owrt: prepared tree in $PWD"; exit 0; }
{ echo "$CFG"; echo "CONFIG_SDK=y"; echo "CONFIG_ALL_KMODS=n"; echo "CONFIG_ALL=n"; echo "CONFIG_ALL_NONSHARED=n"
  [ -f "$KPK" ] && sed -n 's/^\([a-z0-9-]*\)$/CONFIG_PACKAGE_\1=m/p' "$KPK"; true; } > .config
make defconfig >/dev/null
make download -j"$(nproc)" >"$OUT/download.log" 2>&1 || { tail -30 "$OUT/download.log"; exit 1; }
# the downloaded tarball must be the one kernel.org signs the hash for
f=$(ls dl/linux-$KERNEL_LINE.$KERNEL_PATCH.tar.* | head -1); echo "$KERNEL_SHA256  $f" | sha256sum -c - >/dev/null || { echo "build-owrt: kernel tarball sha256 mismatch" >&2; exit 1; }
make -j"$(nproc)" >"$OUT/build.log" 2>&1 || { tail -80 "$OUT/build.log"; echo "build-owrt: build failed, retrying single job for the error" >&2; make -j1 V=s >"$OUT/build-j1.log" 2>&1 || { tail -80 "$OUT/build-j1.log"; exit 1; }; }
mkdir -p "$OUT/bin"; cp -a bin/targets/. "$OUT/bin/"
cp .config "$OUT/dot-config"; cp "$K" "$OUT/kernel-$KERNEL_LINE"
( cd "$OUT/bin" && find . -type f | sort | xargs sha256sum ) > "$OUT/SHA256SUMS"
echo "build-owrt: done $T kernel $KERNEL_LINE.$KERNEL_PATCH"; tail -3 "$OUT/SHA256SUMS"
