#!/bin/bash
# nor-ci.sh: the 16 MiB NOR tier size budget, end to end, for BOTH init variants (CI job "NOR tier size budget" in
# .forgejo/workflows/embedded-tier.yml). Runs inside the embedded builder image (pembed-slate-img:ci on the arm64 build
# host: crossdev mips-unknown-linux-musl sysroot, the router rootfs in /rootfs, OpenRC in /rootfs-openrc, and in
# /opt/pembed the cross-built systemd tree + libucontext and the stock OpenWrt 25.12.6 sysupgrade image).
#   1. build the multi-call patronus-cli from this checkout (stage-patronus.sh), pack it with the rootfs (pack.sh)
#   2. assemble the NOR-profile root (no recovery root, 1 MiB xz blocks) for OpenRC and for systemd (assemble.sh,
#      throwaway unit files: the budget does not depend on per-unit data)
#   3. nor-budget.sh: kernel + root + settings must leave the margin free in the 16000 KiB firmware partition
set -euo pipefail
SRC=$(cd "$(dirname "$0")/../../.." && pwd); HERE=$SRC/ci/embedded-mips/slate
P=/opt/pembed; T=mips-unknown-linux-musl
STOCK_SU=$P/openwrt-25.12.6-ath79-nand-glinet_gl-ar750s-nor-nand-squashfs-sysupgrade.bin
echo "3d58b599daca2a239f745cf5d739d624d6262302000df1615295ca03c594ed03  $STOCK_SU" | sha256sum -c -
W=${NOR_CI_DIR:-/tmp/nor-ci}; rm -rf "$W"; mkdir -p "$W"/{unit/hostapd,out,stock,kern}
# 1. binaries (stage-patronus.sh copies /w/src; the builder image's scripts expect /w and /out)
mkdir -p /w /out; rm -rf /w/src; mkdir -p /w/src; tar cf - -C "$SRC" --exclude=./target --exclude=./.git . | tar xf - -C /w/src
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/out/target-s}
bash "$HERE/stage-patronus.sh"
bash "$HERE/pack.sh"
# stock OpenWrt pieces: its root (kmods, firmware, swconfig) and kernel
tar xf "$STOCK_SU" -C "$W/kern" --wildcards '*/kernel' '*/root'
unsquashfs -q -d "$W/stock/root" "$W"/kern/*/root >/dev/null
# 2. throwaway unit files (assemble.sh wants the per-unit inputs; sizes are what matter)
U=$W/unit
echo 'root:*:1::::::' > "$U/shadow-root"; : > "$U/authorized_keys"
for k in rsa ecdsa ed25519; do head -c 400 /dev/urandom > "$U/dropbear_${k}_host_key"; done
{ echo 'network={'; echo ' ssid="ci"'; printf ' %s="%s"\n' psk "$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"; echo '}'; } > "$U/wpa_supplicant.conf"
rc=0
for v in openrc systemd; do
  if [ $v = openrc ]; then export OPENRC_TREE=/out/pack/openrc.tar; unset SYSTEMD_TREE SYSTEMD_LIBS
  else unset OPENRC_TREE; export SYSTEMD_TREE=$P/systemd-strip.tar SYSTEMD_LIBS=$P/libucontext.so.1; fi
  NOR_PROFILE=1 STOCK_ROOT=$W/stock/root STOCK_SYSUPGRADE=$STOCK_SU UNIT_DIR=$U OUT_DIR=$W/out TMPDIR=$W SOURCE_REV="ci $(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo ?)" \
    bash "$HERE/assemble.sh" /out/pack nor-$v > "$W/assemble-$v.log" 2>&1 || { tail -30 "$W/assemble-$v.log"; exit 1; }
  echo "== $v"; sh "$HERE/nor-budget.sh" "$W/out/nor-$v/root.squashfs" "$W"/kern/*/kernel || rc=1
done
exit $rc
