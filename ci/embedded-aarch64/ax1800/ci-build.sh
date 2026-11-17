#!/bin/bash
# ci-build.sh: INSIDE the builder image (Dockerfile.builder), the whole GL-AX1800 build from a source tree in /w/src:
#   patronus-cli (stage-patronus.sh), systemd (stage-systemd.sh), the Alpine userland (stage-rootfs.sh), OpenRC from source
#   (stage-openrc.sh), pack,
#   the pinned OpenWrt parts (fetch-stock.sh), a throwaway CI unit (ci-unit.sh), then assemble.sh for BOTH init systems
#   (OpenRC and systemd), the NAND budget (inside assemble.sh) and the host tests. Output: /out/images/{openrc,systemd}/<tag>/,
#   /out/unit (CI ssh key for the QEMU gate), /out/stock (VIRT_KERNEL for the gate), /out/summary.txt.
# Caches (optional volumes): /cache/cargo (CARGO_HOME registry), /cache/target, /cache/stock, /cache/systemd.
# Env: TAG (default ci-<short sha>), SOURCE_REV, VARIANTS (default "openrc systemd"). The systemd tree is rebuilt only when
# stage-systemd.sh changes (stamp in /cache/systemd).
set -euo pipefail
H=/w/src/ci/embedded-aarch64/ax1800
TAG=${TAG:-ci-$(echo "${SOURCE_REV:-local}" | cut -c1-8)}
VARIANTS=${VARIANTS:-openrc systemd}
mkdir -p /out /cache/cargo /cache/target /cache/stock /cache/systemd
export CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target
[ -d /cache/cargo/bin ] || cp -a /root/.cargo/. /cache/cargo/
export PATH=/cache/cargo/bin:$PATH
t0=$(date +%s); step() { echo "== $(date -u +%T) (+$(( $(date +%s) - t0 ))s) $*"; }

step "host tests (image tooling)"
sh "$H/tests/run.sh"

step "patronus-cli (aarch64 musl, multi-call)"
bash "$H/stage-patronus.sh" || { tail -40 /out/build-patronus-cli.log; exit 1; }

case " $VARIANTS " in *" systemd "*)
step "systemd"
if [ -s /cache/systemd/systemd-root.tar ] && [ "$(cat /cache/systemd/stamp 2>/dev/null)" = "$(sha256sum "$H/stage-systemd.sh" | cut -c1-16)" ]; then
  echo "systemd tree cached (stage-systemd.sh unchanged)"
else
  bash "$H/stage-systemd.sh"
  tar cf /cache/systemd/systemd-root.tar -C /out/systemd-root .
  sha256sum "$H/stage-systemd.sh" | cut -c1-16 > /cache/systemd/stamp
fi ;;
esac

step "hostapd (Patronus package), userland + OpenRC (Alpine packages), pack"
bash "$H/stage-hostapd.sh"; bash "$H/stage-rootfs.sh"; bash "$H/stage-openrc.sh"; bash "$H/pack.sh"

step "OpenWrt parts (sha256-pinned)"
eval "$(sh "$H/fetch-stock.sh" /cache/stock)"
export STOCK_ROOT STOCK_SYSUPGRADE
mkdir -p /out/stock; cp "$VIRT_KERNEL" /out/stock/virt-kernel.bin
# reference layout: OpenWrt's own factory.ubi for this board must pass the same layout check ours does
python3 "$H/ubi-layout.py" check "$FACTORY_UBI"

step "throwaway CI unit"
sh "$H/ci-unit.sh" /out/unit
export UNIT_DIR=/out/unit SOURCE_REV=${SOURCE_REV:-unknown}

: > /out/summary.txt
for init in $VARIANTS; do
  step "assemble ($init)"
  if [ $init = openrc ]; then export OPENRC_TREE=/out/pack/openrc.tar; unset SYSTEMD_TREE; else unset OPENRC_TREE; export SYSTEMD_TREE=/cache/systemd/systemd-root.tar; fi
  OUT_DIR=/out/images/$init bash "$H/assemble.sh" /out/pack "$TAG-$init"
  { echo "### $init"; cat "/out/images/$init/$TAG-$init/sizes.txt" "/out/images/$init/$TAG-$init/nand-budget.txt"; } >> /out/summary.txt
done
step "done"; cat /out/summary.txt
