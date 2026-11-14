#!/bin/bash
# INSIDE the build container (after stage-all.sh): re-emerge busybox with busybox.portage-env, rebuild the
# patronus binaries from /w/src, pack. Log /out/rebuild.log. (This is what produced the Slate's p4 image.)
exec > /out/rebuild.log 2>&1
set -x
T=mips-unknown-linux-musl; SYS=/usr/$T
mkdir -p $SYS/etc/portage/env/sys-apps; cp /w/busybox.portage-env $SYS/etc/portage/env/sys-apps/busybox
ROOT=/rootfs $T-emerge -q --nodeps sys-apps/busybox 2>&1 | tail -20
grep -E 'PREFER_APPLETS|SH_STANDALONE' /rootfs/etc/portage/savedconfig/sys-apps/busybox-* || true
rm -f /out/stage-patronus.ok
CLI_FEATURES=${CLI_FEATURES:-nftables,cli,dhcp-server,dns-server,uci-import} bash /w/stage-patronus.sh
bash /w/pack.sh
echo REBUILD-DONE
