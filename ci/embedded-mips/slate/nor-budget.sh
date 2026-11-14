#!/bin/sh
# nor-budget.sh <root.squashfs> <kernel>   size budget of the 16 MiB NOR-only router tier (no NAND: the whole system
# lives in the SPI NOR next to U-Boot). Exit 0 = fits with margin, 1 = over budget, 2 = usage.
# Layout (OpenWrt's ath79 16 MiB NOR boards, e.g. glinet,gl-ar750s-nor): u-boot 256 KiB + u-boot-env 64 KiB +
# art 64 KiB, then "firmware" = 16000 KiB holding the kernel, the root squashfs and the settings partition, each
# starting on a 64 KiB erase block. The settings partition (jffs2 on NOR: config store, TLS key, /etc overlay) needs
# NOR_DATA_MIN KiB (default 1024: the Slate's settings use 140 KiB, jffs2 needs ~5 spare erase blocks for GC) and
# NOR_MARGIN KiB (default 256) stays free for growth between releases. The root is built with NOR_PROFILE=1 (no
# embedded OpenWrt recovery root: on NOR the stock firmware is not carried inside the root image).
R=${1:-}; K=${2:-}
[ -f "$R" ] && [ -f "$K" ] || { echo "usage: nor-budget.sh <root.squashfs> <kernel>"; exit 2; }
FIRMWARE_KIB=${NOR_FIRMWARE_KIB:-16000}; DATA=${NOR_DATA_MIN:-1024}; MARGIN=${NOR_MARGIN:-256}
eb() { echo $(( ($(wc -c < "$1") + 65535) / 65536 * 64 )); }   # KiB, rounded up to 64 KiB erase blocks
k=$(eb "$K"); r=$(eb "$R"); used=$((k + r + DATA)); free=$((FIRMWARE_KIB - used))
printf 'NOR budget: kernel %d KiB + root %d KiB + settings %d KiB = %d of %d KiB; free %d KiB (margin wanted %d KiB)\n' \
  "$k" "$r" "$DATA" "$used" "$FIRMWARE_KIB" "$free" "$MARGIN"
if [ "$free" -lt "$MARGIN" ]; then echo "NOR budget: OVER by $((MARGIN - free)) KiB"; exit 1; fi
echo "NOR budget: fits"
