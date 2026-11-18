#!/bin/sh
# nand-budget.sh <root.squashfs> <kernel> [factory.ubi]: does the image fit the GL-AX1800's UBI, with room for settings?
# Layout from the device profile's [nand] table (profiles/hw/qualcommax-gl-ax1800.toml), checked against OpenWrt's own
# factory.ubi with ubi-layout.py (docs/embedded-routers.md section 7): mtd "rootfs" = 920 PEBs of 128 KiB holding ONE UBI
# device with the volumes kernel (id 0, the FIT), rootfs (id 1, ubiblock0_1) and rootfs_data (id 2, autoresize; Patronus
# renames it patronus_data on first boot). A volume takes ceil(bytes / LEB) LEBs, LEB = PEB - 2 pages = 126976 B (the
# 25.12.6 factory.ubi: kernel 5305856 B = 42, root 7344128 B = 58, exactly its reserved_pebs). UBI keeps reserved_pebs back
# (layout volume 2 + wear-levelling 1 + atomic LEB change 1 + bad-block reserve 20 per 1024 PEBs of the 128 MiB chip).
# With [factory.ubi]: its layout is checked too (ubi-layout.py check) and its kernel/rootfs volumes must match the parts.
# NAND_DATA_MIN / NAND_MARGIN (KiB) override the profile's data_min_kib / margin_kib.
# Boot rollback (12.16) keeps the previous image as kernel_prev/rootfs_prev: counted at this image's size unless
# NAND_ROLLBACK=0.
# Exit 0 = fits with margin, 1 = over budget or bad layout, 2 = usage.
HERE=$(cd "$(dirname "$0")" && pwd)
R=${1:-}; K=${2:-}; U=${3:-}
[ -f "$R" ] && [ -f "$K" ] || { echo "usage: nand-budget.sh <root.squashfs> <kernel> [factory.ubi]"; exit 2; }
PROFILE=${HW_PROFILE:-$HERE/../../../profiles/hw/qualcommax-gl-ax1800.toml}
ENV=$(python3 "$HERE/../../hw-profile/hwprofile.py" env "$PROFILE") || exit 2
eval "$ENV"
PART=$HW_NAND_UBI_MTD_BYTES; PEB=$HW_NAND_PEB_BYTES; LEB=$HW_NAND_LEB_BYTES; RESERVE=$HW_NAND_RESERVED_PEBS
DATA=${NAND_DATA_MIN:-$HW_NAND_DATA_MIN_KIB}; MARGIN=${NAND_MARGIN:-$HW_NAND_MARGIN_KIB}
lebs() { echo $(( ($(wc -c < "$1") + LEB - 1) / LEB )); }
total=$((PART / PEB)); avail=$((total - RESERVE))
k=$(lebs "$K"); r=$(lebs "$R"); d=$(( (DATA * 1024 + LEB - 1) / LEB ))
if [ -n "$U" ]; then
  python3 "$HERE/ubi-layout.py" check "$U" --profile "$PROFILE" || { echo "NAND budget: $U has the wrong UBI layout"; exit 1; }
  uk=$(python3 "$HERE/ubi-layout.py" show "$U" | python3 -c 'import json,sys; v={x["name"]:x for x in json.load(sys.stdin)["volumes"]}; print(v["kernel"]["reserved_pebs"], v["rootfs"]["reserved_pebs"])')
  # shellcheck disable=SC2086
  set -- $uk
  [ "$1" = "$k" ] && [ "$2" = "$r" ] || { echo "NAND budget: factory.ubi reserves kernel $1 / rootfs $2 PEBs, the parts need $k / $r"; exit 1; }
fi
rb=0; [ "${NAND_ROLLBACK:-1}" = 1 ] && rb=$((k + r))
used=$((k + r + d + rb)); free=$((avail - used)); fkib=$((free * LEB / 1024)); mkib=$MARGIN
printf 'NAND budget: UBI %d PEBs - %d reserved = %d LEBs; kernel %d + root %d + rollback copy %d + settings(min %d KiB) %d = %d; free %d LEBs = %d KiB (margin wanted %d KiB)\n' \
  "$total" "$RESERVE" "$avail" "$k" "$r" "$rb" "$DATA" "$d" "$used" "$free" "$fkib" "$mkib"
if [ "$fkib" -lt "$mkib" ]; then echo "NAND budget: OVER by $((mkib - fkib)) KiB"; exit 1; fi
echo "NAND budget: fits"
