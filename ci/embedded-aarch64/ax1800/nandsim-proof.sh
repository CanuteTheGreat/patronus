#!/bin/bash
# nandsim-proof.sh <factory.ubi> <new-sysupgrade.tar>: the GL-AX1800 UBI paths against the real Linux UBI driver on a
# simulated 128 MiB SPI-NAND of the board's geometry (nandsim: 2048-byte pages, 128 KiB blocks, 1024 blocks), no router.
#   1. ubiformat the simulated flash with factory.ubi (what GL's U-Boot web recovery does with it), attach UBI
#   2. first boot: ubi-data replaces rootfs_data with patronus_data (with upgrade headroom); write a settings file on UBIFS
#   3. upgrade: patronus-flash check/sysupgrade guards against this UBI, then upgrade-install ubi-write writes the other
#      image's kernel + root into volumes 0/1 (growing rootfs with ubirsvol when needed) and reads both back
#   4. the settings volume and its file survive; the layout is still kernel=0 rootfs=1
# Needs root, the host's nandsim/ubi/ubifs modules (loaded by the caller) and the builder image tools. Not run in CI:
# loading nandsim on a shared runner host is a host change. Prints PASS/FAIL, ends with "FAILED: none".
set -uo pipefail
FU=${1:?factory.ubi}; NEW=${2:?sysupgrade tar}; H=$(cd "$(dirname "$0")" && pwd); LIB=$H/overlay/usr/libexec/patronus
MTD=${MTD:-$(sed -n 's/^\(mtd[0-9]*\): .*"NAND simulator.*/\1/p' /proc/mtd | head -1)}
[ -n "$MTD" ] || { echo "no nandsim mtd in /proc/mtd"; exit 2; }
fails=(); pass() { echo "PASS: $*"; }; fail() { echo "FAIL: $*"; fails+=("$*"); }
chk() { n=$1; shift; if o=$("$@" 2>&1); then pass "$n"; else fail "$n"; echo "$o" | tail -8 | sed 's/^/    /'; fi; }
N=${MTD#mtd}
echo "== mtd: $(grep "^$MTD:" /proc/mtd)"
ubidetach -m "$N" 2>/dev/null
chk "ubiformat the simulated NAND with factory.ubi (U-Boot recovery path)" ubiformat "/dev/$MTD" -y -q -s 2048 -O 2048 -f "$FU"
# nandsim's raw NAND allows 512-byte sub-page writes, the board's SPI-NAND does not: attach with the board's VID header
# offset (2048, as in factory.ubi), which is what the board's kernel derives on its own
D=$(ubiattach -m "$N" -O 2048 2>&1 | sed -n 's/.*UBI device number \([0-9]*\).*/\1/p'); U=/dev/ubi$D
[ -c "$U" ] || { fail "ubiattach"; echo "FAILED: ${fails[*]}"; exit 1; }
vols() { ubinfo "$U" -a | awk '/^Volume ID/{id=$3} /^Name:/{print id"="$2}' | tr '\n' ' '; }
echo "== after attach: $(vols); $(ubinfo "$U" | grep -E 'Amount of (available|logical eraseblocks)|Count of bad' | tr -s ' ' | tr '\n' ';')"
chk "factory.ubi volumes kernel=0 rootfs=1 rootfs_data=2" sh -c "[ \"$(vols)\" = '0=kernel 1=rootfs 2=rootfs_data ' ]"
ra=$(ubinfo "$U" -n 2 | sed -n 's/^Size: *\([0-9]*\) LEBs.*/\1/p')
chk "rootfs_data autoresized over the free flash on first attach ($ra LEBs)" test "$ra" -gt 500
id=$(sh "$LIB/ubi-data" "$U") ; echo "== first boot: $(vols)"
chk "first boot: patronus_data replaces rootfs_data, upgrade headroom left free" sh -c "[ -n '$id' ] && ! ubinfo $U -N rootfs_data >/dev/null 2>&1 && [ \$(ubinfo $U | sed -n 's/^Amount of available logical eraseblocks: *\([0-9]*\).*/\1/p') -ge 264 ]"
mkdir -p /tmp/ud && mount -t ubifs "ubi$D:patronus_data" /tmp/ud && echo "settings-$$" > /tmp/ud/settings && sync
chk "settings written to UBIFS on patronus_data" test -s /tmp/ud/settings
# upgrade: guards against this UBI (board identity faked: the host is not a GL-AX1800), then the installer's write step
printf 'glinet,gl-ax1800\0qcom,ipq6018\0' > /tmp/compat
FE="PATRONUS_DT_COMPAT=/tmp/compat PATRONUS_UBI=$U PATRONUS_LIB=$LIB PATRONUS_DATA=/tmp/ud"
chk "patronus-flash check: the new image passes every guard against this UBI" env $FE sh "$H/overlay/usr/sbin/patronus-flash" check "$NEW"
chk "patronus-flash sysupgrade stages it on patronus_data" env $FE sh "$H/overlay/usr/sbin/patronus-flash" sysupgrade "$NEW"
chk "upgrade-install verify (the early-boot re-check)" env $FE sh "$LIB/upgrade-install" verify
ubiblock -c "${U}_1" 2>/dev/null && echo "== ubiblock on rootfs created (released by ubi-write)"
before=$(ubinfo "$U" -n 1 | sed -n 's/^Size: *\([0-9]*\) LEBs.*/\1/p')
chk "upgrade-install ubi-write: root then kernel written, read back, sha256 equal" env PATRONUS_UBI=$U sh "$LIB/upgrade-install" ubi-write /tmp/ud/.upgrade/kernel /tmp/ud/.upgrade/root
after=$(ubinfo "$U" -n 1 | sed -n 's/^Size: *\([0-9]*\) LEBs.*/\1/p'); echo "== rootfs volume $before -> $after LEBs"
chk "volumes still kernel=0 rootfs=1, patronus_data kept" sh -c "vols=\$(ubinfo $U -a | awk '/^Volume ID/{id=\$3} /^Name:/{print id\"=\"\$2}' | tr '\n' ' '); case \"\$vols\" in '0=kernel 1=rootfs '*patronus_data*) ;; *) echo \$vols; exit 1;; esac"
k=$(stat -c%s /tmp/ud/.upgrade/kernel); r=$(stat -c%s /tmp/ud/.upgrade/root)
chk "kernel volume = the new kernel" sh -c "[ \"\$(head -c $k ${U}_0 | sha256sum | cut -c1-64)\" = \"\$(sha256sum < /tmp/ud/.upgrade/kernel | cut -c1-64)\" ]"
chk "rootfs volume = the new root" sh -c "[ \"\$(head -c $r ${U}_1 | sha256sum | cut -c1-64)\" = \"\$(sha256sum < /tmp/ud/.upgrade/root | cut -c1-64)\" ]"
umount /tmp/ud; mount -t ubifs "ubi$D:patronus_data" /tmp/ud
chk "settings file survived the upgrade" grep -q "settings-$$" /tmp/ud/settings
umount /tmp/ud; ubiblock -r "${U}_1" 2>/dev/null; ubidetach -m "$N"
[ ${#fails[@]} = 0 ] && { echo "FAILED: none"; exit 0; }; echo "FAILED: ${fails[*]}"; exit 1
