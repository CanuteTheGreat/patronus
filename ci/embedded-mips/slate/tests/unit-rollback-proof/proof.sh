#!/bin/sh
# Rollback-path proof for a Slate root image, run INSIDE a chroot of that image (its own busybox, mtd-utils, patronus-flash,
# patronus-guard) on the unit's real kernel/UBI driver, against a THROWAWAY UBI device (ubi1 on mtdram). ubi0 is never touched.
# Test roots: tiny squashfs A/B (stand-ins for the running/new roots) and OWRT (stand-in for the embedded OpenWrt recovery root).
U=/dev/ubi1; S=/sys/class/ubi/ubi1; P=/tmp/pt
export PATRONUS_UBI=$U PATRONUS_DATA=/mnt PATRONUS_NOR_KERNEL=/nonexistent PATRONUS_FLASH_TMP=/tmp
fails=0; ok() { echo "PASS: $*"; }; bad() { echo "FAIL: $*"; fails=$((fails+1)); }
vid() { for d in $S/ubi1_*; do [ "$(cat $d/name 2>/dev/null)" = "$1" ] && { echo "${d##*_}"; return 0; }; done; return 0; }
nodes() { for d in $S/ubi1_*; do [ -e "$d/dev" ] || continue; n=/dev/${d##*/}; [ -c $n ] || { m=$(cat $d/dev); mknod $n c ${m%:*} ${m#*:}; }; done; }
volsha() { i=$(vid "$1"); [ -n "$i" ] || { echo none; return 0; }; nodes; head -c "$2" /dev/ubi1_$i | sha256sum | cut -c1-16; }
is() { [ "$(volsha "$1" "$(wc -c < "$2")")" = "$(sha256sum < "$2" | cut -c1-16)" ]; }
layout() { for d in $S/ubi1_*; do [ -e "$d/name" ] && printf '%s=%s ' "${d##*_}" "$(cat $d/name)"; done; echo; }
chk() { n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; echo "    layout: $(layout)"; fi; }
echo "== image under test: $(grep ^BUILD= /etc/patronus-release) ($(grep ^SOURCE= /etc/patronus-release))"
echo "== tools: ubinfo=$(command -v ubinfo) ubirename=$(command -v ubirename) busybox=$(readlink -f /bin/sh)"
# --- the unit's layout before a flash: rootfs (running root A), rootfs_prev, patronus_data (UBIFS), rootfs_data (OpenWrt overlay)
mk() { ubimkvol $U -N "$1" -s "$(wc -c < "$2")" >/dev/null && nodes && ubiupdatevol /dev/ubi1_$(vid "$1") "$2"; }
mk rootfs $P/A.sq; mk rootfs_prev $P/A.sq
ubimkvol $U -N patronus_data -s 2600000 >/dev/null; ubimkvol $U -N rootfs_data -m >/dev/null; nodes
echo "== start: $(layout)"
chk "setup: rootfs=A rootfs_prev=A patronus_data rootfs_data" sh -c "$(is rootfs $P/A.sq && is rootfs_prev $P/A.sq && echo true || echo false) && [ -n '$(vid patronus_data)' ] && [ -n '$(vid rootfs_data)' ]"
mount -t ubifs ubi1:patronus_data /mnt || bad "mount test patronus_data (UBIFS)"
echo "2 some-build" > /mnt/.init-boot-attempts
# --- T1 forward: patronus-flash root (what the unit runs to install a new root)
patronus-flash root $P/B.sq > /tmp/t1.log 2>&1; r=$?; tail -n 3 /tmp/t1.log | sed 's/^/    /'
chk "root: exit 0" [ $r = 0 ]
chk "root: rootfs = B (new root)" is rootfs $P/B.sq
chk "root: rootfs_prev = A (previous root kept)" is rootfs_prev $P/A.sq
chk "root: rootfs_data dropped, no rootfs_new left" sh -c "[ -z '$(vid rootfs_data)$(vid rootfs_new)' ]"
chk "root: unconfirmed-boot count cleared" [ ! -e /mnt/.init-boot-attempts ]
echo "== after root: $(layout)"
# --- T2 rollback (patronus-init's boot-loop rollback runs exactly this command)
patronus-flash rollback > /tmp/t2.log 2>&1; r=$?
chk "rollback: exit 0" [ $r = 0 ]
chk "rollback: rootfs = A" is rootfs $P/A.sq
chk "rollback: rootfs_prev = B" is rootfs_prev $P/B.sq
patronus-flash rollback > /tmp/t2b.log 2>&1; r=$?
chk "rollback again: back to rootfs = B, rootfs_prev = A" sh -c "[ $r = 0 ] && $(is rootfs $P/B.sq && echo true || echo false) && $(is rootfs_prev $P/A.sq && echo true || echo false)"
# --- T3 the same with mtd-utils' ubinfo unusable: busybox applets + sysfs only (the sl-4c39538a failure mode)
printf '#!/bin/sh\nexit 1\n' > /tmp/noubinfo; chmod 755 /tmp/noubinfo
UBINFO=$(command -v ubinfo); [ -n "$UBINFO" ] && mount --bind /tmp/noubinfo "$UBINFO"
ubinfo $U -N rootfs >/dev/null 2>&1 && bad "ubinfo still works (bind failed)" || ok "ubinfo disabled for the sysfs-fallback run"
patronus-flash rollback > /tmp/t3.log 2>&1; r=$?
chk "rollback without ubinfo: rootfs = A" sh -c "[ $r = 0 ] && $(is rootfs $P/A.sq && echo true || echo false)"
patronus-flash rollback > /tmp/t3b.log 2>&1; r=$?
chk "rollback without ubinfo, again: rootfs = B" sh -c "[ $r = 0 ] && $(is rootfs $P/B.sq && echo true || echo false) && $(is rootfs_prev $P/A.sq && echo true || echo false)"
[ -n "$UBINFO" ] && umount "$UBINFO"
# --- T4 the guard's revert: an unconfirmed boot after GRACE -> patronus-flash openwrt (embedded stock root + config) -> restart
# (images before the config-mount fix hard-code ubi0:rootfs_data: for those, a copy with only that mount pointed at ubi1)
sed 's#ubi0:rootfs_data#ubi1:rootfs_data#' /usr/sbin/patronus-flash > /tmp/pf-ubi1; chmod 755 /tmp/pf-ubi1
grep 'ubi0:rootfs_data' /usr/sbin/patronus-flash >/dev/null && echo "    (this image hard-codes ubi0:rootfs_data: testing a copy with that one mount changed)"
mkdir -p /tmp/rec /tmp/gr; cp $P/OWRT.sq /tmp/rec/openwrt-root.squashfs; cp $P/cfg.tgz /tmp/rec/sysupgrade.tgz
rm -f /mnt/.guard-auto
PATRONUS_RECOVERY=/tmp/rec PATRONUS_FLASH=/tmp/pf-ubi1 PATRONUS_BOARD=/nonexistent PATRONUS_GUARD_GRACE=1 PATRONUS_GUARD_GW= \
  PATRONUS_GUARD_RUN=/tmp/gr PATRONUS_GUARD_DATA=/mnt PATRONUS_REBOOT="touch /tmp/gr/restarted" patronus-guard arm > /tmp/t4.log 2>&1
sed 's/^/    guard-state: /' /tmp/gr/patronus-guard.state; sed 's/^/    flash: /' /mnt/guard-log/flash.txt 2>/dev/null | tail -n 4
chk "guard: unconfirmed boot -> REVERTING" grep -q REVERTING /tmp/gr/patronus-guard.state
chk "guard: rootfs = embedded OpenWrt root" is rootfs $P/OWRT.sq
chk "guard: rootfs_prev = the unconfirmed root (B)" is rootfs_prev $P/B.sq
chk "guard: rootfs_data recreated" [ -n "$(vid rootfs_data)" ]
mkdir -p /tmp/rd; mount -t ubifs ubi1:rootfs_data /tmp/rd && { chk "guard: OpenWrt config backup placed on rootfs_data" cmp -s /tmp/rd/sysupgrade.tgz $P/cfg.tgz; umount /tmp/rd; } || bad "mount rootfs_data"
chk "guard: restart requested after the revert" [ -e /tmp/gr/restarted ]
# --- T5 the guard does NOT revert a confirmed boot (patronus-guard ok) nor an auto-confirmed one (.guard-auto + gateway + sshd)
rm -rf /tmp/gr2; mkdir -p /tmp/gr2; PATRONUS_GUARD_RUN=/tmp/gr2 PATRONUS_GUARD_DATA=/mnt patronus-guard ok >/dev/null
PATRONUS_FLASH=/bin/false PATRONUS_BOARD=/nonexistent PATRONUS_GUARD_GRACE=1 PATRONUS_GUARD_RUN=/tmp/gr2 PATRONUS_GUARD_DATA=/mnt \
  PATRONUS_REBOOT="touch /tmp/gr2/restarted" patronus-guard arm >/dev/null 2>&1
chk "guard ok: confirmed boot stays, no restart" sh -c "grep -q 'confirmed by operator' /tmp/gr2/patronus-guard.state && [ ! -e /tmp/gr2/restarted ]"
umount /mnt
echo "== end: $(layout)"
[ "$fails" = 0 ] && echo "FAILED: none" || echo "FAILED: $fails"
