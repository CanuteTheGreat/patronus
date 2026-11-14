#!/bin/sh
# Host tests for the GL-AR750S image tooling (no router, no root): run as `sh ci/embedded-mips/slate/tests/run.sh`.
# - every shell script parses (sh -n / bash -n), t_slate.py compiles
# - check-rootfs.sh accepts a good root and rejects the three mistakes that cost a real flash
# - patronus-flash root / rollback / openwrt / factory-reset against a fake UBI (fake-ubi/ = ubinfo, ubimkvol, ...)
# - patronus-guard: operator-confirmed boot stays, unconfirmed boot reverts (flash openwrt + reboot), unattended mode
set -u
D=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/slate-tests.XXXX"); trap 'rm -rf "$W"' EXIT
pass=0; failn=0
ok() { echo "PASS: $*"; pass=$((pass+1)); }
no() { echo "FAIL: $*"; failn=$((failn+1)); }
t() { name=$1; shift; if "$@" >"$W/out" 2>&1; then ok "$name"; else no "$name"; sed 's/^/    /' "$W/out"; fi; }
tn() { name=$1; shift; if "$@" >"$W/out" 2>&1; then no "$name (expected failure)"; sed 's/^/    /' "$W/out"; else ok "$name"; fi; }

# 1. syntax
for f in "$D"/*.sh "$D"/overlay/usr/libexec/patronus/* "$D"/overlay/usr/sbin/* "$D"/overlay/etc/patronus/board.sh "$D"/tests/fake-ubi/*; do
  case "$(head -1 "$f")" in *bash*) t "bash -n ${f#$D/}" bash -n "$f";; *) t "sh -n ${f#$D/}" sh -n "$f";; esac
done
# OpenRC scripts: openrc-run syntax is sh plus depend/start functions
for f in "$D"/overlay-openrc/etc/init.d/*; do t "sh -n ${f#$D/}" sh -n "$f"; t "openrc-run shebang ${f#$D/}" grep -q '^#!/sbin/openrc-run' "$f"; done
# parity: every service of one variant exists in the other (OpenRC script <-> systemd unit)
for p in "patronus-board:patronus-network" "patronus-apply:patronus-apply" "patronus-applyd:patronus-applyd" "patronus-web:patronus-web" "dropbear:patronus-dropbear" "patronus-ntpd:patronus-ntpd"; do
  t "parity ${p%%:*} (OpenRC) = ${p#*:}.service (systemd)" sh -c "[ -x '$D/overlay-openrc/etc/init.d/${p%%:*}' ] && [ -L '$D/overlay-systemd/etc/systemd/system/multi-user.target.wants/${p#*:}.service' ]"
done
t "py_compile t_slate.py" python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$D/t_slate.py"

# 2. check-rootfs.sh
mkroot() { r=$W/root-$1; rm -rf "$r"; mkdir -p "$r/etc/wpa_supplicant" "$r/bin" "$r/sbin" "$r/root/.ssh" "$r/var/lib/misc" "$r/usr/sbin" "$r/usr/share/patronus-recovery" "$r/etc/init.d" "$r/usr/libexec/patronus" "$r/etc/pam.d" "$r/lib/security"
  printf 'network={\n ssid="x"\n psk="y"\n}\n' > "$r/etc/wpa_supplicant/wpa_supplicant.conf"
  printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > "$r/etc/passwd"
  echo 'root:$6$salt$hash:1::::::' > "$r/etc/shadow"; ln -s busybox "$r/bin/sh"; : > "$r/bin/busybox"; chmod +x "$r/bin/busybox"
  : > "$r/usr/sbin/patronus-guard"; : > "$r/usr/sbin/patronus-flash"; : > "$r/usr/sbin/patronus-init"; : > "$r/usr/libexec/patronus/early"
  : > "$r/etc/pam.d/patronus"; : > "$r/lib/security/pam_unix.so"; ln -s /usr/sbin/patronus-init "$r/sbin/init"; echo INIT=openrc > "$r/etc/patronus-init"
  for b in openrc-init openrc-run supervise-daemon; do : > "$r/sbin/$b"; chmod +x "$r/sbin/$b"; done; printf '#!/bin/sh\nexec /sbin/openrc-shutdown -r now\n' > "$r/sbin/reboot"; chmod +x "$r/sbin/reboot"
  for s in patronus-board patronus-apply patronus-applyd patronus-web dropbear dnsmasq patronus-dhcpc; do : > "$r/etc/init.d/$s"; chmod +x "$r/etc/init.d/$s"; done
  echo "http 80/tcp" > "$r/etc/services"
  printf 'hsqs....' > "$r/usr/share/patronus-recovery/openwrt-root.squashfs"; echo "$r"; }
t "check-rootfs: good root" "$D/check-rootfs.sh" "$(mkroot good)"
r=$(mkroot upd); sed -i '1i update_config=1' "$r/etc/wpa_supplicant/wpa_supplicant.conf"
tn "check-rootfs: rejects update_config (p1)" "$D/check-rootfs.sh" "$r"
r=$(mkroot bash); sed -i 's#^root:.*#root:!:0:0:root:/root:/bin/bash#' "$r/etc/passwd"
tn "check-rootfs: rejects root:! with a missing /bin/bash (p2)" "$D/check-rootfs.sh" "$r"
r=$(mkroot noguard); rm "$r/usr/sbin/patronus-guard"
tn "check-rootfs: rejects an image without the guard" "$D/check-rootfs.sh" "$r"
r=$(mkroot rec); printf 'XXXX' > "$r/usr/share/patronus-recovery/openwrt-root.squashfs"
tn "check-rootfs: rejects a recovery root that is not a squashfs" "$D/check-rootfs.sh" "$r"
r=$(mkroot bbinit); echo INIT=busybox > "$r/etc/patronus-init"
tn "check-rootfs: rejects busybox init (not a variant: OpenRC or systemd)" "$D/check-rootfs.sh" "$r"
r=$(mkroot bbreboot); ln -sf /bin/busybox "$r/sbin/reboot"
tn "check-rootfs: rejects busybox reboot on OpenRC (SIGTERM = openrc-init halts)" "$D/check-rootfs.sh" "$r"
r=$(mkroot nodhcpc); rm "$r/etc/init.d/patronus-dhcpc"
tn "check-rootfs: rejects an OpenRC image without patronus-dhcpc (the WAN lease)" "$D/check-rootfs.sh" "$r"

# 3. patronus-flash on a fake UBI
export FAKE_UBI=$W/ubi; mkdir -p "$FAKE_UBI" "$W/bin" "$W/data" "$W/rec"
for n in ubinfo ubimkvol ubirmvol ubirename ubiupdatevol mount umount logger; do ln -sf "$D/tests/fake-ubi/ubi" "$W/bin/$n"; done
export PATH="$W/bin:$PATH" PATRONUS_UBI=$FAKE_UBI/ubi0 PATRONUS_FLASH_TMP=$W PATRONUS_DATA=$W/data PATRONUS_RECOVERY=$W/rec
F=$D/overlay/usr/sbin/patronus-flash
vol() { cat "$FAKE_UBI/by-name/$1" 2>/dev/null; }
ubimkvol "$PATRONUS_UBI" -N rootfs -s 8 >/dev/null; printf 'hsqs-A' > "$FAKE_UBI/by-name/rootfs"
printf 'hsqs-B' > "$W/b.sq"; printf 'hsqs-OPENWRT' > "$W/rec/openwrt-root.squashfs"; printf 'cfg' > "$W/rec/sysupgrade.tgz"
t "flash root: new root becomes rootfs" sh -c "'$F' root '$W/b.sq' && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-B ]"
t "flash root: old root kept as rootfs_prev" test "$(vol rootfs_prev)" = hsqs-A
tn "flash root: refuses a non-squashfs" "$F" root "$W/rec/sysupgrade.tgz"
t "flash rollback: previous root boots again" sh -c "'$F' rollback && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-A ] && [ \"\$(cat $FAKE_UBI/by-name/rootfs_prev)\" = hsqs-B ]"
t "flash rollback twice: back to B" sh -c "'$F' rollback && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-B ]"
t "flash openwrt: stock root + rootfs_data + config placed" sh -c "'$F' openwrt && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-OPENWRT ] && [ -e $FAKE_UBI/by-name/rootfs_data ] && [ \"\$(cat $W/pf/rd/sysupgrade.tgz)\" = cfg ]"
t "flash openwrt: patronus root kept as rootfs_prev" test "$(vol rootfs_prev)" = hsqs-B
mkdir -p "$W/sut/sysupgrade-x"; printf 'hsqs-TAR' > "$W/sut/sysupgrade-x/root"; tar cf "$W/su.tar" -C "$W/sut" sysupgrade-x
t "flash openwrt: from a sysupgrade tar" sh -c "'$F' openwrt '$W/su.tar' '' && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-TAR ]"
# after an OpenWrt sysupgrade, rootfs_data holds all free space (p4 -> sd1 on the real unit: ENOSPC, and the old
# flash had already deleted rootfs_prev). Now: rootfs_data goes first and the rollback target survives.
rm -rf "$FAKE_UBI"; mkdir -p "$FAKE_UBI"
for v in rootfs rootfs_prev patronus_data rootfs_data; do ubimkvol "$PATRONUS_UBI" -N $v -s 1 >/dev/null; done
printf 'hsqs-CUR' > "$FAKE_UBI/by-name/rootfs"; printf 'hsqs-PREV' > "$FAKE_UBI/by-name/rootfs_prev"; echo 4 > "$FAKE_UBI/max-vols"
t "flash root on a full UBI: drops rootfs_data, new root in" sh -c "'$F' root '$W/b.sq' && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-B ] && [ ! -e $FAKE_UBI/by-name/rootfs_data ]"
t "flash root on a full UBI: the running root became rootfs_prev" test "$(vol rootfs_prev)" = hsqs-CUR
echo 3 > "$FAKE_UBI/max-vols"
t "flash root with room for only one root: drops rootfs_prev and still installs" sh -c "'$F' root '$W/b.sq' && [ \"\$(cat $FAKE_UBI/by-name/rootfs)\" = hsqs-B ]"
echo 2 > "$FAKE_UBI/max-vols"; printf 'hsqs-KEEP' > "$FAKE_UBI/by-name/rootfs"
tn "flash root with no room at all fails" "$F" root "$W/b.sq"
t "...and leaves the running root alone" test "$(vol rootfs)" = hsqs-KEEP
rm -f "$FAKE_UBI/max-vols"
t "flash factory-reset: marker for the early boot" sh -c "'$F' factory-reset && [ -f $W/data/.factory-reset ]"
t "early boot wipes settings on the factory-reset marker" grep -q '\.factory-reset.*rm -rf /data/overlay /data/tls' "$D/overlay/usr/libexec/patronus/early"

# 4. patronus-guard
G=$D/overlay/usr/sbin/patronus-guard
export PATRONUS_GUARD_GRACE=0 PATRONUS_GUARD_RUN=$W/run PATRONUS_GUARD_DATA=$W/gdata PATRONUS_FLASH="$W/bin/rec-flash" PATRONUS_REBOOT="$W/bin/rec-reboot"
printf '#!/bin/sh\necho "flash $*" >> %s/calls\n' "$W" > "$W/bin/rec-flash"; printf '#!/bin/sh\necho reboot >> %s/calls\n' "$W" > "$W/bin/rec-reboot"
printf '#!/bin/sh\nexit ${FAKE_PING_RC:-1}\n' > "$W/bin/ping"; printf '#!/bin/sh\necho "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN"\n' > "$W/bin/netstat"
chmod +x "$W/bin/rec-flash" "$W/bin/rec-reboot" "$W/bin/ping" "$W/bin/netstat"
reset_g() { rm -rf "$W/run" "$W/gdata" "$W/calls"; mkdir -p "$W/run" "$W/gdata"; }
reset_g; touch "$W/run/patronus-good"
t "guard: operator-confirmed boot stays" sh -c "'$G' arm && [ ! -e $W/calls ] && grep -q 'confirmed by operator' $W/run/patronus-guard.state"
reset_g
t "guard: unconfirmed boot reverts to OpenWrt and reboots" sh -c "'$G' arm; grep -q 'flash openwrt' $W/calls && grep -q reboot $W/calls && grep -q REVERTING $W/run/patronus-guard.state && [ -d $W/gdata/guard-log ]"
reset_g; touch "$W/gdata/.guard-auto"
t "guard: unattended mode stays when the gateway answers" sh -c "FAKE_PING_RC=0 PATRONUS_GUARD_GW=192.0.2.1 '$G' arm && [ ! -e $W/calls ] && [ -f $W/run/patronus-good ]"
reset_g; touch "$W/gdata/.guard-auto"
t "guard: unattended mode reverts when the gateway is gone" sh -c "FAKE_PING_RC=1 PATRONUS_GUARD_GW=192.0.2.1 '$G' arm; grep -q 'flash openwrt' $W/calls"
reset_g; touch "$W/gdata/.guard-auto"
t "guard: unattended mode without a gateway configured reverts" sh -c "FAKE_PING_RC=0 PATRONUS_GUARD_GW= '$G' arm; grep -q 'flash openwrt' $W/calls"

# 5. fwtool metadata (sysupgrade -T refuses an image without it)
mkdir -p "$W/fw/sysupgrade-x"; echo k > "$W/fw/sysupgrade-x/kernel"; tar cf "$W/fw.tar" -C "$W/fw" sysupgrade-x
t "fwmeta: add + read back (supported_devices = board)" sh -c "python3 '$D/fwmeta.py' add '$W/fw.tar' glinet,gl-ar750s-nor-nand --version t1 && python3 '$D/fwmeta.py' show '$W/fw.tar' | grep -q '\"supported_devices\": \[\"glinet,gl-ar750s-nor-nand\"\]'"
tn "fwmeta: refuses to add twice" python3 "$D/fwmeta.py" add "$W/fw.tar" glinet,gl-ar750s-nor-nand
t "fwmeta: the tar is still a valid tar" tar tf "$W/fw.tar"
printf 'X' | dd of="$W/fw.tar" bs=1 seek=10 conv=notrunc 2>/dev/null
tn "fwmeta: a corrupted image fails the CRC" python3 "$D/fwmeta.py" show "$W/fw.tar"

# 6. nothing per-unit in the repo copy
t "no unit secrets/addresses in the tooling" sh -c "! grep -rIlE 'wpa_passphrase=[^c]|psk=\"|^STA_MAC=[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}' '$D' --exclude=run.sh --exclude='*.example'"

echo "slate tooling tests: $pass passed, $failn failed"
[ $failn -eq 0 ]
