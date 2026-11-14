#!/bin/sh
# check-rootfs.sh <root>: refuse an image that would boot into a box nobody can reach (each check = a failed real flash).
#  - wpa_supplicant is built with CONFIG_NO_CONFIG_WRITE: `update_config` is a parse error, the uplink never comes up (p1)
#  - root must log in with a shell that exists in the image and defer to shadow (Gentoo ships root:!:...:/bin/bash, p2)
#  - dnsmasq needs the nobody user and /var/lib/misc; patronus-guard and patronus-flash must be there (the way back)
R=${1:?usage: check-rootfs.sh <root>}; bad=0
fail() { echo "check-rootfs: $*" >&2; bad=1; }
W=$R/etc/wpa_supplicant/wpa_supplicant.conf
[ -f "$W" ] || fail "no $W (the Wi-Fi uplink)"
[ -f "$W" ] && grep -q '^[[:space:]]*update_config' "$W" && fail "wpa_supplicant.conf: drop update_config (CONFIG_NO_CONFIG_WRITE build)"
r=$(grep '^root:' "$R/etc/passwd" 2>/dev/null)
case "$r" in root:x:0:0:*) ;; *) fail "root passwd line must be root:x:0:0:... (got '${r%%:*}:${r#*:}' )";; esac
sh=${r##*:}
[ -n "$sh" ] && { [ -x "$R$sh" ] || [ -L "$R$sh" ]; } || fail "root shell '$sh' missing in the image"
grep -q '^root:[^:!*]' "$R/etc/shadow" 2>/dev/null || [ -s "$R/root/.ssh/authorized_keys" ] || fail "root has neither a password nor an authorized key"
grep -q '^nobody:' "$R/etc/passwd" || fail "no nobody user (dnsmasq)"
[ -d "$R/var/lib/misc" ] || fail "no /var/lib/misc (dnsmasq leases)"
[ -s "$R/etc/services" ] || fail "no /etc/services (busybox wget/nc: bad port 'http', p4)"
for f in usr/sbin/patronus-guard usr/sbin/patronus-flash usr/share/patronus-recovery/openwrt-root.squashfs etc/init.d/rcS; do
  [ -e "$R/$f" ] || fail "missing /$f"; done
[ -e "$R/usr/share/patronus-recovery/openwrt-root.squashfs" ] && ! head -c4 "$R/usr/share/patronus-recovery/openwrt-root.squashfs" | grep -q hsqs && fail "recovery root is not a squashfs"
exit $bad
