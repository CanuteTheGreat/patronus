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
for f in usr/sbin/patronus-guard usr/sbin/patronus-flash usr/sbin/patronus-init usr/libexec/patronus/early etc/patronus-init etc/pam.d/patronus lib/security/pam_unix.so; do
  [ -e "$R/$f" ] || fail "missing /$f"; done
[ -n "${NOR_PROFILE:-}" ] || [ -e "$R/usr/share/patronus-recovery/openwrt-root.squashfs" ] || fail "missing the recovery root"
# the init system recorded for patronus-init must be in the image (busybox init is not a variant)
. "$R/etc/patronus-init" 2>/dev/null
case "${INIT:-}" in
  openrc)  [ -x "$R/sbin/openrc-init" ] && [ -x "$R/sbin/openrc-run" ] && [ -x "$R/sbin/supervise-daemon" ] || fail "OpenRC variant without openrc-init/openrc-run/supervise-daemon"
           for s in patronus-board patronus-apply patronus-applyd patronus-web dropbear dnsmasq patronus-dhcpc; do [ -x "$R/etc/init.d/$s" ] || fail "OpenRC variant: no /etc/init.d/$s"; done
           [ -x "$R/sbin/reboot" ] && grep -q openrc-shutdown "$R/sbin/reboot" || fail "OpenRC variant: /sbin/reboot must be openrc's (busybox reboot signals openrc-init to HALT)" ;;
  systemd) [ -x "$R/usr/lib/systemd/systemd" ] || fail "systemd variant without /usr/lib/systemd/systemd"
           for u in patronus-network patronus-apply patronus-applyd patronus-web patronus-dropbear; do [ -f "$R/etc/systemd/system/$u.service" ] || fail "systemd variant: no $u.service"; done ;;
  *) fail "/etc/patronus-init must say INIT=openrc or INIT=systemd (got '${INIT:-}')" ;;
esac
[ "$(readlink "$R/sbin/init")" = /usr/sbin/patronus-init ] || fail "/sbin/init must be /usr/sbin/patronus-init"
[ -e "$R/usr/share/patronus-recovery/openwrt-root.squashfs" ] && ! head -c4 "$R/usr/share/patronus-recovery/openwrt-root.squashfs" | grep hsqs >/dev/null && fail "recovery root is not a squashfs"
# every shared library an ELF in the image needs must be in it (o3: supervise-daemon needed libcap.so.2, so no
# supervised service started). Needs readelf (binutils); skipped without it.
if command -v readelf >/dev/null 2>&1; then
  miss=$(cd "$R" && find . -type f \( -perm -u+x -o -name '*.so*' \) -exec sh -c 'head -c4 "$1" | grep ELF >/dev/null && readelf -d "$1" 2>/dev/null' _ {} \; \
         | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p' | sort -u | while read -r l; do
           [ -e "$R/usr/lib/$l" ] || [ -e "$R/lib/$l" ] || [ -e "$R/usr/lib/openwrt/$l" ] || [ -e "$R/usr/lib/systemd/$l" ] || echo "$l"; done)
  [ -z "$miss" ] || fail "shared libraries needed but not in the image: $(echo $miss)"
fi
exit $bad
