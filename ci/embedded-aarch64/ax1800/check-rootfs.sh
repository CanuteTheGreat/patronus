#!/bin/sh
# check-rootfs.sh <root>: refuse an image that would boot into a box nobody can reach (each check = a failed real flash).
#  - root must log in with a shell that exists in the image and defer to shadow
#  - the early boot, the flash tool, the AP renderer, hostapd, the UBI tools and the Wi-Fi firmware must be there
#  - the init system recorded for patronus-init is OpenRC or systemd (busybox init is not a variant), with its units
#  - ETPhoneHome is baked in and enabled under both inits (owner rule)
#  - the AP role: no DHCP/DNS server is enabled, 802.11r is not in any shipped config
#  - Wi-Fi bring-up: calibration written to /run before the kmods, ath11k never unloaded
R=${1:?usage: check-rootfs.sh <root>}; bad=0
fail() { echo "check-rootfs: $*" >&2; bad=1; }
r=$(grep '^root:' "$R/etc/passwd" 2>/dev/null)
case "$r" in root:x:0:0:*) ;; *) fail "root passwd line must be root:x:0:0:... (got '${r%%:*}:${r#*:}' )";; esac
sh=${r##*:}
[ -n "$sh" ] && { [ -x "$R$sh" ] || [ -L "$R$sh" ]; } || fail "root shell '$sh' missing in the image"
grep -q '^root:[^:!*]' "$R/etc/shadow" 2>/dev/null || [ -s "$R/root/.ssh/authorized_keys" ] || fail "root has neither a password nor an authorized key"
grep -q '^nobody:' "$R/etc/passwd" || fail "no nobody user"
[ -s "$R/etc/services" ] || fail "no /etc/services (busybox wget/nc: bad port 'http')"
for f in usr/sbin/patronus-flash usr/libexec/patronus/fwcheck.sh usr/libexec/patronus/upgrade-install usr/libexec/patronus/ubi-data usr/sbin/patronus-init usr/libexec/patronus/early usr/libexec/patronus/ath11k-caldata usr/libexec/patronus/ap \
         usr/libexec/patronus/ap-guest usr/libexec/patronus/ap-coord usr/libexec/patronus/ap-steer usr/libexec/patronus/ap-chan usr/libexec/patronus/ap-addr usr/libexec/patronus/leds usr/libexec/patronus/restart-schedule \
         usr/libexec/patronus/scheduled-restart usr/libexec/patronus/board-network etc/patronus/board.sh etc/patronus-init etc/pam.d/patronus \
         usr/sbin/hostapd usr/sbin/dropbear usr/bin/patronus-cli usr/bin/patronus-web \
         usr/sbin/patronus-guard usr/bin/fw_printenv usr/bin/fw_setenv etc/patronus/boot-guard.board etc/patronus/boot-guard.conf usr/sbin/ubimkvol \
         lib/firmware/ath11k/IPQ6018/hw1.0/board-2.bin lib/firmware/IPQ6018/q6_fw.mdt lib/firmware/IPQ6018/m3_fw.mdt lib/firmware/regulatory.db; do
  [ -e "$R/$f" ] || [ -L "$R/$f" ] || fail "missing /$f"; done
# hostapd must be the Patronus build (synchronous cross-BSS station removal): Alpine's stock one lets one MAC be a peer
# on two BSSes of a radio and the IPQ6018 firmware asserts and restarts the unit (docs 12.6d)
grep -a 'patronus-xbss' "$R/usr/sbin/hostapd" >/dev/null 2>&1 || fail "hostapd is not the Patronus build (no patronus-xbss): stock hostapd crashes the IPQ6018 firmware when a client moves between SSIDs"
# ... and the build with the authentication-failure backoff (docs 12.18): `ap` renders patronus_authfail_* lines, which an
# older Patronus hostapd refuses (no radio would start)
grep -a 'patronus_authfail_max' "$R/usr/sbin/hostapd" >/dev/null 2>&1 || fail "hostapd has no patronus_authfail_* settings (built before the authentication backoff): the rendered radio configs would be refused"
# `ap` starts these only when executable: a 0644 helper is skipped silently (no channel plan, no steering)
for f in ap ap-coord ap-steer ap-chan ap-event ap-guest wifi-guard; do [ -x "$R/usr/libexec/patronus/$f" ] || fail "/usr/libexec/patronus/$f is not executable (ap skips it silently)"; done
[ -e "$R/usr/lib/security/pam_unix.so" ] || [ -e "$R/lib/security/pam_unix.so" ] || fail "missing pam_unix.so (web UI login)"
# gpgv: release signatures (update feed, images); ssl_client: busybox wget over https (online firmware check)
for t in ubinfo ubimkvol ubirmvol ubirsvol ubiupdatevol ubiblock iw ip sha256sum pivot_root gpgv ssl_client; do
  found=; for d in bin sbin usr/bin usr/sbin; do [ -e "$R/$d/$t" ] || [ -L "$R/$d/$t" ] && found=1; done
  [ -n "$found" ] || fail "no $t in the image"; done
KV=$(ls "$R/lib/modules" 2>/dev/null | head -1)
[ -n "$KV" ] && [ -s "$R/lib/modules/$KV/modules.dep" ] || fail "no kernel modules / modules.dep"
for m in ath11k_ahb qca-nss-dp qca-ssdk mac80211 cfg80211 nf_tables nfnetlink_log nft_reject_inet nf_conntrack; do [ -e "$R/lib/modules/$KV/$m.ko" ] || fail "kernel module $m.ko missing (no Ethernet/Wi-Fi/firewall without it)"; done
# Wi-Fi queueing (docs 12.20): ath11k must be the rebuilt one with airtime queue limits + fairness (wifi-kmods/), unless the
# build asked for OpenWrt's stock modules (WIFI_KMODS=stock: seconds of delay behind a slow 2.4 GHz station's download)
if [ "${WIFI_KMODS:-patched}" != stock ]; then
  [ -s "$R/usr/share/patronus/wifi-kmods.manifest" ] || fail "wifi-kmods: no manifest (wifi-kmods/fetch.sh did not run)"
  grep -a 'Pending Tx MSDUs' "$R/lib/modules/$KV/ath11k.ko" >/dev/null 2>&1 || fail "wifi-kmods: ath11k.ko is OpenWrt's stock module (no airtime queue limits)"
fi
# features of the patronus-cli build (FEATURES= in /etc/patronus-release, from stage-patronus.sh): each one's runtime pieces
FEAT=$(sed -n 's/^FEATURES=//p' "$R/etc/patronus-release" 2>/dev/null)
[ -n "$FEAT" ] || fail "/etc/patronus-release has no FEATURES= line (which pages the web UI has)"
has_feature() { case ",$FEAT," in *",$1,"*) return 0;; esac; return 1; }
if has_feature wifi-ap; then
  for m in nft_meta_bridge nf_conntrack_bridge; do [ -e "$R/lib/modules/$KV/$m.ko" ] || fail "wifi-ap: kernel module $m.ko missing (kmods.pin kmod-nft-bridge; guest networks need it)"; done
fi
if has_feature vpn-wireguard; then
  [ -x "$R/usr/bin/wg" ] || fail "vpn-wireguard: no /usr/bin/wg (wireguard-tools-wg): every tunnel would fail at wg syncconf"
  [ -e "$R/lib/modules/$KV/wireguard.ko" ] || fail "vpn-wireguard: kernel module wireguard.ko missing (kmods.pin)"
  grep -qsx wireguard "$R"/etc/modules.d/* || fail "vpn-wireguard: wireguard.ko is not loaded at boot (no /etc/modules.d line)"
fi
if has_feature syslog; then
  [ -x "$R/usr/libexec/patronus/syslogd" ] || fail "syslog: no /usr/libexec/patronus/syslogd (the Syslog page's busybox backend: remote collectors -> syslogd -R)"
  grep -q /usr/libexec/patronus/syslogd "$R/etc/init.d/patronus-syslogd" "$R/etc/systemd/system/patronus-syslogd.service" 2>/dev/null || fail "syslog: patronus-syslogd does not run the launcher (remote collectors would be ignored)"
fi
# /dev comes from mdev (no devtmpfs in these kernels): without mdev.conf /dev/null and /dev/urandom are root-only
grep -qE '^urandom[[:space:]]+0:0[[:space:]]+666' "$R/etc/mdev.conf" 2>/dev/null && grep -qE '^null[[:space:]]+0:0[[:space:]]+666' "$R/etc/mdev.conf" \
  || fail "/etc/mdev.conf must make /dev/null and /dev/urandom 0666 (daemons that drop root cannot open them otherwise)"
# the clock (no RTC) and the NTP server page (ntp-server) are one daemon: chrony, run as its own user, service chronyd
[ -x "$R/usr/sbin/chronyd" ] || fail "no /usr/sbin/chronyd (the box would never get the time)"
grep -q '^chrony:' "$R/etc/passwd" && grep -q '^chrony:' "$R/etc/group" || fail "no chrony user/group (chronyd drops root to it)"
[ -s "$R/etc/chrony/chrony.conf" ] || fail "no /etc/chrony/chrony.conf"
grep -q 'driftfile /var/lib/chrony/drift' "$R/etc/chrony/chrony.conf" 2>/dev/null || fail "chrony.conf must keep its drift file in /var/lib/chrony (data volume): chronyd -s starts the clock from it"
[ -e "$R/bin/ntpd" ] || [ -L "$R/bin/ntpd" ] && fail "busybox ntpd is linked: chrony is the one NTP daemon"
. "$R/etc/patronus-init" 2>/dev/null
case "${INIT:-}" in
  openrc)  [ -x "$R/sbin/openrc-init" ] && [ -x "$R/sbin/openrc-run" ] && [ -x "$R/sbin/supervise-daemon" ] || fail "OpenRC variant without openrc-init/openrc-run/supervise-daemon"
           for s in patronus-board patronus-apply patronus-applyd patronus-web dropbear patronus-etph chronyd patronus-crond; do [ -x "$R/etc/init.d/$s" ] || fail "OpenRC variant: no /etc/init.d/$s"; done
           [ -x "$R/sbin/reboot" ] && grep -q openrc-shutdown "$R/sbin/reboot" || fail "OpenRC variant: /sbin/reboot must be openrc's (busybox reboot signals openrc-init to HALT)" ;;
  systemd) [ -x "$R/usr/lib/systemd/systemd" ] || fail "systemd variant without /usr/lib/systemd/systemd"
           [ -e "$R/usr/lib/libmount.so.1" ] || [ -e "$R/lib/libmount.so.1" ] || fail "systemd variant without libmount.so.1 (dlopen()ed by PID 1: it freezes without it)"
           for u in patronus-network patronus-apply patronus-applyd patronus-web patronus-dropbear patronus-etph chronyd patronus-restart; do [ -f "$R/etc/systemd/system/$u.service" ] || fail "systemd variant: no $u.service"; done ;;
  *) fail "/etc/patronus-init must say INIT=openrc or INIT=systemd (got '${INIT:-}')" ;;
esac
[ "$(readlink "$R/sbin/init")" = /usr/sbin/patronus-init ] || fail "/sbin/init must be /usr/sbin/patronus-init"
# Wi-Fi bring-up: calibration goes to a writable tmpfs before the kmods load; never unload ath11k (it crashes the board)
grep -q 'CALDATA_OUT:-/run/' "$R/usr/libexec/patronus/ath11k-caldata" 2>/dev/null || fail "ath11k-caldata must write to /run (the root is read-only)"
grep -q 'firmware_class/parameters/path' "$R/usr/libexec/patronus/early" 2>/dev/null || fail "early boot does not point firmware_class.path at the calibration dir"
grep -qE '^[^#]*rmmod[^#]*ath11k' "$R/usr/libexec/patronus/early" 2>/dev/null && fail "early boot unloads ath11k (crashes the board)"
# ETPhoneHome
# release signature checks of upgrade images (fwcheck.sh): gpgv + the release keyring must be on every image
[ -x "$R/usr/bin/gpgv" ] || [ -x "$R/bin/gpgv" ] || fail "gpgv missing: patronus-flash could not check release signatures (every upgrade would be refused)"
[ -s "$R/usr/share/openpgp-keys/errantsolutions.gpg" ] || fail "release keyring /usr/share/openpgp-keys/errantsolutions.gpg missing"
[ -x "$R/usr/sbin/etphonehome" ] && head -c4 "$R/usr/sbin/etphonehome" | grep ELF >/dev/null || fail "ETPhoneHome: no /usr/sbin/etphonehome ELF binary"
[ -x "$R/usr/libexec/patronus/etph-run" ] || fail "ETPhoneHome: no /usr/libexec/patronus/etph-run"
case "${INIT:-}" in
  openrc)  [ -x "$R/etc/init.d/patronus-etph" ] && [ -L "$R/etc/runlevels/default/patronus-etph" ] || fail "ETPhoneHome: OpenRC service patronus-etph missing or not in the default runlevel" ;;
  systemd) [ -f "$R/etc/systemd/system/patronus-etph.service" ] && [ -L "$R/etc/systemd/system/multi-user.target.wants/patronus-etph.service" ] || fail "ETPhoneHome: patronus-etph.service missing or not enabled" ;;
esac
# AP role: no DHCP/DNS server enabled; no 802.11r in anything shipped
for s in dnsmasq patronus-dhcpd patronus-dnsd; do
  { [ -e "$R/etc/runlevels/default/$s" ] || [ -L "$R/etc/runlevels/default/$s" ]; } && fail "AP role: $s is enabled in the default runlevel"
  { [ -e "$R/etc/systemd/system/multi-user.target.wants/$s.service" ] || [ -L "$R/etc/systemd/system/multi-user.target.wants/$s.service" ]; } && fail "AP role: $s.service is enabled"; done
. "$R/etc/patronus/board.sh" 2>/dev/null
[ "${ROLE:-}" = ap ] || fail "board.sh must set ROLE=ap"
grep -qx 'PATRONUS_DEVICE_ROLE=ap' "$R/etc/patronus/embedded.env" || fail "embedded.env must set PATRONUS_DEVICE_ROLE=ap (board.sh ROLE=ap): the web UI would offer the router wizard"
[ -x "$R/usr/libexec/patronus/accounts-sync" ] || fail "missing /usr/libexec/patronus/accounts-sync (package-managed accounts)"
if [ -d "$R/usr/share/patronus/accounts.d" ]; then
  grep accounts-sync "$R/usr/libexec/patronus/early" >/dev/null || fail "early boot never runs accounts-sync"
  for a in "$R"/usr/share/patronus/accounts.d/*/; do [ -s "$a/passwd" ] || fail "account ${a%/}: no passwd line"; done
fi
grep -qx 'PATRONUS_AUTH_BACKEND=shadow' "$R/etc/patronus/embedded.env" || fail "embedded.env must set PATRONUS_AUTH_BACKEND=shadow: pam_unix on musl cannot verify yescrypt hashes copied from Gentoo/Horcrux hosts"
[ "${AP_FT:-0}" = 0 ] || fail "board.sh: AP_FT must default to 0 (802.11r crashes ath11k firmware)"
if [ -f "$R/etc/patronus/ap.env" ]; then
  grep -qE '^[[:space:]]*AP_FT=1' "$R/etc/patronus/ap.env" && fail "ap.env enables 802.11r (AP_FT=1)"
  . "$R/etc/patronus/ap.env"; n=0; for s in $AP_SSIDS; do n=$((n+1)); done
  [ "$n" -ge 1 ] || fail "ap.env: no AP_SSIDS (Wi-Fi would stay off)"
fi
grep -rIlE '^[[:space:]]*ieee80211r=1' "$R/etc" 2>/dev/null | grep . >/dev/null && fail "a shipped hostapd config enables ieee80211r"
# every shared library an ELF in the image needs must be in it. Needs readelf (binutils); skipped without it.
if command -v readelf >/dev/null 2>&1; then
  miss=$(cd "$R" && find . -type f \( -perm -u+x -o -name '*.so*' \) -exec sh -c 'head -c4 "$1" | grep ELF >/dev/null && readelf -d "$1" 2>/dev/null' _ {} \; \
         | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p' | sort -u | while read -r l; do
           [ -e "$R/usr/lib/$l" ] || [ -e "$R/lib/$l" ] || [ -e "$R/usr/lib/systemd/$l" ] || echo "$l"; done)
  [ -z "$miss" ] || fail "shared libraries needed but not in the image: $(echo $miss)"
fi
exit $bad
