#!/bin/sh
# Host tests for the GL-AX1800 image tooling (no router, no root): `sh ci/embedded-aarch64/ax1800/tests/run.sh`.
# Needs python3; mksquashfs/unsquashfs and ubinize for the image-format cases (the builder image has them; skipped without).
#  - every script parses; OpenRC <-> systemd service parity; no udev units shipped in the systemd overlay
#  - check-rootfs.sh accepts a good root and rejects the mistakes it exists for (busybox init, no ETPhoneHome, 802.11r)
#  - the AP renderer never writes 802.11r unless asked; explicit unique BSSIDs; 5 GHz centre channels; caldata path
#  - patronus-flash check/sysupgrade and upgrade-install verify against a fake UBI: every guard fails closed, incl. the release
#    signature (unsigned, foreign key, tampered root with a re-made patronus.sha256): needs gpg + gpgv, the cases fail without them
#  - ubi-layout.py / nand-budget.sh on ubinize-made images; profile values agree with stock.pin
set -u
D=$(cd "$(dirname "$0")/.." && pwd); ROOT=$(cd "$D/../../.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/ax1800-tests.XXXX"); trap 'rm -rf "$W"' EXIT
pass=0; failn=0; skip=0
ok() { echo "PASS: $*"; pass=$((pass+1)); }
no() { echo "FAIL: $*"; failn=$((failn+1)); }
sk() { echo "SKIP: $*"; skip=$((skip+1)); }
t() { name=$1; shift; if "$@" >"$W/out" 2>&1; then ok "$name"; else no "$name"; sed 's/^/    /' "$W/out"; fi; }
tn() { name=$1; shift; if "$@" >"$W/out" 2>&1; then no "$name (expected failure)"; sed 's/^/    /' "$W/out"; else ok "$name"; fi; }
# tn_msg NAME PATTERN cmd...: must fail AND say why
tn_msg() { name=$1; pat=$2; shift 2; if "$@" >"$W/out" 2>&1; then no "$name (expected failure)"; sed 's/^/    /' "$W/out";
  elif grep -q "$pat" "$W/out"; then ok "$name"; else no "$name (failed without '$pat')"; sed 's/^/    /' "$W/out"; fi; }
O=$D/overlay

# 1. syntax + parity
for f in "$D"/*.sh "$O"/usr/libexec/patronus/* "$O"/usr/sbin/* "$O"/etc/patronus/board.sh "$O"/usr/share/udhcpc/default.script; do
  case "$(head -1 "$f")" in *bash*) t "bash -n ${f#$D/}" bash -n "$f";; *) t "sh -n ${f#$D/}" sh -n "$f";; esac
done
for f in "$D"/*.py; do t "py_compile ${f#$D/}" python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f"; done
for f in "$D"/overlay-openrc/etc/init.d/*; do t "openrc-run shebang ${f#$D/}" grep -q '^#!/sbin/openrc-run' "$f"; done
for p in patronus-board:patronus-network patronus-etph:patronus-etph patronus-apply:patronus-apply patronus-applyd:patronus-applyd \
         patronus-web:patronus-web dropbear:patronus-dropbear chronyd:chronyd patronus-syslogd:patronus-syslogd patronus-klogd:patronus-klogd; do
  t "parity ${p%%:*} (OpenRC) = ${p#*:}.service (systemd)" sh -c "[ -x '$D/overlay-openrc/etc/init.d/${p%%:*}' ] && [ -L '$D/overlay-systemd/etc/systemd/system/multi-user.target.wants/${p#*:}.service' ] && [ -f '$D/overlay-systemd/etc/systemd/system/${p#*:}.service' ]"
done
n=$(ls "$D/overlay-systemd/etc/systemd/system" | grep -c 'udev\|hwdb')
[ "$n" = 0 ] && ok "systemd overlay ships no udev/hwdb units (devtmpfs board; assemble.sh drops them)" || no "systemd overlay still has $n udev/hwdb units"
bad=$(find "$D/overlay-systemd/etc/systemd/system" -maxdepth 1 -type f -size 0)
[ -z "$bad" ] && ok "systemd masks are /dev/null links, not empty unit files" || no "empty unit files (not masks): $bad"

# 1c. every command the flash guard / installer runs on the box exists there: a busybox applet (busybox-applets.txt) or a
#     packaged tool (mtd-utils UBI tools); od was missing once and the guard refused every image on the QEMU gate
for c in od tail head tr cut mktemp sha256sum wc cmp date logger mknod pivot_root sed grep sleep tar dd mount umount cat ls \
         basename mv rm cp sync mkdir rmdir uname reboot base64 chmod printf; do
  grep -qx "$c" "$D/busybox-applets.txt" && ok "busybox applet for $c (flash guard/installer)" || no "no busybox applet for $c (used on the box by fwcheck.sh/upgrade-install)"; done

# 2. check-rootfs.sh
mkroot() { r=$W/root-$1; rm -rf "$r"; mkdir -p "$r/bin" "$r/sbin" "$r/usr/bin" "$r/usr/sbin" "$r/root/.ssh" "$r/etc/init.d" "$r/etc/runlevels/default" \
    "$r/usr/libexec/patronus" "$r/etc/pam.d" "$r/lib/security" "$r/etc/patronus" "$r/lib/firmware/ath11k/IPQ6018/hw1.0" "$r/lib/firmware/IPQ6018" "$r/lib/modules/6.12.112"
  printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\nchrony:x:980:980:chrony:/var/lib/chrony:/bin/false\n' > "$r/etc/passwd"; echo 'chrony:x:980:' > "$r/etc/group"; echo 'root:!:1::::::' > "$r/etc/shadow"
  echo "ssh-ed25519 AAAA test" > "$r/root/.ssh/authorized_keys"; echo "http 80/tcp" > "$r/etc/services"
  : > "$r/bin/busybox"; chmod +x "$r/bin/busybox"; ln -s busybox "$r/bin/sh"
  for f in usr/sbin/patronus-flash usr/libexec/patronus/fwcheck.sh usr/libexec/patronus/upgrade-install usr/libexec/patronus/ubi-data usr/sbin/patronus-init usr/libexec/patronus/early \
           usr/libexec/patronus/ath11k-caldata usr/libexec/patronus/ap usr/libexec/patronus/board-network etc/pam.d/patronus lib/security/pam_unix.so \
           usr/sbin/hostapd usr/sbin/dropbear usr/bin/patronus-cli lib/firmware/ath11k/IPQ6018/hw1.0/board-2.bin lib/firmware/IPQ6018/q6_fw.mdt \
           lib/firmware/IPQ6018/m3_fw.mdt lib/firmware/regulatory.db usr/libexec/patronus/etph-run usr/libexec/patronus/ap-guest usr/libexec/patronus/ap-addr \
           usr/libexec/patronus/leds usr/libexec/patronus/restart-schedule usr/libexec/patronus/scheduled-restart usr/bin/gpgv usr/bin/ssl_client usr/libexec/patronus/accounts-sync; do : > "$r/$f"; chmod +x "$r/$f"; done
  ln -s patronus-cli "$r/usr/bin/patronus-web"; cp "$O/etc/patronus/board.sh" "$O/etc/patronus/embedded.env" "$r/etc/patronus/"
  cp "$O/usr/libexec/patronus/early" "$O/usr/libexec/patronus/ath11k-caldata" "$r/usr/libexec/patronus/"
  for b in ubinfo ubimkvol ubirmvol ubirsvol ubiupdatevol ubiblock iw ip sha256sum pivot_root; do ln -s /bin/busybox "$r/usr/sbin/$b"; done
  echo x > "$r/lib/modules/6.12.112/modules.dep"; for m in ath11k_ahb qca-nss-dp qca-ssdk mac80211 cfg80211 nf_tables nfnetlink_log nft_reject_inet nf_conntrack; do : > "$r/lib/modules/6.12.112/$m.ko"; done
  echo patronus-xbss > "$r/usr/sbin/hostapd"
  printf '\177ELF' > "$r/usr/sbin/etphonehome"; chmod +x "$r/usr/sbin/etphonehome"
  echo INIT=openrc > "$r/etc/patronus-init"; echo FEATURES=nftables,cli,wifi-ap,web-multicall,vpn-wireguard,ntp-server,syslog > "$r/etc/patronus-release"
  : > "$r/lib/modules/6.12.112/wireguard.ko"; : > "$r/lib/modules/6.12.112/nft_meta_bridge.ko"; : > "$r/lib/modules/6.12.112/nf_conntrack_bridge.ko"; mkdir -p "$r/etc/modules.d" "$r/etc/chrony"; echo wireguard > "$r/etc/modules.d/wireguard"
  for b in usr/bin/wg usr/sbin/chronyd usr/libexec/patronus/syslogd; do : > "$r/$b"; chmod +x "$r/$b"; done; cp "$O/etc/chrony/chrony.conf" "$r/etc/chrony/"; ln -s /usr/sbin/patronus-init "$r/sbin/init"
  mkdir -p "$r/usr/share/openpgp-keys"; echo k > "$r/usr/share/openpgp-keys/errantsolutions.gpg"; : > "$r/usr/bin/gpgv"; chmod +x "$r/usr/bin/gpgv"
  for b in openrc-init openrc-run supervise-daemon; do : > "$r/sbin/$b"; chmod +x "$r/sbin/$b"; done
  printf '#!/bin/sh\nexec /sbin/openrc-shutdown -r now "$@"\n' > "$r/sbin/reboot"; chmod +x "$r/sbin/reboot"
  for s in patronus-board patronus-apply patronus-applyd patronus-web dropbear patronus-etph chronyd patronus-crond; do : > "$r/etc/init.d/$s"; chmod +x "$r/etc/init.d/$s"; done
  cp "$D/overlay-openrc/etc/init.d/patronus-syslogd" "$r/etc/init.d/"; cp "$O/etc/mdev.conf" "$r/etc/"
  ln -s /etc/init.d/patronus-etph "$r/etc/runlevels/default/patronus-etph"; echo "$r"; }
CR="env PATH=/usr/bin:/bin:/usr/sbin:/sbin sh $D/check-rootfs.sh"   # readelf check runs only where binutils exist; fake roots have no ELFs
t "check-rootfs: good OpenRC root" $CR "$(mkroot good)"
r=$(mkroot bbinit); echo INIT=busybox > "$r/etc/patronus-init"; tn "check-rootfs: rejects busybox init (not a variant)" $CR "$r"
r=$(mkroot noetph); rm "$r/etc/runlevels/default/patronus-etph"; tn "check-rootfs: rejects ETPhoneHome not enabled" $CR "$r"
r=$(mkroot noetphbin); rm "$r/usr/sbin/etphonehome"; tn "check-rootfs: rejects a missing ETPhoneHome binary" $CR "$r"
r=$(mkroot ft); printf 'AP_SSIDS=m\nSSID_m=x KEY_m=yyyyyyyy\nAP_FT=1\n' > "$r/etc/patronus/ap.env"; tn "check-rootfs: rejects ap.env with 802.11r" $CR "$r"
r=$(mkroot dhcp); : > "$r/etc/init.d/dnsmasq"; ln -s /etc/init.d/dnsmasq "$r/etc/runlevels/default/dnsmasq"; tn "check-rootfs: rejects a DHCP server on the AP" $CR "$r"
r=$(mkroot rocal); sed -i 's#CALDATA_OUT:-/run/#CALDATA_OUT:-/lib/#' "$r/usr/libexec/patronus/ath11k-caldata"; tn "check-rootfs: rejects caldata written to the read-only root" $CR "$r"
r=$(mkroot rmmod); echo 'rmmod ath11k_ahb' >> "$r/usr/libexec/patronus/early"; tn "check-rootfs: rejects an early boot that unloads ath11k" $CR "$r"
r=$(mkroot noupg); rm "$r/usr/libexec/patronus/upgrade-install"; tn "check-rootfs: rejects an image without the upgrade installer" $CR "$r"
r=$(mkroot nogpgv); rm "$r/usr/bin/gpgv"; tn "check-rootfs: rejects an image without gpgv (release signatures could not be checked)" $CR "$r"
r=$(mkroot nokey); rm "$r/usr/share/openpgp-keys/errantsolutions.gpg"; tn "check-rootfs: rejects an image without the release keyring" $CR "$r"
r=$(mkroot norole); sed -i '/^PATRONUS_DEVICE_ROLE=/d' "$r/etc/patronus/embedded.env"; tn "check-rootfs: rejects an AP image whose web UI does not know it is an AP" $CR "$r"
r=$(mkroot noauth); sed -i '/^PATRONUS_AUTH_BACKEND=/d' "$r/etc/patronus/embedded.env"; tn "check-rootfs: rejects an image whose web login would go through musl pam_unix (no yescrypt)" $CR "$r"
r=$(mkroot noacc); rm "$r/usr/libexec/patronus/accounts-sync"; tn "check-rootfs: rejects an image without accounts-sync" $CR "$r"
r=$(mkroot accnoearly); mkdir -p "$r/usr/share/patronus/accounts.d/u"; echo "u:x:1:1::/h:/bin/sh" > "$r/usr/share/patronus/accounts.d/u/passwd"; sed -i "/accounts-sync/d" "$r/usr/libexec/patronus/early"; tn "check-rootfs: rejects accounts that early boot never applies" $CR "$r"
r=$(mkroot nowg); rm "$r/usr/bin/wg"; tn_msg "check-rootfs: vpn-wireguard build without wg is refused" 'no /usr/bin/wg' $CR "$r"
r=$(mkroot nowgko); rm "$r/lib/modules/6.12.112/wireguard.ko"; tn_msg "check-rootfs: vpn-wireguard build without wireguard.ko is refused" 'wireguard.ko missing' $CR "$r"
r=$(mkroot nowgload); rm "$r/etc/modules.d/wireguard"; tn_msg "check-rootfs: vpn-wireguard build that does not load the module at boot is refused" 'not loaded at boot' $CR "$r"
r=$(mkroot nobrko); rm "$r/lib/modules/6.12.112/nft_meta_bridge.ko"; tn_msg "check-rootfs: a wifi-ap build without the nftables bridge modules is refused" 'nft_meta_bridge.ko missing' $CR "$r"
r=$(mkroot wgoff); rm "$r/usr/bin/wg" "$r/lib/modules/6.12.112/wireguard.ko"; echo FEATURES=nftables,cli,web-multicall > "$r/etc/patronus-release"; t "check-rootfs: a build without vpn-wireguard needs no wg" $CR "$r"
r=$(mkroot nochrony); rm "$r/usr/sbin/chronyd"; tn_msg "check-rootfs: rejects an image without chronyd (no clock)" 'no /usr/sbin/chronyd' $CR "$r"
r=$(mkroot nochronyuser); sed -i '/^chrony:/d' "$r/etc/passwd"; tn_msg "check-rootfs: rejects an image without the chrony user" 'no chrony user' $CR "$r"
r=$(mkroot bbntpd); ln -s /bin/busybox "$r/bin/ntpd"; tn_msg "check-rootfs: rejects a second NTP daemon (busybox ntpd)" 'busybox ntpd is linked' $CR "$r"
r=$(mkroot nochronysvc); rm "$r/etc/init.d/chronyd"; tn_msg "check-rootfs: rejects an OpenRC image without the chronyd service" 'no /etc/init.d/chronyd' $CR "$r"
r=$(mkroot nosyslogd); rm "$r/usr/libexec/patronus/syslogd"; tn_msg "check-rootfs: syslog build without the syslogd launcher is refused" 'no /usr/libexec/patronus/syslogd' $CR "$r"
r=$(mkroot syslogbare); echo 'command=/bin/syslogd' > "$r/etc/init.d/patronus-syslogd"; tn_msg "check-rootfs: syslog build whose logger ignores the collectors is refused" 'does not run the launcher' $CR "$r"
r=$(mkroot nomdev); rm "$r/etc/mdev.conf"; tn_msg "check-rootfs: rejects an image whose /dev/null and /dev/urandom would be root-only" 'mdev.conf' $CR "$r"
r=$(mkroot stockhostapd); : > "$r/usr/sbin/hostapd"; tn_msg "check-rootfs: rejects stock hostapd (no synchronous cross-BSS removal)" 'not the Patronus build' $CR "$r"
r=$(mkroot nofeat); : > "$r/etc/patronus-release"; tn_msg "check-rootfs: rejects an image that does not record its features" 'no FEATURES= line' $CR "$r"

# 3. AP renderer (the real script, `ap render`, against a fake sysfs). The fake radios have the board's MAC shape: the
#    5 GHz phy MAC is odd and the 2.4 GHz phy MAC is the 5 GHz one - 1 (hostapd's automatic addressing broke on both).
A=$W/ap; mkdir -p "$A/sys/phy0" "$A/sys/phy1"; echo 94:00:5e:10:20:d7 > "$A/sys/phy0/macaddress"; echo 94:00:5e:10:20:d6 > "$A/sys/phy1/macaddress"
# aprender NAME 'ap.env lines': renders into $A/NAME (ap5.conf, ap24.conf)
aprender() { printf '. %s\n%s\n' "$O/etc/patronus/board.sh" "$2" > "$A/board-$1.sh"; rm -rf "$A/$1"
  AP_BOARD=$A/board-$1.sh AP_RENDER_OUT=$A/$1 AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render >"$A/$1.out" 2>&1; }
TWO='AP_SSIDS="m g"
SSID_m=Example KEY_m=examplekey SEC_m=wpa2+3
SSID_g=Guest KEY_g=guestkey99'
aprender ft0 "AP_SSIDS=m
SSID_m=Example KEY_m=examplekey SEC_m=wpa2+3"
if [ -s "$A/ft0/ap5.conf" ] && ! grep -q ieee80211r "$A/ft0/ap5.conf"; then ok "ap: no 802.11r by default"; else no "ap: 802.11r rendered by default (or render failed)"; cat "$A/ft0.out"; fi
aprender ft1 "AP_FT=1 AP_SSIDS=m
SSID_m=Example KEY_m=examplekey"
grep -q '^ieee80211r=1' "$A/ft1/ap5.conf" 2>/dev/null && ok "ap: 802.11r only when AP_FT=1" || no "ap: AP_FT=1 did not render 802.11r"
# BSSIDs: one per BSS, explicit, unique across both radios, first BSS = the radio's MAC, the rest locally administered
aprender two "$TWO
AP_CHAN5=149 AP_CHAN24=6"
b5=$(sed -n 's/^bssid=//p' "$A/two/ap5.conf" 2>/dev/null); b24=$(sed -n 's/^bssid=//p' "$A/two/ap24.conf" 2>/dev/null)
[ "$(echo "$b5" | wc -l)" = 2 ] && [ "$(echo "$b24" | wc -l)" = 2 ] && [ "$(grep -c '^ssid=' "$A/two/ap5.conf")" = 2 ] \
  && ok "ap: every BSS on both radios has an explicit bssid= (2 SSIDs x 2 bands)" || { no "ap: bssid lines missing: 5=[$b5] 24=[$b24]"; cat "$A/two.out"; }
all="$b5
$b24"
[ "$(echo "$all" | sort -u | wc -l)" = 4 ] && ok "ap: the four BSSIDs are unique across radios" || no "ap: duplicate BSSIDs: $(echo $all)"
[ "$(echo "$b5" | head -1)" = 94:00:5e:10:20:d7 ] && [ "$(echo "$b24" | head -1)" = 94:00:5e:10:20:d6 ] && ok "ap: first BSS of each radio = the radio's own MAC" \
  || no "ap: first BSSIDs are not the phy MACs: $(echo $all)"
la=1; for x in $(echo "$b5" | sed 1d) $(echo "$b24" | sed 1d); do [ $(( 0x${x%%:*} & 2 )) = 2 ] || la=0; [ "${x#*:}" = 00:5e:10:20:d7 ] || [ "${x#*:}" = 00:5e:10:20:d6 ] || la=0; done
[ $la = 1 ] && ok "ap: further BSSIDs are locally administered variants of their radio's MAC" || no "ap: further BSSIDs not LA variants: $(echo $all)"
# hostapd's own rule for the old (automatic) case must no longer apply: no BSS may sit on the other radio's MAC
case " $(echo $b24) " in *" 94:00:5e:10:20:d7 "*) no "ap: a 2.4 GHz BSS uses the 5 GHz radio's MAC";; *) ok "ap: no 2.4 GHz BSS on the 5 GHz radio's MAC";; esac
# three SSIDs: still unique
aprender three "AP_SSIDS=\"a b c\"
SSID_a=A KEY_a=aaaaaaaa
SSID_b=B KEY_b=bbbbbbbb
SSID_c=C KEY_c=cccccccc"
n=$(cat "$A/three/ap5.conf" "$A/three/ap24.conf" 2>/dev/null | sed -n 's/^bssid=//p' | sort -u | wc -l)
[ "$n" = 6 ] && ok "ap: 3 SSIDs -> 6 unique BSSIDs" || no "ap: 3 SSIDs gave $n unique BSSIDs"
# 5 GHz channel plan: fixed channel at 80 MHz writes the centre channel and the HT40 direction; auto leaves them out
seg() { sed -n "s/^$2=//p" "$A/$1/ap5.conf" 2>/dev/null | head -1; }
for c in 36:42:+ 40:42:- 44:42:+ 48:42:- 52:58:+ 100:106:+ 116:122:+ 132:138:+ 149:155:+ 153:155:- 157:155:+ 161:155:- 165:171:+; do
  ch=${c%%:*}; r=${c#*:}; want=${r%:*}; dir=${r#*:}
  aprender c$ch "$TWO
AP_CHAN5=$ch AP_HT5=80 AP_HE=1"
  [ "$(seg c$ch vht_oper_centr_freq_seg0_idx)" = $want ] && [ "$(seg c$ch he_oper_centr_freq_seg0_idx)" = $want ] && [ "$(seg c$ch vht_oper_chwidth)" = 1 ] \
    && case "$(seg c$ch ht_capab)" in "[HT40$dir][LDPC]"*) true;; *) false;; esac && [ "$(seg c$ch channel)" = $ch ] \
    && ok "ap: 5 GHz ch $ch / 80 MHz -> centre $want, HT40$dir" || { no "ap: ch $ch / 80 MHz: seg0=$(seg c$ch vht_oper_centr_freq_seg0_idx) he=$(seg c$ch he_oper_centr_freq_seg0_idx) ht=$(seg c$ch ht_capab)"; cat "$A/c$ch.out"; }
done
for c in 36:38:+ 40:38:- 149:151:+ 153:151:-; do
  ch=${c%%:*}; r=${c#*:}; want=${r%:*}; dir=${r#*:}
  aprender w$ch "$TWO
AP_CHAN5=$ch AP_HT5=40"
  [ "$(seg w$ch vht_oper_centr_freq_seg0_idx)" = $want ] && [ "$(seg w$ch vht_oper_chwidth)" = 0 ] \
    && case "$(seg w$ch ht_capab)" in "[HT40$dir][LDPC]"*) true;; *) false;; esac \
    && ok "ap: 5 GHz ch $ch / 40 MHz -> centre $want, HT40$dir" || no "ap: ch $ch / 40 MHz: seg0=$(seg w$ch vht_oper_centr_freq_seg0_idx) ht=$(seg w$ch ht_capab)"
done
aprender auto "$TWO
AP_CHAN5=auto AP_HT5=80"
[ "$(seg auto channel)" = 0 ] && ! grep -q 'centr_freq_seg0_idx' "$A/auto/ap5.conf" && [ "$(seg auto vht_oper_chwidth)" = 1 ] \
  && ok "ap: 5 GHz auto (ACS) at 80 MHz leaves the centre channel to hostapd" || no "ap: ACS config wrong: $(grep -E 'channel|centr|chwidth' "$A/auto/ap5.conf" | tr '\n' ' ')"
aprender bad "$TWO
AP_CHAN5=150"
[ "$(seg bad channel)" = 0 ] && grep -q 'not a 5 GHz channel' "$A/bad.out" && ok "ap: an off-raster 5 GHz channel falls back to auto, with a message" || no "ap: AP_CHAN5=150 not handled"
# client isolation per SSID (the Wi-Fi page's "isolate clients"): ISOLATE_<id>=1 -> ap_isolate=1 on that SSID's BSSes only;
# values the web UI writes with shell quoting (spaces, quotes) reach hostapd unchanged
aprender iso "AP_SSIDS=\"m g\"
SSID_m='Main 9 3/4' KEY_m='it'\\''s a key' SEC_m=wpa2
SSID_g=Guest KEY_g=guestkey99 ISOLATE_g=1"
iso5=$(awk '/^ssid=/{s=$0} /^ap_isolate=/{print s" "$0}' "$A/iso/ap5.conf" 2>/dev/null | tr '\n' '|')
[ "$iso5" = "ssid=Main 9 3/4 ap_isolate=0|ssid=Guest ap_isolate=1|" ] && grep -qx "wpa_passphrase=it's a key" "$A/iso/ap24.conf" \
  && ok "ap: ISOLATE_<id>=1 isolates only that SSID; quoted SSID/key values pass through" || { no "ap: isolation/quoting wrong: $iso5"; cat "$A/iso.out"; }
# 802.11ax: ON by default with OpenWrt 25.12's radio settings for this board (a bare ieee80211ax=1 without them left
# phones in power save with 50-100 % downstream loss); AP_HE=0 turns it off on both radios, VHT 80 MHz stays complete
aprender he1 "$TWO
AP_CHAN5=149 AP_HT5=80"
c5="$A/he1/ap5.conf"; c24="$A/he1/ap24.conf"
cnt() { grep -c "^$1" "$2" 2>/dev/null; }
if [ "$(seg he1 ieee80211ax)" = 1 ] && grep -q '^ieee80211ax=1' "$c24" && [ "$(seg he1 he_oper_centr_freq_seg0_idx)" = 155 ] \
  && [ "$(seg he1 he_oper_chwidth)" = 1 ]; then ok "ap: 802.11ax on by default on both radios, HE centre channel set"
else no "ap: default HE state wrong: $(grep -hE '^(ieee80211ax|he_oper)' "$c5" "$c24" | tr '\n' ' ')"; cat "$A/he1.out"; fi
heok=1
for f in "$c5" "$c24"; do
  for k in he_su_beamformer=1 he_su_beamformee=1 he_mu_beamformer=1 he_spr_sr_control=3 he_default_pe_duration=4 \
           he_rts_threshold=1023 he_mu_edca_ac_be_aifsn=8 he_mu_edca_ac_bk_aifsn=15 he_mu_edca_ac_vi_ecwmax=7 \
           he_mu_edca_ac_vo_timer=255 beacon_int=100 stationary_ap=1; do grep -qx "$k" "$f" || { heok=0; echo "  missing $k in ${f##*/}"; }; done
  col=$(sed -n 's/^he_bss_color=//p' "$f"); [ -n "$col" ] && [ "$col" -ge 1 ] && [ "$col" -le 63 ] || { heok=0; echo "  he_bss_color=$col in ${f##*/}"; }
  [ "$(cnt he_bss_color= "$f")" = 1 ] || heok=0
done
[ $heok = 1 ] && ok "ap: HE beamforming, BSS color 1-63, spatial reuse, PE 16 us, RTS off and MU EDCA on both radios" \
  || no "ap: HE radio settings incomplete (see above)"
[ "$(sed -n 's/^he_bss_color=//p' "$c5")" != "$(sed -n 's/^he_bss_color=//p' "$c24")" ] && ok "ap: the two radios get different BSS colors" \
  || no "ap: both radios have the same BSS color"
case "$(seg he1 ht_capab)" in "[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1]"*) v=1;; *) v=0;; esac
grep -q '^vht_capab=\[RXLDPC\]\[SHORT-GI-80\].*\[SU-BEAMFORMER\]' "$c5" || v=0
grep -qx 'ht_capab=\[LDPC\]\[SHORT-GI-20\]\[SHORT-GI-40\]\[TX-STBC\]\[RX-STBC1\]\[DSSS_CCK-40\]' "$c24" || v=0
grep -qx 'basic_rates=60 120 240' "$c24" && ! grep -qE '^supported_rates=(.* )?(10|20|55|110)( |$)' "$c24" || v=0
[ $v = 1 ] && ok "ap: the board's HT/VHT capabilities are written, 2.4 GHz without 802.11b rates" \
  || no "ap: ht/vht capabilities: $(grep -hE '^(ht_capab|vht_capab|basic_rates|supported_rates)' "$c5" "$c24" | tr '\n' ' ')"
# every BSS (2 SSIDs x 2 radios): own control socket, U-APSD advertised, low-ACK disassoc, inactivity poll
b=1; for f in "$c5" "$c24"; do
  for k in ctrl_interface=/run/hostapd uapsd_advertisement_enabled=1 disassoc_low_ack=1 skip_inactivity_poll=0; do
    [ "$(grep -cx "$k" "$f")" = 2 ] || { b=0; echo "  $k: $(grep -cx "$k" "$f") of 2 BSS in ${f##*/}"; }; done; done
[ $b = 1 ] && ok "ap: every BSS has its control socket, U-APSD, low-ACK disassociation and the inactivity poll" \
  || no "ap: per-BSS settings missing (see above)"
aprender he0 "$TWO
AP_CHAN5=149 AP_HT5=80 AP_HE=0"
if [ "$(seg he0 ieee80211ax)" = 0 ] && grep -q '^ieee80211ax=0' "$A/he0/ap24.conf" && ! grep -q '^he_' "$A/he0/ap5.conf" "$A/he0/ap24.conf" \
  && [ "$(seg he0 vht_oper_centr_freq_seg0_idx)" = 155 ] && [ "$(seg he0 vht_oper_chwidth)" = 1 ] && [ "$(seg he0 ieee80211ac)" = 1 ]; then
  ok "ap: AP_HE=0 turns 802.11ax off on both radios (no he_* lines), VHT 80 MHz centre kept"
else no "ap: AP_HE=0 not rendered: $(grep -hE '^(ieee80211ax|ieee80211ac|he_|vht_oper)' "$A/he0/ap5.conf" "$A/he0/ap24.conf" | tr '\n' ' ')"; cat "$A/he0.out"; fi
aprender w20 "$TWO
AP_CHAN5=36 AP_HT5=20"
[ "$(grep -c '^ht_capab=' "$A/w20/ap5.conf")" = 1 ] && case "$(seg w20 ht_capab)" in "[LDPC]"*) true;; *) false;; esac \
  && ok "ap: 20 MHz on 5 GHz still writes one ht_capab line with the board's capabilities" || no "ap: 20 MHz ht_capab: $(grep '^ht_capab' "$A/w20/ap5.conf" | tr '\n' ' ')"
# ap-event: a station that joins one radio is dropped (without a frame) from the other radio's BSSes that still list it
E=$W/apev; mkdir -p "$E/ctrl" "$E/bin"
if command -v python3 >/dev/null 2>&1; then
  for i in wl24-m wl5-m wl5-g; do python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$E/ctrl/$i"; done
  # fake hostapd_cli: wl24-m and wl5-g list the station, wl5-m is where it just connected
  cat > "$E/bin/hostapd_cli" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -p) shift 2;; -i) i=$2; shift 2;; *) break;; esac; done
echo "$i $*" >> "$APEV_LOG"
[ "$1" = sta ] && case "$i" in wl24-m|wl5-g) echo "$2"; echo flags=[AUTH][ASSOC];; *) echo FAIL;; esac
exit 0
EOF
  chmod +x "$E/bin/hostapd_cli"; : > "$E/log"
  # fake sysfs: wl5-* on phy0 (5 GHz), wl24-* on phy1 (2.4 GHz)
  for i in wl24-m:phy1 wl5-m:phy0 wl5-g:phy0; do mkdir -p "$E/net/${i%%:*}/phy80211"; echo "${i#*:}" > "$E/net/${i%%:*}/phy80211/name"; done
  APEV_LOG=$E/log AP_CTRL=$E/ctrl AP_CLI=$E/bin/hostapd_cli AP_SYSNET=$E/net sh "$O/usr/libexec/patronus/ap-event" wl5-m AP-STA-CONNECTED 02:11:22:33:44:55
  grep -qx 'wl24-m deauthenticate 02:11:22:33:44:55 tx=0' "$E/log" && ! grep -q '^wl5-g deauthenticate' "$E/log" \
    && ! grep -q '^wl5-m deauthenticate' "$E/log" \
    && ok "ap-event: a station that joined one radio is removed (tx=0) from the other radio's BSS that lists it, never from a BSS of its own radio" \
    || { no "ap-event: wrong removals"; cat "$E/log"; }
  : > "$E/log"; rm -rf "$E/net/wl24-m"
  APEV_LOG=$E/log AP_CTRL=$E/ctrl AP_CLI=$E/bin/hostapd_cli AP_SYSNET=$E/net sh "$O/usr/libexec/patronus/ap-event" wl5-m AP-STA-CONNECTED 02:11:22:33:44:55
  ! grep -q 'deauthenticate' "$E/log" && ok "ap-event: a BSS whose radio is unknown is never touched" || { no "ap-event: removed from a BSS of unknown radio"; cat "$E/log"; }
  : > "$E/log"
  APEV_LOG=$E/log AP_CTRL=$E/ctrl AP_CLI=$E/bin/hostapd_cli AP_SYSNET=$E/net sh "$O/usr/libexec/patronus/ap-event" wl5-m AP-STA-DISCONNECTED 02:11:22:33:44:55
  [ ! -s "$E/log" ] && ok "ap-event: other events change nothing" || { no "ap-event: acted on AP-STA-DISCONNECTED"; cat "$E/log"; }
else sk "ap-event (no python3 to create the control sockets)"; fi
grep -q 'hostapd_cli -B .* -a /usr/libexec/patronus/ap-event' "$O/usr/libexec/patronus/ap" && [ -x "$O/usr/libexec/patronus/ap-event" ] \
  && ok "ap: start runs ap-event for every BSS (executable)" || no "ap: ap-event not wired into start, or not executable"
grep -q centr_freq "$A/two/ap24.conf" && no "ap: 2.4 GHz config got a 5 GHz centre channel" || ok "ap: 2.4 GHz config has no VHT/HE centre channel"
[ "$(stat -c %a "$A/two/ap5.conf")" = 600 ] && ok "ap: config is 0600 (holds the keys)" || no "ap: config mode $(stat -c %a "$A/two/ap5.conf")"

# 3a. Wi-Fi firmware crash containment (wifi-guard) and the Patronus hostapd package (docs 12.6d)
G=$W/wg; WGS=$O/usr/libexec/patronus/wifi-guard; mkdir -p "$G/bin"
printf '#!/bin/sh\necho "ap $*" >> %s/calls\n' "$G" > "$G/bin/ap"
printf '#!/bin/sh\nshift 4; echo "state=$(cat %s/bss-state)"\n' "$G" > "$G/bin/cli"
printf '#!/bin/sh\necho "logger $*" >> %s/calls\n' "$G" > "$G/bin/logger"; chmod +x "$G/bin/"*
wgenv() { env WG_STATE="$G/st" WG_RUN="$G/run" WG_AP="$G/bin/ap" WG_CLI="$G/bin/cli" WG_CTRL="$G/ctrl" WG_UPTIME="$G/uptime" \
  WG_LOGGER="$G/bin/logger" WG_KMSG="$G/kmsg" RECOVER_WAIT=0 "$@"; }
wgreset() { rm -rf "$G/st" "$G/run" "$G/ctrl" "$G/calls"; mkdir -p "$G/st" "$G/ctrl"; : > "$G/calls"; echo "100.00 50.00" > "$G/uptime"; echo ENABLED > "$G/bss-state"; }
wgreset; echo 5 > "$G/st/boot"; printf '4 31\n5 29\n' > "$G/st/crashes"
wgenv sh "$WGS" boot >/dev/null 2>&1
[ "$(cat "$G/st/boot")" = 6 ] && wgenv sh "$WGS" safe && grep -q 'PATRONUS-AP-SAFE-MODE on' "$G/calls" \
  && ok "wifi-guard: a firmware crash in each of the last 2 boots (restart loop) -> safe mode before hostapd starts" \
  || { no "wifi-guard: restart loop not detected"; cat "$G/calls"; }
wgenv sh "$WGS" boot >/dev/null 2>&1
[ "$(cat "$G/st/boot")" = 6 ] && ok "wifi-guard: a second ap start in the same boot is not a new boot" || no "wifi-guard: boot counted twice ($(cat "$G/st/boot"))"
wgreset; echo 5 > "$G/st/boot"; printf '3 31\n5 29\n' > "$G/st/crashes"
wgenv sh "$WGS" boot >/dev/null 2>&1
wgenv sh "$WGS" safe && no "wifi-guard: safe mode after a crash in only one of the last 2 boots" || ok "wifi-guard: one crashed boot is not a loop (no safe mode)"
if command -v python3 >/dev/null 2>&1; then
  python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$G/ctrl/wl24-m" 2>/dev/null
  # kmsg: one record from before the guard started (ignored), then CRASH_MAX crashes
  kmsg() { : > "$G/kmsg"; echo '3,10,20000000,-;remoteproc remoteproc0: crash detected in cd00000.remoteproc: type fatal error' >> "$G/kmsg"
    i=0; while [ $i -lt "$1" ]; do echo "3,$((20 + 2 * i)),$((100000001 + i)),-;remoteproc remoteproc0: crash detected in cd00000.remoteproc: type fatal error" >> "$G/kmsg"
      echo "6,$((21 + 2 * i)),$((100000002 + i)),-;remoteproc remoteproc0: remote processor cd00000.remoteproc is now up" >> "$G/kmsg"; i=$((i + 1)); done; }
  wgreset; echo 7 > "$G/st/boot"; mkdir -p "$G/ctrl"; python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$G/ctrl/wl24-m"
  kmsg 1; wgenv timeout 20 sh "$WGS" run >/dev/null 2>&1
  [ "$(grep -c '^7 ' "$G/st/crashes")" = 1 ] && grep -q 'PATRONUS-WIFI-CRASH' "$G/calls" && grep -q 'PATRONUS-WIFI-RECOVERED every BSS' "$G/calls" \
    && ! grep -q '^ap ' "$G/calls" && ! wgenv sh "$WGS" safe \
    && ok "wifi-guard: one crash is recorded (old kernel records ignored), BSSes back -> no restart, no safe mode" \
    || { no "wifi-guard: single crash handling"; cat "$G/calls" "$G/st/crashes"; }
  wgreset; echo 7 > "$G/st/boot"; python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$G/ctrl/wl24-m"; echo DISABLED > "$G/bss-state"
  kmsg 1; wgenv timeout 20 sh "$WGS" run >/dev/null 2>&1
  grep -q 'ap stop' "$G/calls" && grep -q 'ap start' "$G/calls" && grep -q 'RECOVERED by restarting' "$G/calls" \
    && ok "wifi-guard: a BSS that did not come back after the crash -> the APs are restarted (no driver unload)" \
    || { no "wifi-guard: dead BSS not restarted"; cat "$G/calls"; }
  wgreset; echo 7 > "$G/st/boot"; python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$G/ctrl/wl24-m"
  kmsg 3; wgenv CRASH_MAX=3 timeout 20 sh "$WGS" run >/dev/null 2>&1
  wgenv sh "$WGS" safe && grep -q 'PATRONUS-AP-SAFE-MODE on' "$G/calls" && grep -q 'ap start' "$G/calls" \
    && ok "wifi-guard: 3 crashes within 10 min -> safe mode + APs restarted with it" || { no "wifi-guard: crash burst not contained"; cat "$G/calls"; }
  grep -q 'rmmod\|modprobe -r' "$WGS" && no "wifi-guard: unloads a driver (crashes this board)" || ok "wifi-guard: never unloads ath11k"
else sk "wifi-guard run cases (no python3 to create the control sockets)"; fi
printf '#!/bin/sh\nexit 0\n' > "$G/safe-on"; printf '#!/bin/sh\nexit 1\n' > "$G/safe-off"; chmod +x "$G/safe-on" "$G/safe-off"
printf '. %s\n%s\n' "$O/etc/patronus/board.sh" "$TWO" > "$A/board-safe.sh"
for m in on off; do rm -rf "$A/safe-$m"; AP_GUARD=$G/safe-$m AP_BOARD=$A/board-safe.sh AP_RENDER_OUT=$A/safe-$m AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 \
  sh "$O/usr/libexec/patronus/ap" render > "$A/safe-$m.out" 2>&1; done
[ "$(grep -c '^ssid=' "$A/safe-on/ap24.conf")" = 1 ] && grep -qx 'ssid=Example' "$A/safe-on/ap24.conf" && [ "$(grep -c '^ssid=' "$A/safe-on/ap5.conf")" = 1 ] \
  && [ "$(grep -c '^ssid=' "$A/safe-off/ap24.conf")" = 2 ] \
  && ok "ap: safe mode renders only the first SSID on each radio; normal mode both" || { no "ap: safe-mode render"; grep -h '^ssid=' "$A"/safe-*/ap*.conf; cat "$A/safe-on.out"; }
grep -q 'wifi-guard' "$O/usr/libexec/patronus/ap" && grep -q '"$WG" boot' "$O/usr/libexec/patronus/ap" && [ -x "$WGS" ] \
  && ok "ap: start counts the boot and keeps wifi-guard running (executable)" || no "ap: wifi-guard not wired into start"
HP=$D/hostapd; bad=
for f in hostapd.initd hostapd.confd patronus-xbss.diff; do
  want=$(awk -v f="$f" '$2 == f { print $1 }' "$HP/APKBUILD"); have=$(sha512sum "$HP/$f" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$have" ] || bad="$bad $f"; done
[ -z "$bad" ] && ok "hostapd/APKBUILD: sha512sums pin the local sources" || no "hostapd/APKBUILD: sha512sums out of date for:$bad"
grep -q 'ap_sta_drop_in_other_bss(hapd, sta->addr);' "$HP/patronus-xbss.diff" && grep -q 'hostapd_drv_sta_remove(bss, addr);' "$HP/patronus-xbss.diff" \
  && ok "hostapd patch: other-BSS removal goes to the driver synchronously before the new peer is added" || no "hostapd patch: synchronous removal missing"

# 3c. router-tier device settings (docs/router-tier-ui.md): guest networks, block lists, transmit power, LEDs,
#     scheduled restart, address trial. The real scripts against fakes (sysfs, nft, iw, hostapd_cli, rc-*, systemctl).
aprender gst "AP_SSIDS=\"m g\"
SSID_m=Main KEY_m=mainpass1 SSID_g=Guest KEY_g=guestpass1 GUEST_g=1 DENY_g='aa:bb:cc:dd:ee:01 junk'
AP_DENY='AA:BB:CC:DD:EE:02'"
g5=$(awk '/^bss=wl5-g$/,0' "$A/gst/ap5.conf" 2>/dev/null)
case "$g5" in *ap_isolate=1*"deny_mac_file=$A/gst/deny-wl5-g"*) ok "ap: a guest network always isolates its clients and has a deny file";;
  *) no "ap: guest BSS without ap_isolate/deny_mac_file"; cat "$A/gst.out"; sed 's/^/    /' "$A/gst/ap5.conf" 2>/dev/null;; esac
grep -q '^ap_isolate=0' "$A/gst/ap5.conf" && grep -q "^deny_mac_file=$A/gst/deny-wl5-m" "$A/gst/ap5.conf" \
  && ok "ap: a normal network is not isolated, every BSS gets its deny file" || no "ap: normal BSS rendering changed"
[ "$(cat "$A/gst/deny-wl24-g" 2>/dev/null | tr '\n' ' ')" = "aa:bb:cc:dd:ee:01 aa:bb:cc:dd:ee:02 " ] && [ "$(cat "$A/gst/deny-wl24-m" 2>/dev/null)" = "aa:bb:cc:dd:ee:02" ] \
  && [ "$(stat -c %a "$A/gst/deny-wl24-g" 2>/dev/null)" = 600 ] \
  && ok "ap: deny files = unit list + the network's own, lower case, junk dropped, 0600" || no "ap: deny files wrong: $(cat "$A"/gst/deny-* 2>/dev/null | tr '\n' ' ')"
# live: `ap txpower` / `ap acl` act on the running radios through iw / hostapd_cli (fakes record the calls)
FB=$A/fakebin; mkdir -p "$FB"
printf '#!/bin/sh\necho "iw $*" >> %s/calls\n' "$A" > "$FB/iw"; printf '#!/bin/sh\necho "hostapd_cli $*" >> %s/calls\n' "$A" > "$FB/hostapd_cli"; chmod +x "$FB"/*
printf '. %s\nAP_SSIDS="m g"\nSSID_m=Main KEY_m=mainpass1 SSID_g=Guest KEY_g=guestpass1 GUEST_g=1\nAP_TXPOWER5=17 AP_DENY=aa:bb:cc:dd:ee:03\n' "$O/etc/patronus/board.sh" > "$A/board-live.sh"
: > "$A/calls"; PATH=$FB:$PATH AP_BOARD=$A/board-live.sh AP_RENDER_OUT=$A/gst sh "$O/usr/libexec/patronus/ap" txpower > /dev/null 2>&1
PATH=$FB:$PATH AP_BOARD=$A/board-live.sh AP_RENDER_OUT=$A/gst sh "$O/usr/libexec/patronus/ap" acl > /dev/null 2>&1
c=$(cat "$A/calls")
case "$c" in *"iw dev wl5-m set txpower fixed 1700"*"iw dev wl24-m set txpower auto"*) ok "ap txpower: 5 GHz fixed 17 dBm, 2.4 GHz auto, no restart";; *) no "ap txpower: $c";; esac
case "$c" in *"-i wl5-g deny_acl CLEAR"*"-i wl5-g deny_acl ADD_MAC aa:bb:cc:dd:ee:03"*) ok "ap acl: deny lists pushed to the running hostapds (DENY_ACL)";; *) no "ap acl: $c";; esac
# guest filter: nft bridge table from ap.env; none -> no table
printf '. %s\nAP_SSIDS="m g i"\nGUEST_g=1 BANDS_g=24 GUEST_i=1\n' "$O/etc/patronus/board.sh" > "$A/board-g.sh"
gr=$(AP_BOARD=$A/board-g.sh AP_GUEST_NETS4=192.0.2.0/24 AP_GUEST_NETS6=2001:db8:1:2::/64 AP_GUEST_GW=192.0.2.1 AP_GUEST_RESOLV=/dev/null \
  sh "$O/usr/libexec/patronus/ap-guest" render 2>&1)
case "$gr" in *'elements = { "wl24-g", "wl24-i", "wl5-i" }'*'192.0.2.0/24'*'2001:db8:1:2::/64'*'set ok4 { type ipv4_addr; elements = { 192.0.2.1 } }'*'iifname @ports ip daddr @lan4 drop'*'iifname @ports meta l4proto { tcp, udp } drop'*)
  ok "ap-guest: guest ports, LAN networks, gateway exception and the no-access-to-this-unit rule";; *) no "ap-guest render: $gr";; esac
command -v nft > /dev/null && { printf '%s\n' "$gr" > "$A/guest.nft"; nft -c -f "$A/guest.nft" > "$A/nft.out" 2>&1 \
  && ok "ap-guest: nft accepts the rendered ruleset (nft -c)" || { grep -q 'Operation not permitted\|Permission' "$A/nft.out" && sk "nft -c needs CAP_NET_ADMIN" || { no "ap-guest: nft -c"; cat "$A/nft.out"; }; }; } || sk "ap-guest: no nft on this host"
printf '. %s\nAP_SSIDS="m"\n' "$O/etc/patronus/board.sh" > "$A/board-ng.sh"
AP_BOARD=$A/board-ng.sh sh "$O/usr/libexec/patronus/ap-guest" render > /dev/null 2>&1 && no "ap-guest: rendered a table without guest networks" || ok "ap-guest: no guest network, no filter"
# LEDs: off = trigger none + brightness 0; on = the boot defaults back
L=$A/leds; mkdir -p "$L/sys/green:status" "$L/sys/blue:wlan"; echo 'none [default-on] timer' > "$L/sys/green:status/trigger"; echo 1 > "$L/sys/green:status/brightness"
echo '[none] timer' > "$L/sys/blue:wlan/trigger"; echo 255 > "$L/sys/blue:wlan/brightness"
echo LEDS=off > "$L/env"; LEDS_SYSFS=$L/sys LEDS_ENV=$L/env LEDS_RUN=$L/run sh "$O/usr/libexec/patronus/leds" apply > /dev/null
[ "$(cat "$L/sys/green:status/trigger")" = none ] && [ "$(cat "$L/sys/blue:wlan/brightness")" = 0 ] && ok "leds: off" || no "leds: off did not switch them off"
echo LEDS=on > "$L/env"; LEDS_SYSFS=$L/sys LEDS_ENV=$L/env LEDS_RUN=$L/run sh "$O/usr/libexec/patronus/leds" apply > /dev/null
[ "$(cat "$L/sys/green:status/trigger")" = default-on ] && [ "$(cat "$L/sys/blue:wlan/brightness")" = 255 ] && ok "leds: on restores the boot triggers/brightness" \
  || no "leds: on: $(cat "$L/sys/green:status/trigger") $(cat "$L/sys/blue:wlan/brightness")"
lo=$(LEDS_SYSFS=$L/none LEDS_ENV=$L/env LEDS_RUN=$L/run sh "$O/usr/libexec/patronus/leds" apply); case "$lo" in *"none in"*) true;; *) false;; esac && ok "leds: a device without LEDs is left alone" || no "leds: no-LED case"
# scheduled restart: OFF by default; OpenRC = crontab line + patronus-crond in default; systemd = timer drop-in + enable
S=$A/rs; mkdir -p "$S/bin" "$S/sd"
for c in rc-update rc-service systemctl logger; do printf '#!/bin/sh\necho "%s $*" >> %s/calls\n' "$c" "$S" > "$S/bin/$c"; chmod +x "$S/bin/$c"; done
printf 'RESTART=weekly RESTART_TIME=04:05 RESTART_DAY=mon\n' > "$S/env"
PATH=$S/bin:$PATH RS_ENV=$S/env RS_CRONTAB=$S/crontab RS_INIT=openrc sh "$O/usr/libexec/patronus/restart-schedule" apply > "$S/out" 2>&1
grep -qx '5 4 \* \* 1 /usr/libexec/patronus/scheduled-restart # patronus-restart' "$S/crontab" && grep -q 'rc-update add patronus-crond default' "$S/calls" \
  && ok "restart-schedule (OpenRC): weekly crontab line, crond enabled" || { no "restart-schedule openrc"; cat "$S/crontab" "$S/calls" "$S/out"; }
printf 'RESTART=off\n' > "$S/env"; PATH=$S/bin:$PATH RS_ENV=$S/env RS_CRONTAB=$S/crontab RS_INIT=openrc sh "$O/usr/libexec/patronus/restart-schedule" apply > /dev/null 2>&1
! grep -q patronus-restart "$S/crontab" && grep -q 'rc-update del patronus-crond default' "$S/calls" && ok "restart-schedule (OpenRC): off removes the line and crond" || no "restart-schedule openrc off"
printf 'RESTART=daily RESTART_TIME=23:30\n' > "$S/env"; : > "$S/calls"
PATH=$S/bin:$PATH RS_ENV=$S/env RS_SYSTEMD_DIR=$S/sd RS_INIT=systemd sh "$O/usr/libexec/patronus/restart-schedule" apply > /dev/null 2>&1
grep -qx 'OnCalendar=\*-\*-\* 23:30:00' "$S/sd/patronus-restart.timer.d/schedule.conf" 2>/dev/null && grep -q 'systemctl enable --now patronus-restart.timer' "$S/calls" \
  && ok "restart-schedule (systemd): OnCalendar drop-in, timer enabled" || { no "restart-schedule systemd"; cat "$S/sd/patronus-restart.timer.d/schedule.conf" "$S/calls"; }
[ -x "$D/overlay-openrc/etc/init.d/patronus-crond" ] && [ -f "$D/overlay-systemd/etc/systemd/system/patronus-restart.timer" ] \
  && [ ! -e "$D/overlay-systemd/etc/systemd/system/timers.target.wants/patronus-restart.timer" ] \
  && ok "parity: scheduled restart patronus-crond (OpenRC) = patronus-restart.timer (systemd), neither on by default" || no "scheduled restart parity"
# address trial: a trial that was never confirmed before a restart is undone at boot (the unit cannot be stranded)
R2=$A/addr; mkdir -p "$R2/run"; printf '#!/bin/sh\necho "ip $*" >> %s/calls\n' "$R2" > "$R2/ip"; printf '#!/bin/sh\n' > "$R2/udhcpc"; chmod +x "$R2/ip" "$R2/udhcpc"
echo "AP_ADDR=198.51.100.7/24 AP_GW=198.51.100.1" > "$R2/ap.env"; echo "AP_ADDR=" > "$R2/ap.env.addr-prev"; echo 100 > "$R2/ap.env.addr-pending"
PATH=$R2:$PATH AP_ENV=$R2/ap.env AP_ADDR_RUN=$R2/run AP_ADDR_TMP=$R2 AP_ADDR_IP=$R2/ip AP_ADDR_DHCP=$R2/udhcpc sh "$O/usr/libexec/patronus/ap-addr" boot > "$R2/out" 2>&1
[ "$(cat "$R2/ap.env")" = "AP_ADDR=" ] && [ ! -e "$R2/ap.env.addr-pending" ] && ! grep -q 198.51.100.7 "$R2/calls" 2>/dev/null \
  && ok "ap-addr: an unconfirmed address change is undone at the next boot" || { no "ap-addr boot revert"; cat "$R2/out" "$R2/calls" 2>/dev/null; }
echo "AP_ADDR=192.0.2.9/24 AP_GW=192.0.2.1 AP_DNS='192.0.2.1 192.0.2.2'" > "$R2/ap.env"; : > "$R2/calls"
PATH=$R2:$PATH AP_ENV=$R2/ap.env AP_ADDR_RUN=$R2/run AP_ADDR_TMP=$R2 AP_ADDR_IP=$R2/ip AP_ADDR_DHCP=$R2/udhcpc sh "$O/usr/libexec/patronus/ap-addr" boot > /dev/null 2>&1
grep -q 'ip addr add 192.0.2.9/24 dev br-lan' "$R2/calls" && grep -q 'ip route replace default via 192.0.2.1 dev br-lan' "$R2/calls" \
  && ok "ap-addr: static address + gateway at boot" || { no "ap-addr static boot"; cat "$R2/calls"; }
PATH=$R2:$PATH AP_ENV=$R2/ap.env AP_ADDR_RUN=$R2/run AP_ADDR_TMP=$R2 sh "$O/usr/libexec/patronus/ap-addr" confirm > /dev/null 2>&1 && no "ap-addr: confirm without a trial succeeded" || ok "ap-addr: confirm refuses when nothing is pending"

# 3b. ath11k-caldata: writes the calibration to a writable path (the root is read-only), fails loudly when it cannot
CD=$W/cal; mkdir -p "$CD/ro"; head -c 131072 /dev/urandom > "$CD/art"
grep -q '^OUT=${CALDATA_OUT:-/run/firmware/' "$O/usr/libexec/patronus/ath11k-caldata" && ok "caldata: default output is under /run/firmware (tmpfs), not the squashfs root" \
  || no "caldata: default output is not under /run/firmware"
grep -q 'firmware_class/parameters/path' "$O/usr/libexec/patronus/early" && ok "early: firmware_class.path points at the tmpfs firmware dir" || no "early: firmware_class.path not set"
e_cal=$(grep -n 'ath11k-caldata' "$O/usr/libexec/patronus/early" | grep -v '^ *[0-9]*:#' | head -1 | cut -d: -f1); e_km=$(grep -n 'mark modules-loaded' "$O/usr/libexec/patronus/early" | cut -d: -f1)
[ -n "$e_cal" ] && [ -n "$e_km" ] && [ "$e_cal" -lt "$e_km" ] && ok "early: calibration is generated before the kmods load" || no "early: calibration runs after the kmods (cal=$e_cal kmods=$e_km)"
grep -q 'rmmod ath11k' "$O/usr/libexec/patronus/early" && no "early: still rmmods ath11k (crashes the board)" || ok "early: never rmmods ath11k"
if CALDATA_ART=$CD/art CALDATA_LABEL=94:00:5e:10:20:d4 CALDATA_OUT=$CD/w/ath11k/IPQ6018/hw1.0/cal.bin sh "$O/usr/libexec/patronus/ath11k-caldata" > "$CD/out" 2>&1 \
   && [ "$(wc -c < "$CD/w/ath11k/IPQ6018/hw1.0/cal.bin")" = 65536 ]; then ok "caldata: writes 64 KiB to a writable path (directories created)"; else no "caldata: write to a writable path failed"; cat "$CD/out"; fi
m0=$(od -An -tx1 -j14 -N6 "$CD/w/ath11k/IPQ6018/hw1.0/cal.bin" 2>/dev/null | tr -d ' \n')
[ "$m0" = 94005e1020d7 ] && ok "caldata: radio 0 MAC = label + 3 patched in" || no "caldata: radio 0 MAC is $m0"
# label MAC as in the early boot (before the Ethernet kmod probes): no mac-address property yet, a zero
# local-mac-address placeholder, the real MAC only in the ART nvmem cell (phandle -> fixed-layout cell -> partition)
FDT=$CD/dt; mkdir -p "$FDT/aliases" "$FDT/soc@0/dp1" "$FDT/soc@0/nand/partitions/partition@980000/nvmem-layout/macaddr@0" "$FDT/soc@0/nand/partitions/partition@980000/nvmem-layout/macaddr@6" "$CD/parts"
printf '/soc@0/dp1\0' > "$FDT/aliases/label-mac-device"; printf '\0\0\0\0\0\0' > "$FDT/soc@0/dp1/local-mac-address"; printf '\0\0\0\042' > "$FDT/soc@0/dp1/nvmem-cells"
L6=$FDT/soc@0/nand/partitions/partition@980000; printf '0:art\0' > "$L6/label"
printf '\0\0\0\042' > "$L6/nvmem-layout/macaddr@0/phandle"; printf '\0\0\0\0\0\0\0\006' > "$L6/nvmem-layout/macaddr@0/reg"
printf '\0\0\0\043' > "$L6/nvmem-layout/macaddr@6/phandle"; printf '\0\0\0\006\0\0\0\006' > "$L6/nvmem-layout/macaddr@6/reg"
printf '\224\000\136\020\040\324\224\000\136\020\040\325' > "$CD/parts/0:art"; head -c 4084 /dev/zero >> "$CD/parts/0:art"; tail -c +4097 "$CD/art" >> "$CD/parts/0:art"
CAL() { env CALDATA_ART="$CD/parts/0:art" CALDATA_DT="$FDT" CALDATA_PARTS="$CD/parts" CALDATA_OUT="$CD/$1.bin" sh "$O/usr/libexec/patronus/ath11k-caldata"; }
if CAL nv > "$CD/out" 2>&1 && grep -q 'label MAC from nvmem' "$CD/out"; then ok "caldata: label MAC read from the nvmem cell before the Ethernet driver probes"; else no "caldata: nvmem label MAC"; cat "$CD/out"; fi
m0=$(od -An -tx1 -j14 -N6 "$CD/nv.bin" 2>/dev/null | tr -d ' \n'); m1=$(od -An -tx1 -j20 -N6 "$CD/nv.bin" 2>/dev/null | tr -d ' \n')
[ "$m0" = 94005e1020d7 ] && [ "$m1" = 94005e1020d6 ] && ok "caldata: radio MACs = nvmem label + 3 / + 2" || no "caldata: radio MACs from nvmem label are $m0 / $m1"
printf '\224\000\136\020\040\330' > "$FDT/soc@0/dp1/mac-address"
CAL prop > "$CD/out" 2>&1; m0=$(od -An -tx1 -j14 -N6 "$CD/prop.bin" 2>/dev/null | tr -d ' \n')
grep -q 'label MAC from mac-address' "$CD/out" && [ "$m0" = 94005e1020db ] && ok "caldata: a mac-address property (driver already probed) wins" || { no "caldata: mac-address property not used ($m0)"; cat "$CD/out"; }
rm "$FDT/soc@0/dp1/mac-address" "$FDT/soc@0/dp1/nvmem-cells"
if CAL zero > "$CD/out" 2>&1; then no "caldata: accepted the zero local-mac-address placeholder"; else
  m0=$(od -An -tx1 -j14 -N6 "$CD/zero.bin" 2>/dev/null | tr -d ' \n')
  grep -q 'no valid label MAC' "$CD/out" && [ "$m0" != 000000000003 ] && ok "caldata: an all-zero label MAC is refused (non-zero exit, nothing patched)" || { no "caldata: zero label handling ($m0)"; cat "$CD/out"; }; fi
chmod 555 "$CD/ro"
if [ "$(id -u)" != 0 ]; then
  if CALDATA_ART=$CD/art CALDATA_LABEL=94:00:5e:10:20:d4 CALDATA_OUT=$CD/ro/cal.bin sh "$O/usr/libexec/patronus/ath11k-caldata" > "$CD/out" 2>&1; then no "caldata: exit 0 on a read-only path"
  else grep -q 'not writable' "$CD/out" && ok "caldata: a read-only path fails loudly (non-zero, says why)" || { no "caldata: read-only path failed silently"; cat "$CD/out"; }; fi
else sk "caldata read-only case (running as root)"; fi
chmod 755 "$CD/ro"

# 4. patronus-flash / upgrade-install guards against synthetic images and a fake UBI
if command -v mksquashfs >/dev/null && command -v unsquashfs >/dev/null; then
  F=$W/flash; mkdir -p "$F/bin" "$F/data"; LIB=$O/usr/libexec/patronus
  cat > "$F/bin/ubinfo" <<'EOF'
#!/bin/sh
# fake ubinfo: kernel = volume 0 (42 LEBs), rootfs = volume 1 (FAKE_ROOT_LEBS), FAKE_AVAIL free LEBs
case "${2:-}" in
  -N) case "$3" in kernel) echo "Volume ID:   ${FAKE_KID:-0} (on ubi0)"; echo "Name:   kernel"; echo "Size:     42 LEBs (5332992 bytes, 5.0 MiB)";;
                   rootfs) echo "Volume ID:   ${FAKE_RID:-1} (on ubi0)"; echo "Name:   rootfs"; echo "Size:     ${FAKE_ROOT_LEBS:-160} LEBs (x bytes)";;
                   *) exit 1;; esac;;
  -a) echo "Volume ID:   0 (on ubi0)"; echo "Name:   kernel"; echo "Size:  42 LEBs";;
  *) echo "Amount of available logical eraseblocks: ${FAKE_AVAIL:-10} (1269760 bytes, 1.2 MiB)";;
esac
EOF
  chmod +x "$F/bin/ubinfo"; tr ' ' '\0' <<EOF > "$F/compat"
glinet,gl-ax1800 qcom,ipq6018
EOF
  printf 'linux,dummy-virt\0' > "$F/compat-other"
  # release signing: a throwaway "release" key (its keyring plays the box's FW_KEYRING) and a foreign key
  KR=$F/keyring.gpg
  mkkey() { g=$F/gpg-$1; mkdir -p "$g"; chmod 700 "$g"
    gpg --homedir "$g" --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "test $1 <$1@example.invalid>" ed25519 sign 1d >/dev/null 2>&1; }
  if command -v gpg >/dev/null && command -v gpgv >/dev/null; then
    mkkey rel; mkkey foreign; gpg --homedir "$F/gpg-rel" --batch --export > "$KR"
  else no "gpg/gpgv missing: the release signature cases cannot run (install gnupg gpgv)"; fi
  # sigfor KEY FILE: binary detached signature of FILE on stdout
  sigfor() { gpg --homedir "$F/gpg-$1" --batch --pinentry-mode loopback --passphrase '' --detach-sign --output - "$2" 2>/dev/null; }
  # mkimg NAME [board-in-release] [meta-board] [dist] [init]
  mkimg() { n=$1; rb=${2:-glinet,gl-ax1800}; mb=${3:-glinet,gl-ax1800}; dist=${4:-Patronus}; init=${5:-openrc}
    s=$F/src-$n; rm -rf "$s"; mkdir -p "$s/r/etc" "$s/r/usr/sbin" "$s/t/sysupgrade-glinet_gl-ax1800"
    printf 'PATRONUS_TIER=embedded\nBOARD=%s\nBUILD=%s\nINIT=%s\n' "$rb" "$n" "$init" > "$s/r/etc/patronus-release"; echo "INIT=$init" > "$s/r/etc/patronus-init"
    for b in patronus-init patronus-flash etphonehome; do echo x > "$s/r/usr/sbin/$b"; done
    T=$s/t/sysupgrade-glinet_gl-ax1800
    mksquashfs "$s/r" "$T/root" -quiet -noappend -all-root >/dev/null; printf '\320\015\376\355' > "$T/kernel"; head -c 300000 /dev/urandom >> "$T/kernel"
    cp "$s/r/etc/patronus-release" "$T/patronus-release"; [ -n "${TREL:-}" ] && sed -i "s/^BOARD=.*/BOARD=$TREL/" "$T/patronus-release"; echo "CONTROL" > "$T/CONTROL"; (cd "$T" && sha256sum kernel root > patronus.sha256)
    (cd "$s/t" && tar cf "$F/$n.tar" sysupgrade-glinet_gl-ax1800)
    # SIGN=rel (default) | foreign | none: who signs patronus.sha256 (the signature rides in the metadata as patronus_sig)
    : > "$s/sig"; [ "${SIGN:-rel}" = none ] || sigfor "${SIGN:-rel}" "$T/patronus.sha256" > "$s/sig"
    [ "$mb" = none ] || python3 - "$F/$n.tar" "$mb" "$dist" "$D/fwmeta.py" "$s/sig" <<'PY'
import base64, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("fwmeta", sys.argv[4]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
data = open(sys.argv[1], "rb").read()
meta = {"metadata_version": "1.1", "compat_version": "1.0", "supported_devices": [sys.argv[2]], "version": {"dist": sys.argv[3], "version": "t"}}
sig = open(sys.argv[5], "rb").read()
if sig:
    meta["patronus_sig"] = base64.b64encode(sig).decode()
payload = b"\0" * 8 + (json.dumps(meta) + "\n").encode()
open(sys.argv[1], "ab").write(payload + m.trailer_for(data, payload))
PY
    echo "$F/$n.tar"; }
  PF() { env PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="${COMPAT:-$F/compat}" FW_UBINFO="$F/bin/ubinfo" FW_KEYRING="${KEYRING:-$KR}" sh "$O/usr/sbin/patronus-flash" "$@"; }
  good=$(mkimg good)
  t "fwmeta.py reads the test metadata back" python3 "$D/fwmeta.py" show "$good"
  t "flash check: good image" PF check "$good"
  COMPAT=$F/compat-other tn_msg "flash check: refuses on another board" "image is for glinet,gl-ax1800" PF check "$good"
  tn_msg "flash check: refuses an image without metadata" "no image metadata" PF check "$(mkimg nometa glinet,gl-ax1800 none)"
  tn_msg "flash check: refuses metadata for another board" "does not list" PF check "$(mkimg otherboard glinet,gl-ax1800 glinet,gl-mt6000)"
  tn_msg "flash check: refuses an OpenWrt image" "not a Patronus image" PF check "$(mkimg owrt glinet,gl-ax1800 glinet,gl-ax1800 OpenWrt)"
  tn_msg "flash check: refuses a root built for another board" "not for\|not built for" PF check "$(mkimg rootboard glinet,gl-mt6000)"
  tn_msg "flash check: refuses a root image built for another board (tar says this board)" "not built for" PF check "$(TREL=glinet,gl-ax1800 mkimg rootonly glinet,gl-mt6000)"
  # release signature: unsigned, signed by another key, a modified root with a re-made patronus.sha256 (the attacker cannot re-sign),
  # a box without the keyring
  tn_msg "flash check: refuses an UNSIGNED image" "not signed" PF check "$(SIGN=none mkimg unsigned)"
  tn_msg "flash check: refuses an image signed by a foreign key" "signature check FAILED" PF check "$(SIGN=foreign mkimg foreign)"
  tm=$F/tampered.tar; rm -rf "$F/tt"; mkdir -p "$F/tt"; tar xf "$good" -C "$F/tt" 2>/dev/null
  printf 'evil' >> "$F/tt/sysupgrade-glinet_gl-ax1800/root"; (cd "$F/tt/sysupgrade-glinet_gl-ax1800" && sha256sum kernel root > patronus.sha256)
  (cd "$F/tt" && tar cf "$tm" sysupgrade-glinet_gl-ax1800); python3 - "$good" "$tm" "$D/fwmeta.py" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("fwmeta", sys.argv[3]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
meta = m.read(open(sys.argv[1], "rb").read())          # the good image's metadata, signature included
data = open(sys.argv[2], "rb").read(); payload = b"\0" * 8 + (json.dumps(meta) + "\n").encode()
open(sys.argv[2], "ab").write(payload + m.trailer_for(data, payload))
PY
  tn_msg "flash check: refuses a TAMPERED image (root changed, sha256 re-made, old signature)" "signature check FAILED" PF check "$tm"
  KEYRING=$F/no-such-keyring tn_msg "flash check: refuses when the box has no release keyring" "no release signing key" PF check "$good"
  tn_msg "flash check: refuses a raw squashfs" "no image metadata\|not a tar" PF check "$F/src-good/t/sysupgrade-glinet_gl-ax1800/root"
  c=$F/corrupt.tar; cp "$good" "$c"; python3 - "$c" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); i = b.find(b"hsqs"); b[i + 600] ^= 0xFF; open(p, "wb").write(bytes(b))
PY
  tn_msg "flash check: refuses a corrupt root (sha256)" "sha256" PF check "$c"
  x=$F/extra.tar; rm -rf "$F/xx"; cp -r "$F/src-nometa/t" "$F/xx"; echo e > "$F/xx/sysupgrade-glinet_gl-ax1800/extra"
  (cd "$F/xx" && tar cf "$x" sysupgrade-glinet_gl-ax1800); python3 "$D/fwmeta.py" add "$x" glinet,gl-ax1800 --version t
  tn_msg "flash check: refuses an unexpected tar member" "unexpected tar member" PF check "$x"
  if env FAKE_KID=0 FAKE_RID=0 FAKE_ROOT_LEBS=160 PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="$F/compat" FW_UBINFO="$F/bin/ubinfo" FW_KEYRING="$KR" sh "$O/usr/sbin/patronus-flash" check "$good" >"$W/out" 2>&1; then
    no "flash check: accepted volume ids kernel=0 rootfs=0"; else grep -q "rootfs=0" "$W/out" && ok "flash check: refuses a UBI whose rootfs is not volume 1" || { no "flash check: wrong volume ids, wrong message"; cat "$W/out"; }; fi
  # a root that needs more LEBs than volume + free
  big=$(mkimg big); if env FAKE_ROOT_LEBS=0 FAKE_AVAIL=0 PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="$F/compat" FW_UBINFO="$F/bin/ubinfo" FW_KEYRING="$KR" sh "$O/usr/sbin/patronus-flash" check "$big" >"$W/out" 2>&1; then
    no "flash check: accepted an image that does not fit"; else grep -q "more LEBs" "$W/out" && ok "flash check: refuses an image that does not fit the UBI" || { no "flash check: no-room case, wrong message"; cat "$W/out"; }; fi
  t "flash sysupgrade: stages a good image" PF sysupgrade "$good"
  [ -f "$F/data/.upgrade/ready" ] && [ -s "$F/data/.upgrade/root" ] && [ ! -e "$F/data/.upgrade.new" ] && ok "staged: ready marker + parts" || no "staged layout wrong: $(ls -a "$F/data" "$F/data/.upgrade" 2>&1)"
  tn_msg "flash sysupgrade: refuses a second staging" "already staged" PF sysupgrade "$good"
  UV() { env PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="${COMPAT:-$F/compat}" FW_UBINFO="$F/bin/ubinfo" FW_KEYRING="$KR" sh "$LIB/upgrade-install" verify; }
  t "upgrade-install verify: accepts the staged image (early boot re-check)" UV
  COMPAT=$F/compat-other tn "upgrade-install verify: refuses on another board" UV
  [ -d "$F/data/.upgrade-rejected" ] && [ ! -e "$F/data/.upgrade" ] && ok "rejected upgrade moved aside (normal boot goes on)" || no "rejected upgrade not moved aside"
  t "flash sysupgrade: stage again after a rejection" PF sysupgrade "$good"
  [ -s "$F/data/.upgrade/patronus.sha256.sig" ] && ok "staged: the release signature is kept for the boot-time re-check" || no "staged upgrade has no patronus.sha256.sig"
  printf 'x' >> "$F/data/.upgrade/root"; tn "upgrade-install verify: refuses a staged root changed after staging" UV
  t "flash sysupgrade: stage again (2)" PF sysupgrade "$good"
  printf 'x' >> "$F/data/.upgrade/root"; (cd "$F/data/.upgrade" && sha256sum kernel root > patronus.sha256)
  : > "$F/data/upgrade.log"; tn "upgrade-install verify: refuses a staged root + re-made sha256 (release signature)" UV
  grep -q "signature check FAILED" "$F/data/upgrade.log" && ok "upgrade.log names the failed release signature" || { no "upgrade.log lacks the signature failure"; cat "$F/data/upgrade.log"; }
  t "flash sysupgrade: stage again (3)" PF sysupgrade "$good"; rm -f "$F/data/.upgrade/patronus.sha256.sig"
  : > "$F/data/upgrade.log"; tn "upgrade-install verify: refuses a staged upgrade without its signature" UV
  grep -q "not signed" "$F/data/upgrade.log" && ok "upgrade.log says the staged upgrade is not signed" || { no "upgrade.log lacks 'not signed'"; cat "$F/data/upgrade.log"; }
  t "flash cancel" PF cancel; [ ! -e "$F/data/.upgrade" ] && ok "cancel removed the staged upgrade" || no "cancel left the staged upgrade"
  tn_msg "flash: unknown command shows usage" "patronus-flash check" PF frobnicate
else sk "patronus-flash image cases (no mksquashfs/unsquashfs)"; fi

# 5. UBI layout + NAND budget
eval "$(python3 "$ROOT/ci/hw-profile/hwprofile.py" env "$ROOT/profiles/hw/qualcommax-gl-ax1800.toml")"
. "$D/stock.pin"
[ "$HW_OPENWRT_STOCK_SHA256" = "$OWRT_SYSUPGRADE_SHA256" ] && ok "profile stock_sha256 = stock.pin" || no "profile stock_sha256 != stock.pin"
[ "$HW_STOCK_SYSUPGRADE" = "$OWRT_SYSUPGRADE" ] && ok "profile stock image name = stock.pin" || no "profile stock image name != stock.pin ($HW_STOCK_SYSUPGRADE)"
[ "$((HW_NAND_PEB_BYTES - 2 * HW_NAND_MIN_IO))" = "$HW_NAND_LEB_BYTES" ] && ok "profile LEB = PEB - 2 pages" || no "profile LEB inconsistent"
: > "$W/k"; truncate -s 5305856 "$W/k"; : > "$W/r"; truncate -s 25000000 "$W/r"
out=$(sh "$D/nand-budget.sh" "$W/r" "$W/k"); rc=$?
[ $rc = 0 ] && case "$out" in *"920 PEBs - 24 reserved"*"kernel 42 "*) true;; *) false;; esac && ok "nand-budget: 25 MB root fits, stock kernel = 42 LEBs" || no "nand-budget: $out"
truncate -s 100000000 "$W/r"; sh "$D/nand-budget.sh" "$W/r" "$W/k" >/dev/null 2>&1; [ $? = 1 ] && ok "nand-budget: 100 MB root is over budget" || no "nand-budget: 100 MB root not rejected"
if command -v ubinize >/dev/null; then
  printf '\320\015\376\355' > "$W/k"; head -c 400000 /dev/zero >> "$W/k"; printf 'hsqs' > "$W/r"; head -c 900000 /dev/zero >> "$W/r"
  mkcfg() { printf '[kernel]\nmode=ubi\nvol_id=%s\nvol_type=dynamic\nvol_name=kernel\nimage=%s\n[rootfs]\nmode=ubi\nvol_id=%s\nvol_type=dynamic\nvol_name=rootfs\nimage=%s\n[rootfs_data]\nmode=ubi\nvol_id=2\nvol_type=dynamic\nvol_name=rootfs_data\nvol_size=1MiB\n%s\n' "$1" "$W/k" "$2" "$W/r" "$3" > "$W/u.cfg"; }
  mkcfg 0 1 vol_flags=autoresize; ubinize -o "$W/good.ubi" -p 131072 -m 2048 -s 2048 "$W/u.cfg" >/dev/null 2>&1
  t "ubi-layout: ubinize image with the board layout passes" python3 "$D/ubi-layout.py" check "$W/good.ubi"
  t "nand-budget: parts + their factory.ubi agree" sh "$D/nand-budget.sh" "$W/r" "$W/k" "$W/good.ubi"
  mkcfg 1 0 vol_flags=autoresize; ubinize -o "$W/swap.ubi" -p 131072 -m 2048 -s 2048 "$W/u.cfg" >/dev/null 2>&1
  tn_msg "ubi-layout: kernel/rootfs ids swapped is rejected" "has id" python3 "$D/ubi-layout.py" check "$W/swap.ubi"
  mkcfg 0 1 ""; ubinize -o "$W/noar.ubi" -p 131072 -m 2048 -s 2048 "$W/u.cfg" >/dev/null 2>&1
  tn_msg "ubi-layout: rootfs_data without autoresize is rejected" "autoresize" python3 "$D/ubi-layout.py" check "$W/noar.ubi"
  ubinize -o "$W/sub.ubi" -p 131072 -m 2048 -s 512 "$W/u.cfg" >/dev/null 2>&1 && mkcfg 0 1 vol_flags=autoresize && ubinize -o "$W/sub.ubi" -p 131072 -m 2048 -s 512 "$W/u.cfg" >/dev/null 2>&1 \
    && tn_msg "ubi-layout: a sub-page VID offset (wrong LEB size) is rejected" "leb is" python3 "$D/ubi-layout.py" check "$W/sub.ubi"
else sk "ubinize image cases (no ubinize)"; fi

# 4. package-managed accounts (shared with the Slate)
if out=$(sh "$D/../../embedded-common/tests/accounts-sync.sh" 2>&1); then ok "accounts-sync: $(echo "$out" | tail -1)"; else no "accounts-sync tests"; echo "$out" | grep FAIL | sed 's/^/    /'; fi

echo "ax1800 tooling tests: $pass passed, $failn failed, $skip skipped"
[ "$failn" = 0 ]
