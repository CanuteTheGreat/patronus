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

# 1b. the scripts the boot path runs by path must be executable in the tree (ap-coord was committed 0644 once: `ap` tests -x)
for f in "$O"/usr/libexec/patronus/*; do case "${f##*/}" in fwcheck.sh) continue;; esac
  [ -x "$f" ] && ok "executable: ${f#$D/}" || no "not executable: ${f#$D/}"; done

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
           lib/firmware/IPQ6018/m3_fw.mdt lib/firmware/regulatory.db usr/libexec/patronus/etph-run usr/libexec/patronus/ap-guest usr/libexec/patronus/ap-coord usr/libexec/patronus/ap-steer usr/libexec/patronus/ap-chan usr/libexec/patronus/ap-event usr/libexec/patronus/wifi-guard usr/libexec/patronus/ap-addr \
           usr/libexec/patronus/leds usr/libexec/patronus/restart-schedule usr/libexec/patronus/scheduled-restart usr/bin/gpgv usr/bin/ssl_client usr/libexec/patronus/accounts-sync \
           usr/sbin/patronus-guard usr/bin/fw_printenv etc/patronus/boot-guard.board etc/patronus/boot-guard.conf; do : > "$r/$f"; chmod +x "$r/$f"; done
  ln -s fw_printenv "$r/usr/bin/fw_setenv"
  ln -s patronus-cli "$r/usr/bin/patronus-web"; cp "$O/etc/patronus/board.sh" "$O/etc/patronus/embedded.env" "$r/etc/patronus/"
  cp "$O/usr/libexec/patronus/early" "$O/usr/libexec/patronus/ath11k-caldata" "$r/usr/libexec/patronus/"
  for b in ubinfo ubimkvol ubirmvol ubirsvol ubiupdatevol ubiblock iw ip sha256sum pivot_root; do ln -s /bin/busybox "$r/usr/sbin/$b"; done
  echo x > "$r/lib/modules/6.12.112/modules.dep"; for m in ath11k_ahb qca-nss-dp qca-ssdk mac80211 cfg80211 nf_tables nfnetlink_log nft_reject_inet nf_conntrack; do : > "$r/lib/modules/6.12.112/$m.ko"; done
  # the rebuilt ath11k (wifi-kmods, docs 12.20): carries the airtime queue limit series' debugfs text
  printf 'x\nPending Tx MSDUs:\n' > "$r/lib/modules/6.12.112/ath11k.ko"; mkdir -p "$r/usr/share/patronus"; echo TAG=test > "$r/usr/share/patronus/wifi-kmods.manifest"
  printf "patronus-xbss\npatronus_authfail_max\n" > "$r/usr/sbin/hostapd"
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
r=$(mkroot stockath); : > "$r/lib/modules/6.12.112/ath11k.ko"; tn "check-rootfs: rejects OpenWrt's stock ath11k (no airtime queue limit)" $CR "$r"
WIFI_KMODS=stock t "check-rootfs: WIFI_KMODS=stock builds the stock modules on purpose" $CR "$r"
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
r=$(mkroot oldhostapd); echo patronus-xbss > "$r/usr/sbin/hostapd"; tn_msg "check-rootfs: rejects a Patronus hostapd without the authentication backoff (rendered configs would be refused)" 'no patronus_authfail' $CR "$r"
r=$(mkroot steer644); chmod 644 "$r/usr/libexec/patronus/ap-steer"; tn_msg "check-rootfs: rejects a non-executable ap-steer (ap would skip it silently)" 'ap-steer is not executable' $CR "$r"
r=$(mkroot chan644); chmod 644 "$r/usr/libexec/patronus/ap-chan"; tn_msg "check-rootfs: rejects a non-executable ap-chan (ap-coord would skip it silently)" 'ap-chan is not executable' $CR "$r"
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
# channel plan defaults: no channel in ap.env = ACS on both radios, 2.4 GHz only among 1/6/11, 5 GHz without DFS
s24() { sed -n "s/^$2=//p" "$A/$1/ap24.conf" 2>/dev/null | head -1; }
aprender dflt "$TWO"
if [ "$(seg dflt channel)" = 0 ] && [ "$(s24 dflt channel)" = 0 ] && [ "$(s24 dflt chanlist)" = "1 6 11" ] && [ "$(seg dflt chanlist)" = "36 40 44 48 149 153 157 161" ] \
  && [ "$(seg dflt acs_exclude_dfs)" = 1 ] && [ -z "$(s24 dflt acs_exclude_dfs)" ] && [ "$(seg dflt acs_num_scans)" = 5 ] && [ "$(s24 dflt acs_num_scans)" = 5 ]; then
  ok "ap: default channel plan = ACS on both radios (2.4 GHz among 1/6/11, 5 GHz 80 MHz blocks 36-48/149-161: no DFS, no 165-177, 5 survey rounds)"
else no "ap: default channel plan: $(grep -hE '^(channel|chanlist|acs_)' "$A/dflt/ap5.conf" "$A/dflt/ap24.conf" | tr '\n' ' ')"; cat "$A/dflt.out"; fi
aprender dfs "$TWO
AP_DFS=1 AP_CHANLIST5=\"36 40 44 48 52 56 60 150\" AP_CHANLIST24= AP_ACS_SCANS=3"
[ "$(seg dfs acs_exclude_dfs)" = 0 ] && [ "$(seg dfs chanlist)" = "36 40 44 48" ] && grep -q 'AP_CHANLIST5: 150 is not a channel' "$A/dfs.out" \
  && [ -z "$(s24 dfs chanlist)" ] && [ "$(seg dfs acs_num_scans)" = 3 ] \
  && ok "ap: AP_DFS=1 lets ACS use DFS channels; AP_CHANLIST5 keeps valid channels only; empty 2.4 list = all; AP_ACS_SCANS" \
  || { no "ap: DFS/chanlist: $(grep -hE '^(chanlist|acs_)' "$A/dfs/ap5.conf" "$A/dfs/ap24.conf" | tr '\n' ' ')"; cat "$A/dfs.out"; }
# hostapd's ACS checks only the primary against chanlist: at 80 MHz a lone 165 would run 165-177 (U-NII-4), and an
# incomplete block (52-60 without 64) would run on 64 too; only primaries whose whole block is allowed are offered
aprender dfsall "$TWO
AP_DFS=1"
[ "$(seg dfsall chanlist)" = "36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161" ] \
  && ok "ap: AP_DFS=1 + empty list = every non-U-NII-4 80 MHz block incl. DFS" || no "ap: DFS default list: $(seg dfsall chanlist)"
aprender unii4 "$TWO
AP_UNII4=1"
[ "$(seg unii4 chanlist)" = "36 40 44 48 149 153 157 161 165 169 173 177" ] && ok "ap: AP_UNII4=1 adds the 165-177 block" || no "ap: U-NII-4: $(seg unii4 chanlist)"
aprender w40 "$TWO
AP_HT5=40 AP_CHANLIST5=\"36 40 44 157 161 165\""
[ "$(seg w40 chanlist)" = "36 40 157 161" ] && ok "ap: 40 MHz: only channels whose pair is allowed (44 without 48, 165 without 169 dropped)" || no "ap: 40 MHz list: $(seg w40 chanlist)"
aprender w20 "$TWO
AP_HT5=20"
[ "$(seg w20 chanlist)" = "36 40 44 48 149 153 157 161 165" ] && ok "ap: 20 MHz default list includes 165" || no "ap: 20 MHz list: $(seg w20 chanlist)"
aprender fixed "$TWO
AP_CHAN5=149 AP_CHAN24=6"
! grep -qE '^(acs_|chanlist=)' "$A/fixed/ap5.conf" "$A/fixed/ap24.conf" && ok "ap: a fixed channel writes no ACS settings" || no "ap: ACS lines with fixed channels"

# 3a. channel coordination between access points (docs 12.17): ap-coord parse/busy/plan/check and the ACS list in the render
CO=$O/usr/libexec/patronus/ap-coord; FX=$D/tests/fixtures/scan-coord.txt
printf '. %s\nAP_SSIDS="m g"\nSSID_m="Plat 9" KEY_m=examplekey\nSSID_g=Hogs KEY_g=guestkey99\n' "$O/etc/patronus/board.sh" > "$A/co-board.sh"
co() { AP_BOARD=${CB:-$A/co-board.sh} AP_RENDER_OUT=$A/co sh "$CO" "$@"; }
mkdir -p "$A/co"
[ "$(co parse < "$FX" | head -1)" = "06:aa:bb:cc:11:11 5180 -48 above 80 42 Plat_9" ] \
  && ok "ap-coord: parses iw scan output (primary frequency, signal, HT offset, VHT width + centre, SSID)" || no "ap-coord parse: $(co parse < "$FX" | head -2)"
[ "$(co parse < "$FX" | sed -n 6p)" = "12:11:22:33:44:55 5805 -50 none 20 0 -" ] \
  && ok "ap-coord: a 20 MHz BSS without VHT, a hidden SSID is '-'" || no "ap-coord parse hidden: $(co parse < "$FX" | sed -n 6p)"
[ "$(co parse < "$FX" | co covered | head -1)" = "06:aa:bb:cc:11:11 36 40 44 48" ] && ok "ap-coord: an 80 MHz BSS covers its four 20 MHz channels" || no "ap-coord covered: $(co parse < "$FX" | co covered | head -1)"
b5=$(co parse < "$FX" | co busy 5); [ "$b5" = "36 40 44 48" ] \
  && ok "ap-coord: peers = BSSes with this unit's SSIDs; other networks, 2.4 GHz entries and peers weaker than -90 dBm are ignored" || no "ap-coord busy 5: $b5"
b24=$(co parse < "$FX" | co busy 24); [ "$b24" = "2 3 4 5 6 7 8 9 10" ] && ok "ap-coord: a 2.4 GHz peer on channel 6 overlaps channels 2-10" || no "ap-coord busy 24: $b24"
printf '. %s\nAP_SSIDS="m g"\nSSID_m="Plat 9" KEY_m=examplekey\nSSID_g=Hogs KEY_g=guestkey99\nAP_COORD_PEERS="ff:11:22:33:44:55"\n' "$O/etc/patronus/board.sh" > "$A/co-board-peers.sh"
b5h=$(co parse < "$FX" | CB=$A/co-board-peers.sh co busy 5); [ "$b5h" = "36 40 44 48 161" ] \
  && ok "ap-coord: AP_COORD_PEERS names a unit by any of its BSSIDs (a hidden-SSID peer) and adds its channels" || no "ap-coord peers: $b5h"
aprender co1 "$TWO"
echo "36 40 44 48" > "$A/co1/coord-5"; aprender_keep() { AP_BOARD=$A/board-$1.sh AP_RENDER_OUT=$A/$1 AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render >"$A/$1.out" 2>&1; }
aprender_keep co1
[ "$(seg co1 chanlist)" = "149 153 157 161" ] && grep -q 'left out of the ACS list' "$A/co1.out" \
  && ok "ap: the 5 GHz ACS list drops the block another unit is on (36-48) and keeps 149-161" || no "ap: coordinated 5 GHz list: $(seg co1 chanlist)"; cat "$A/co1.out" | sed 's/^/    /' | grep -v 'left out' | head -3
printf '36 40 44 48 149 153 157 161\n' > "$A/co1/coord-5"; aprender_keep co1
[ "$(seg co1 chanlist)" = "36 40 44 48 149 153 157 161" ] && grep -q 'ACS decides alone' "$A/co1.out" \
  && ok "ap: when every block overlaps another unit the list is left alone (ACS decides)" || no "ap: no free block: $(seg co1 chanlist)"
printf '1 2 3 4 5 6 7 8 9\n' > "$A/co1/coord-24"; echo "36 40 44 48" > "$A/co1/coord-5"; aprender_keep co1
[ "$(s24 co1 chanlist)" = "11" ] && ok "ap: the 2.4 GHz list (1 6 11) loses 1 and 6 next to a unit on channel 4/5" || no "ap: 2.4 GHz coordinated: $(s24 co1 chanlist)"
printf '. %s\nAP_COORD5=0 AP_COORD24=0\n' "$O/etc/patronus/board.sh" > "$A/board-co2.sh"; mkdir -p "$A/co2"; echo "36 40 44 48" > "$A/co2/coord-5"
AP_BOARD=$A/board-co2.sh AP_RENDER_OUT=$A/co2 AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/co2.out" 2>&1
printf 'AP_SSIDS="m"\nSSID_m=Example KEY_m=examplekey\n' >> "$A/board-co2.sh"; AP_BOARD=$A/board-co2.sh AP_RENDER_OUT=$A/co2 AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/co2.out" 2>&1
[ "$(seg co2 chanlist)" = "36 40 44 48 149 153 157 161" ] && ok "ap: AP_COORD5=0 switches the coordination off per band" || no "ap: AP_COORD5=0: $(seg co2 chanlist)"
# plan from a canned scan
rm -f "$A/co/coord-5" "$A/co/coord-24"
AP_COORD_SCAN_FILE=$FX co plan 5 phy0 > "$A/co-plan.out" 2>&1; [ "$(cat "$A/co/coord-5" 2>/dev/null)" = "36 40 44 48" ] && ok "ap-coord plan 5: writes the peers' channels for the renderer" || { no "ap-coord plan: $(cat "$A/co/coord-5" 2>&1)"; cat "$A/co-plan.out"; }
AP_COORD_SCAN_FILE=/dev/null co plan 5 phy0 > "$A/co-plan.out" 2>&1; [ ! -e "$A/co/coord-5" ] && ok "ap-coord plan 5: nobody heard = no file (a stale plan is removed)" || no "ap-coord plan left a stale file"
printf '. %s\nAP_CHAN5=149\n' "$O/etc/patronus/board.sh" > "$A/co-board-fixed.sh"
CB=$A/co-board-fixed.sh AP_COORD_SCAN_FILE=$FX co plan 5 phy0 > /dev/null 2>&1; [ ! -e "$A/co/coord-5" ] && ok "ap-coord plan: a fixed channel is not planned" || no "ap-coord plan wrote for a fixed channel"
# check: who moves. Own radio = 5 GHz ACS on 44/80 (36-48), the peer BSSes 06:aa:bb:cc:11:11 / 0a:aa:bb:cc:11:11 (key aa:bb:cc:11:11)
fakeap=$A/fake-ap; printf '#!/bin/sh\necho "$@" >> %s/fake-ap.log\n' "$A" > "$fakeap"; chmod +x "$fakeap"
printf 'state=ENABLED\nfreq=5220\nsecondary_channel=-1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=42\n' > "$A/co-status"
cocheck() { # OWN-PHY-MAC -> runs `check 5` with the fixture scan; prints restart log
  rm -f "$A/fake-ap.log"; mkdir -p "$A/co3"; printf 'channel=0\ninterface=wl5-m\nbssid=%s\n' "$1" > "$A/co3/ap5.conf"
  AP_BOARD=$A/co-board.sh AP_RENDER_OUT=$A/co3 AP_COORD_AP=$fakeap AP_COORD_SCAN_FILE=$FX AP_COORD_STATUS_FILE=$A/co-status sh "$CO" check 5 "${2:-}" > "$A/co-check.out" 2>&1; cat "$A/fake-ap.log" 2>/dev/null; }
r=$(cocheck 02:cc:00:00:00:99 now); [ "$r" = "restart-band 5" ] && ok "ap-coord check: overlapping the unit with the lower key -> this (higher) unit restarts its 5 GHz radio" || { no "ap-coord check (higher key): '$r'"; cat "$A/co-check.out"; }
r=$(cocheck 02:00:00:00:00:01 now); [ -z "$r" ] && grep -q 'lower key and moves' "$A/co-check.out" && ok "ap-coord check: the unit with the lower key stays where it is" || { no "ap-coord check (lower key): '$r'"; cat "$A/co-check.out"; }
printf 'state=ENABLED\nfreq=5745\nsecondary_channel=1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=155\n' > "$A/co-status"
r=$(cocheck 02:cc:00:00:00:99 now); [ -z "$r" ] && grep -q 'no other access point shares' "$A/co-check.out" && ok "ap-coord check: disjoint blocks (149-161 vs 36-48) = nothing happens" || { no "ap-coord check disjoint: '$r'"; cat "$A/co-check.out"; }
printf 'state=ENABLED\nfreq=5220\nsecondary_channel=-1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=42\n' > "$A/co-status"
mkdir -p "$A/bin"; printf '#!/bin/sh\necho "Station aa:bb"\n' > "$A/bin/iw"; chmod +x "$A/bin/iw"
r=$(PATH=$A/bin:$PATH AP_COORD_QUIET=1-5 AP_COORD_NOW=14 cocheck 02:cc:00:00:00:99); [ -z "$r" ] && grep -q 'moving later' "$A/co-check.out" \
  && ok "ap-coord check: stations connected + outside the quiet hours = the move waits" || { no "ap-coord quiet hours: '$r'"; cat "$A/co-check.out"; }
r=$(PATH=$A/bin:$PATH AP_COORD_QUIET=1-5 AP_COORD_NOW=03 cocheck 02:cc:00:00:00:99); [ "$r" = "restart-band 5" ] && ok "ap-coord check: inside the quiet hours it restarts the radio" || no "ap-coord quiet window: '$r'"
AP_COORD_SCAN_FILE=$FX co plan 5 phy0 > /dev/null 2>&1; [ -s "$A/co/peers-5" ] && ok "ap-coord plan: records the peers it heard (ap-steer knows another access point exists)" || no "ap-coord plan wrote no peers-5"
AP_COORD_SCAN_FILE=/dev/null co plan 5 phy0 > /dev/null 2>&1; [ ! -e "$A/co/peers-5" ] && ok "ap-coord plan: no peer heard = no peers file" || no "ap-coord plan left a stale peers-5"
# the kernel can cut a scan short (iw: exit 0, no message, the cached list): the pre-start scan repeats until two in a row agree
# (hwsim: the first scan of a band ended after 0.1 s, a peer on channel 11 was missed, a leftover of another network made the list
# look real)
mkdir -p "$A/bin-ab"; printf '%s\n' '#!/bin/sh' 'case "$*" in *" scan "*|*" scan") n=$(cat "$AB_N" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$AB_N"' \
  '  if [ -n "${AB_ALT:-}" ]; then printf "BSS 06:de:ad:00:00:%02d(on wl24-coord)\n\tfreq: 2412.0\n\tsignal: -30.00 dBm\n\tSSID: leftover\n" $n' \
  '  elif [ $n -le ${AB_CUT:-1} ]; then printf "BSS 06:de:ad:00:00:01(on wl24-coord)\n\tfreq: 2412.0\n\tsignal: -30.00 dBm\n\tSSID: leftover\n"; else printf "BSS 06:de:ad:00:00:01(on wl24-coord)\n\tfreq: 2412.0\n\tsignal: -30.00 dBm\n\tSSID: leftover\nBSS 06:aa:bb:cc:22:22(on wl24-coord)\n\tfreq: 2462.0\n\tsignal: -40.00 dBm\n\tSSID: Plat 9\n"; fi;; esac' 'exit 0' > "$A/bin-ab/iw"
printf '#!/bin/sh\nexit 0\n' > "$A/bin-ab/ip"; chmod +x "$A/bin-ab/iw" "$A/bin-ab/ip"
rm -f "$A/co/coord-24" "$A/ab-n"; PATH=$A/bin-ab:$PATH AB_N=$A/ab-n AP_CHAN_SMART24=0 co plan 24 phy1 > "$A/co-abort.out" 2>&1
[ "$(cat "$A/co/coord-24" 2>/dev/null)" = "7 8 9 10 11 12 13 14" ] && [ "$(cat "$A/ab-n")" = 3 ] \
  && ok "ap-coord plan: a scan the kernel cut short (only a leftover heard) is repeated until two agree; the peer on channel 11 is found" || { no "ap-coord cut-short scan: '$(cat "$A/co/coord-24" 2>&1)' scans=$(cat "$A/ab-n" 2>&1)"; cat "$A/co-abort.out"; }
rm -f "$A/co/coord-24" "$A/ab-n"; PATH=$A/bin-ab:$PATH AB_N=$A/ab-n AB_ALT=1 AP_COORD_SCAN_TRIES=3 AP_CHAN_SMART24=0 co plan 24 phy1 > "$A/co-abort.out" 2>&1
[ "$(cat "$A/ab-n")" = 3 ] && grep -q 'kept hearing different' "$A/co-abort.out" \
  && ok "ap-coord plan: scans that never agree stop after AP_COORD_SCAN_TRIES and say so" || { no "ap-coord scan limit: scans=$(cat "$A/ab-n" 2>&1)"; cat "$A/co-abort.out"; }
rm -f "$A/co/coord-24" "$A/ab-n"; PATH=$A/bin-ab:$PATH AB_N=$A/ab-n AB_CUT=0 AP_CHAN_SMART24=0 co plan 24 phy1 > "$A/co-abort.out" 2>&1
[ "$(cat "$A/ab-n")" = 2 ] && ok "ap-coord plan: a first scan that already hears everything costs one extra scan, not more" || no "ap-coord stable scan count: $(cat "$A/ab-n" 2>&1)"

# 3a2. channel choice by measurement (docs 12.19): ap-chan scoring, the start-time pick through ap-coord plan (serialized
#      between units), the nightly re-check with hysteresis + agreeing samples, the move by CSA, and the history
CH=$O/usr/libexec/patronus/ap-chan; C2=$A/ch; mkdir -p "$C2/run" "$C2/db"
chx() { AP_BOARD=${CHB:-$A/co-board.sh} AP_RENDER_OUT=$C2/run AP_CHAN_DB=$C2/db AP_SYSFS=$A/sys AP_CHAN_AP=$O/usr/libexec/patronus/ap \
  AP_CHAN_COORD=$CO AP_COORD_CHAN=$CH AP_CHAN_NOW=${NOW:-1000000} AP_CHAN_NOSLEEP=1 AP_COORD_NOSLEEP=1 sh "$@"; }
# score: 5 GHz, 80 MHz. Block 36-48 busy 40-50 % with a strong neighbour, block 149-161 5 % with one neighbour -> 149 first
printf 'S 36 400 200\nS 40 400 160\nS 44 400 160\nS 48 400 160\nS 149 400 20\nS 153 400 20\nS 157 400 20\nS 161 400 20\nB 3c:de:ad:be:ef:01 5180 -60 above 80 42 Neighbour\nB 3c:de:ad:be:ef:02 5745 -70 above 80 155 Other\n' > "$C2/m5"
sc=$(chx "$CH" score 5 "36 40 44 48 149 153 157 161" < "$C2/m5")
[ "$(echo "$sc" | head -1)" = "149 7.0 5.0 1" ] && [ "$(echo "$sc" | grep '^36 ')" = "36 46.0 44.0 1" ] \
  && ok "ap-chan score: busy % from comparable samples (primary counted twice) + 2 per access point heard; the quiet block wins" \
  || { no "ap-chan score 5 GHz"; echo "$sc" | sed 's/^/    /'; }
sc=$(chx "$CH" score 5 "36 40 44 48 149 153 157 161" 153 < "$C2/m5")
[ "$(echo "$sc" | head -1 | cut -d' ' -f1)" = 153 ] && ok "ap-chan score: on equal scores the channel in use comes first (nothing to gain by moving)" \
  || { no "ap-chan score tie"; echo "$sc" | head -3 | sed 's/^/    /'; }
# 2.4 GHz: equal busy everywhere; a strong neighbour on 3 overlaps 1 (2 away) and 6 (3 away); a co-channel one on 11 costs 2
printf 'S 1 400 120\nS 6 400 120\nS 11 400 120\nB 3c:00:00:00:00:03 2422 -62 none 20 0 Near\nB 3c:00:00:00:00:0b 2462 -70 none 20 0 Co\nB 3c:00:00:00:00:0c 2462 -95 none 20 0 TooFar\n' > "$C2/m24"
sc=$(chx "$CH" score 24 "1 6 11" < "$C2/m24" | tr '\n' '|')
[ "$sc" = "11 32.0 30.0 1|6 34.0 30.0 0|1 36.0 30.0 0|" ] \
  && ok "ap-chan score 2.4 GHz: partly overlapping strong neighbours cost by overlap, co-channel ones by count, weaker than -90 dBm ignored" \
  || no "ap-chan score 2.4 GHz: $sc"
# the history line is valid JSON with every field
chx "$CH" note 5 start "unit test" > /dev/null; python3 -c "import json,sys; [json.loads(l) for l in open(sys.argv[1])]" "$C2/db/history" \
  && ok "ap-chan history: one JSON object per line" || { no "ap-chan history JSON"; cat "$C2/db/history"; }
# start: ap-coord plan scans, ap-chan measures (canned scan + survey) and pins its best candidate for the renderer
printf 'Survey data from wl5-coord\n\tfrequency:\t\t\t5180 MHz\n\tchannel active time:\t\t105 ms\n\tchannel busy time:\t\t80 ms\n' > "$C2/survey"
for c in 40 44 48 149 153 157 161 165; do printf 'Survey data from wl5-coord\n\tfrequency:\t\t\t%s MHz\n\tchannel active time:\t\t105 ms\n\tchannel busy time:\t\t%s ms\n' $((5000 + c * 5)) $([ $c -ge 149 ] && echo 10 || echo 60) >> "$C2/survey"; done
sed 's/busy time:\t\t60 ms/busy time:\t\t1 ms/' "$C2/survey" > "$C2/survey2b"
rm -f "$C2/db/history"
AP_COORD_SCAN_FILE=$FX AP_CHAN_SCAN_FILE=$FX AP_CHAN_SURVEY_FILE=$C2/survey chx "$CO" plan 5 phy0 > "$C2/plan.out" 2>&1
# the peer (Plat 9) sits on 36-48: not a candidate; NeighbourNet on 149-161 (-60) and a hidden BSS on 161 cost points
[ "$(cat "$C2/run/coord-5" 2>/dev/null)" = "36 40 44 48" ] && [ "$(cat "$C2/run/chan-5" 2>/dev/null)" = 149 ] \
  && grep -q '"event":"start"' "$C2/db/history" && grep -q '"chosen":149' "$C2/run/chan-status-5" \
  && ok "ap-coord plan + ap-chan pick: the peer's block is out, the measured best channel (149) is pinned, history + status written" \
  || { no "ap-chan start pick: chan-5=$(cat "$C2/run/chan-5" 2>&1)"; cat "$C2/plan.out" "$C2/run/chan-score-5" 2>/dev/null | sed 's/^/    /'; }
# a unit of this network that ap-coord's own scan missed but ap-chan's measurement hears: its block is added to
# ap-coord's list and never picked (found on hardware: the other unit's 2.4 GHz channel was chosen)
: > "$C2/scan-none"; rm -f "$C2/run/coord-5" "$C2/run/chan-5"
AP_COORD_SCAN_FILE=$C2/scan-none AP_CHAN_SCAN_FILE=$FX AP_CHAN_SURVEY_FILE=$C2/survey2b chx "$CO" plan 5 phy0 > "$C2/planm.out" 2>&1
[ "$(cat "$C2/run/coord-5" 2>/dev/null)" = "36 40 44 48" ] && [ "$(cat "$C2/run/chan-5" 2>/dev/null)" = 149 ] && grep -q 'heard on channels 36 40 44 48' "$C2/planm.out" \
  && ok "ap-chan: a unit of this network heard only by the measurement is avoided (its block joins ap-coord's list)" \
  || { no "ap-chan peer merge: coord-5='$(cat "$C2/run/coord-5" 2>&1)' chan-5='$(cat "$C2/run/chan-5" 2>&1)'"; cat "$C2/planm.out" | sed 's/^/    /'; }
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['candidates'] and d['reason'].startswith('channel 149')" "$C2/run/chan-status-5" \
  && ok "ap-chan status: JSON with the reason and every candidate (Wi-Fi page 'why this channel')" || { no "ap-chan status JSON"; cat "$C2/run/chan-status-5"; }
grep -q '^peers-5\|aa:bb:cc:11:11' "$C2/db/peers-5" && ok "ap-chan remember: the unit heard is recorded for the next start's order" || { no "ap-chan remember"; cat "$C2/db/peers-5" 2>&1; }
printf '. %s\n%s\n' "$A/co-board.sh" "$TWO" > "$A/board-chp.sh"; mkdir -p "$A/chp"; cp "$C2/run/chan-5" "$C2/run/coord-5" "$A/chp/"
AP_BOARD=$A/board-chp.sh AP_RENDER_OUT=$A/chp AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/chp.out" 2>&1
[ "$(seg chp chanlist)" = "149 153 157 161" ] && [ "$(seg chp channel)" = 0 ] && ok "ap: ACS may use only the measured channel's 80 MHz block (channel=0, chanlist=149 153 157 161: hostapd refuses a lone primary at 80 MHz)" || no "ap render with chan-5: $(seg chp chanlist)"
echo 157 > "$A/chp/chan-5"; AP_BOARD=$A/board-chp.sh AP_RENDER_OUT=$A/chp AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/chp.out" 2>&1
[ "$(seg chp chanlist)" = "157 149 153 161" ] && ok "ap: the measured primary comes first, then the rest of its block" || no "ap render with chan-5=157: $(seg chp chanlist)"
printf '. %s\nAP_HT5=20\n' "$A/board-chp.sh" > "$A/board-chp20.sh"; AP_BOARD=$A/board-chp20.sh AP_RENDER_OUT=$A/chp AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/chp.out" 2>&1
[ "$(seg chp chanlist)" = 157 ] && ok "ap: at 20 MHz the measured channel alone" || no "ap render 20 MHz pin: $(seg chp chanlist)"
echo 36 > "$A/chp/chan-5"; AP_BOARD=$A/board-chp.sh AP_RENDER_OUT=$A/chp AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/chp.out" 2>&1
[ "$(seg chp chanlist)" = "149 153 157 161" ] && grep -q 'no longer allowed' "$A/chp.out" && ok "ap: a measured channel that is no longer a candidate (peer moved there) is ignored" || no "ap: stale chan-5: $(seg chp chanlist)"
printf '. %s\nAP_CHAN_SMART5=0\n' "$A/board-chp.sh" > "$A/board-chp0.sh"; echo 149 > "$A/chp/chan-5"
AP_BOARD=$A/board-chp0.sh AP_RENDER_OUT=$A/chp AP_SYSFS=$A/sys AP_PHY5=phy0 AP_PHY24=phy1 sh "$O/usr/libexec/patronus/ap" render > "$A/chp.out" 2>&1
[ "$(seg chp chanlist)" = "149 153 157 161" ] && ok "ap: AP_CHAN_SMART5=0 = plain ACS over every candidate" || no "ap: AP_CHAN_SMART5=0: $(seg chp chanlist)"
# simultaneous start: a known unit with a LOWER key (picks first) that is not on air -> wait (AP_CHAN_WAIT), then pick anyway;
# one with a higher key, or one forgotten (not heard for AP_CHAN_FORGET), is not waited for
echo "00:00:00:00:01 999000" > "$C2/db/peers-5"; rm -f "$C2/db/history"
CHB=$A/board-chw.sh; printf '. %s\nAP_CHAN_WAIT=10 AP_CHAN_JITTER=0\n' "$A/co-board.sh" > "$CHB"
e=$(chx "$CH" earlier 5 phy0); [ "$e" = "10 00:00:00:00:01" ] && ok "ap-chan earlier: a known unit with a lower key picks first (wait limit + key)" || no "ap-chan earlier: '$e'"
AP_COORD_SCAN_FILE=$FX AP_CHAN_SCAN_FILE=$FX AP_CHAN_SURVEY_FILE=$C2/survey chx "$CO" plan 5 phy0 > "$C2/plan2.out" 2>&1
grep -q 'not on air after 10 s: 00:00:00:00:01' "$C2/db/history" && [ "$(cat "$C2/run/chan-5")" = 149 ] \
  && ok "ap-coord plan: waits for the earlier unit, then picks anyway after AP_CHAN_WAIT (no single point of failure)" || { no "ap-coord plan wait"; cat "$C2/plan2.out" "$C2/db/history" | sed 's/^/    /'; }
echo "aa:bb:cc:11:11 999000" > "$C2/db/peers-5"; e=$(chx "$CH" earlier 5 phy0); [ -z "$e" ] && ok "ap-chan earlier: a unit with a higher key waits for this one, not the other way round" || no "ap-chan earlier higher: '$e'"
echo "00:00:00:00:01 1" > "$C2/db/peers-5"; e=$(chx "$CH" earlier 5 phy0); [ -z "$e" ] && ok "ap-chan earlier: a unit not heard for AP_CHAN_FORGET is not waited for" || no "ap-chan earlier forgotten: '$e'"
# an earlier unit that IS on air (in the scan): no wait at all, its block is avoided
echo "00:00:00:00:01 999000" > "$C2/db/peers-5"; sed 's/^BSS 06:aa:bb:cc:11:11/BSS 06:00:00:00:00:01/' "$FX" > "$C2/scan-early"; rm -f "$C2/db/history"
AP_COORD_SCAN_FILE=$C2/scan-early AP_CHAN_SCAN_FILE=$C2/scan-early AP_CHAN_SURVEY_FILE=$C2/survey chx "$CO" plan 5 phy0 > "$C2/plan3.out" 2>&1
grep -q 'waited 0 s until' "$C2/db/history" && ok "ap-coord plan: the earlier unit is already on air -> no wait" || { no "ap-coord plan earlier on air"; cat "$C2/plan3.out" "$C2/db/history" | sed 's/^/    /'; }
CHB=
# nightly re-check: the radio runs on 36/80 (status file); samples see 149 clearly better 3 times -> CSA to 149
mkdir -p "$C2/run2"; printf 'channel=0\ninterface=wl5-m\nbssid=94:00:5e:10:20:d7\nbss=wl5-g\nbssid=96:00:5e:10:20:d7\n' > "$C2/run2/ap5.conf"
printf 'state=ENABLED\nfreq=5180\nchannel=36\n' > "$C2/st"
cat > "$C2/cli" <<EOF
#!/bin/sh
echo "\$*" >> $C2/cli.log
case "\$5" in chan_switch) f=\$7; printf 'state=ENABLED\\nfreq=%s\\nchannel=%s\\n' \$f \$(( (f - 5000) / 5 )) > $C2/st; echo OK;; esac
EOF
chmod +x "$C2/cli"
printf 'Survey data from wl5-m\n\tfrequency:\t\t\t5180 MHz [in use]\n\tchannel active time:\t\t100000 ms\n\tchannel busy time:\t\t40000 ms\n' > "$C2/survey2"
for c in 40 44 48 149 153 157 161; do printf 'Survey data from wl5-m\n\tfrequency:\t\t\t%s MHz\n\tchannel active time:\t\t105 ms\n\tchannel busy time:\t\t%s ms\n' $((5000 + c * 5)) $([ $c -ge 149 ] && echo 5 || echo 50) >> "$C2/survey2"; done
printf '10000 3000\n40000 30000\n' > "$C2/home"   # this channel over the window: 30000 ms active, 27000 busy, own airtime 3000
rc() { : > "$C2/cli.log"; AP_RENDER_OUT=$C2/run2 AP_CLI=$C2/cli AP_CHAN_STATUS_FILE=$C2/st AP_CHAN_SCAN_FILE=$C2/scan-none \
  AP_CHAN_HOME_FILE=$C2/home AP_COORD_SCAN_FILE=$C2/scan-none AP_CHAN_SURVEY_FILE=${SV:-$C2/survey2} AP_CHAN_OWN_MS=${OWN:-3000} AP_CHAN_CSA_OK=${CSA:-1} AP_BOARD=$A/co-board.sh AP_CHAN_DB=$C2/db AP_SYSFS=$A/sys \
  AP_CHAN_AP=${CHAP:-$O/usr/libexec/patronus/ap} AP_CHAN_COORD=$CO AP_CHAN_NOW=2000000 AP_CHAN_NOSLEEP=1 sh "$CH" recheck 5 > "$C2/rc.out" 2>&1; }
: > "$C2/scan-none"; rm -f "$C2/db/history"; rc
grep -q 'chan_switch 10 5745 sec_channel_offset=1 center_freq1=5775 bandwidth=80 ht vht he' "$C2/cli.log" && grep -q 'channel=149' "$C2/st" \
  && [ "$(grep -c "\"event\":\"sample\"" "$C2/db/history")" = 3 ] && grep -q '"event":"move".*by CSA' "$C2/db/history" \
  && ok "ap-chan recheck: 80 % busy (own airtime left out) vs 5 %: better in 3 samples in a row -> channel switch announcement to 149/80" \
  || { no "ap-chan recheck move"; cat "$C2/rc.out" "$C2/cli.log" "$C2/db/history" | sed 's/^/    /'; }
# the status names the block and the primary that really runs, after a channel switch too (docs 12.19)
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['current']==149 and d['block']==[149,153,157,161] and d['chosen']==149, d" "$C2/run2/chan-status-5" \
  && ok "ap-chan move (CSA): the status records the running primary and its 80 MHz block" || { no "ap-chan status after CSA"; cat "$C2/run2/chan-status-5"; }
# hostapd's ACS picks its own primary inside the pinned block: measured 48, running 36 (hardware, 2026-11-18)
mkdir -p "$C2/run3"; rm -f "$C2/db/history"
printf '{"band":"5","mode":"start","time":1,"chosen":48,"current":null,"block":[36,40,44,48],"width":80,"csa":true,"reason":"channel 48: 5%% busy","candidates":[{"channel":48,"score":5.0,"busy":5.0,"neighbours":0}]}\n' > "$C2/run3/chan-status-5"
printf 'state=ENABLED\nfreq=5180\nchannel=36\n' > "$C2/st3"
sy() { AP_RENDER_OUT=$C2/run3 AP_CHAN_STATUS_FILE=$C2/st3 AP_BOARD=$A/co-board.sh AP_CHAN_DB=$C2/db AP_CHAN_NOW=2000000 AP_CHAN_NOSLEEP=1 AP_CHAN_SYNC_WAIT=${W:-90} sh "$CH" sync 5 > "$C2/sy.out" 2>&1; }
sy
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['chosen']==48 and d['current']==36 and d['block']==[36,40,44,48] and d['reason']=='channel 48: 5% busy' and len(d['candidates'])==1, d" "$C2/run3/chan-status-5" \
  && grep -q '"event":"primary".*"channel":36.*primary 36 inside the pinned block 36 40 44 48' "$C2/db/history" \
  && ok "ap-chan sync: measured 48, hostapd runs 36 in the same 80 MHz block -> status keeps chosen 48 and records current 36 + block, history says why" \
  || { no "ap-chan sync inside the block"; cat "$C2/run3/chan-status-5" "$C2/db/history" "$C2/sy.out"; }
# a radio that is not serving is never recorded (waits AP_CHAN_SYNC_WAIT, then leaves the status alone)
printf 'state=DISABLED\nchannel=36\n' > "$C2/st3"; printf '{"band":"5","chosen":48,"current":null,"block":[36,40,44,48],"candidates":[]}\n' > "$C2/run3/chan-status-5"; W=6 sy
grep -q '"current":null' "$C2/run3/chan-status-5" && grep -q 'not serving' "$C2/sy.out" \
  && ok "ap-chan sync: a radio that is not serving leaves the status alone and says so" || { no "ap-chan sync on a disabled radio"; cat "$C2/run3/chan-status-5" "$C2/sy.out"; }
# the renderer's start path launches the sync for each band it started
grep -q 'ap-chan}' "$O/usr/libexec/patronus/ap" && grep -q 'sync \$b' "$O/usr/libexec/patronus/ap" \
  && ok "ap start: runs ap-chan sync per started band (the running primary reaches the Wi-Fi page)" || no "ap start does not sync the channel status"
# small gain: stays (hysteresis), nothing switched
sed 's/busy time:\t\t50 ms/busy time:\t\t5 ms/' "$C2/survey2" > "$C2/survey3"
printf 'state=ENABLED\nfreq=5180\nchannel=36\n' > "$C2/st"; printf '10000 3000\n40000 6000\n' > "$C2/home"; rm -f "$C2/db/history"; SV=$C2/survey3 OWN=0 rc
[ ! -s "$C2/cli.log" ] || ! grep -q chan_switch "$C2/cli.log" && grep -q '"event":"stay"' "$C2/db/history" \
  && ok "ap-chan recheck: a channel only slightly better (score 6.9 vs 4.8: under AP_CHAN_MIN_GAIN) -> stays, logged with the reason" \
  || { no "ap-chan recheck hysteresis"; cat "$C2/rc.out" "$C2/cli.log" | sed 's/^/    /'; }
# no CSA support -> the radio is restarted onto the pinned channel instead
printf 'state=ENABLED\nfreq=5180\nchannel=36\n' > "$C2/st"; printf '10000 3000\n40000 30000\n' > "$C2/home"; rm -f "$C2/db/history" "$A/fake-ap.log"
cat > "$C2/apwrap" <<EOF
#!/bin/sh
case "\$1" in candidates) exec sh $O/usr/libexec/patronus/ap "\$@";; *) echo "\$@" >> $A/fake-ap.log;; esac
EOF
chmod +x "$C2/apwrap"; rm -f "$A/fake-ap.log" "$C2/db/history"; CSA=0 CHAP=$C2/apwrap rc
grep -q 'restart-band 5' "$A/fake-ap.log" && [ "$(cat "$C2/run2/chan-5")" = 149 ] && grep -q '"event":"move".*by restart' "$C2/db/history" \
  && ok "ap-chan move: a driver without channel switch support -> radio restart pinned to the chosen channel" || { no "ap-chan move without CSA"; cat "$C2/rc.out" "$A/fake-ap.log" 2>&1 | sed 's/^/    /'; }
# a fixed channel is never re-checked
printf 'channel=44\ninterface=wl5-m\n' > "$C2/run2/ap5.conf"; rc; grep -q 'fixed channel' "$C2/rc.out" && ok "ap-chan recheck: a fixed channel is left alone" || no "ap-chan recheck fixed"
# due: once a day at AP_CHAN_TIME, later by AP_CHAN_STAGGER per unit that comes first
dueat() { rm -f "$C2/run2/chan-done-5"; AP_RENDER_OUT=$C2/run2 AP_BOARD=$A/co-board.sh AP_CHAN_DB=$C2/db AP_SYSFS=$A/sys AP_CHAN_HM=$1 AP_CHAN_NOW=2000000 sh "$CH" due 5 && echo due; }
printf 'channel=0\ninterface=wl5-m\nbssid=94:00:5e:10:20:d7\n' > "$C2/run2/ap5.conf"; rm -f "$C2/db/peers-5"
# boot guard hostapd check: every BSS the renderer wrote must be served (a radio whose hostapd gave up leaves no socket;
# found on hardware: 5 GHz down, 2.4 GHz up, the trial was confirmed)
GH=$W/gh; mkdir -p "$GH/ctl" "$GH/run" "$GH/bin" "$GH/sys/phy0" "$GH/gr"; printf 'AP_SSIDS=m\n' > "$GH/ap.env"
printf 'interface=wl5-m\nbss=wl5-g\n' > "$GH/run/ap5.conf"; printf 'interface=wl24-m\n' > "$GH/run/ap24.conf"
printf '#!/bin/sh\ncase "$1" in -v) echo "hostapd v2.11";; *) sleep 30;; esac\n' > "$GH/bin/hostapd"
printf '#!/bin/sh\necho state=ENABLED\n' > "$GH/bin/hostapd_cli"; chmod +x "$GH/bin/hostapd" "$GH/bin/hostapd_cli"
"$GH/bin/hostapd" run & ghp=$!
for i in wl24-m wl5-g; do python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$GH/ctl/$i"; done
ghc() { env GUARD_PATH="$GH/bin" GUARD_CONF_DIR="$GH" GUARD_RUN="$GH/gr" GUARD_RELEASE="$GH/gr/release" PATRONUS_DATA="$GH" GUARD_CHECKS=hostapd \
  GUARD_HOSTAPD_CTRL="$GH/ctl" GUARD_AP_RUN="$GH/run" GUARD_AP_ENV="$GH/ap.env" GUARD_SYSWIFI="$GH/sys" sh "$O/usr/sbin/patronus-guard" check 2>&1; }
o=$(ghc); case "$o" in *"hostapd FAIL wl5-m: not served (ap5.conf)"*) ok "patronus-guard: a configured BSS without hostapd fails the boot check (one radio down)";; *) no "patronus-guard hostapd check with wl5-m missing: $o";; esac
python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$GH/ctl/wl5-m"
o=$(ghc); case "$o" in "hostapd ok") ok "patronus-guard: every BSS served = hostapd ok";; *) no "patronus-guard hostapd check all served: $o";; esac
kill $ghp 2>/dev/null; wait $ghp 2>/dev/null
[ "$(dueat 0335)/$(dueat 1200)/$(dueat 0329)" = "due//" ] && ok "ap-chan due: in the hour after 03:30, not at noon or before" || no "ap-chan due: $(dueat 0335)/$(dueat 1200)/$(dueat 0329)"
r=$(rm -f "$C2/run2/chan-done-5"; for i in 1 2; do AP_RENDER_OUT=$C2/run2 AP_BOARD=$A/co-board.sh AP_CHAN_DB=$C2/db AP_CHAN_HM=0340 AP_CHAN_NOW=2000000 sh "$CH" due 5 && echo due; done)
[ "$r" = "due" ] && ok "ap-chan due: once per day" || no "ap-chan due twice: $r"
echo "00:00:00:00:01 1999000" > "$C2/db/peers-5"
[ "$(dueat 0335)/$(dueat 0405)" = "/due" ] && ok "ap-chan due: a unit with one unit ahead of it re-checks AP_CHAN_STAGGER (30 min) later: never both at once" || no "ap-chan due stagger: $(dueat 0335)/$(dueat 0405)"
rm -f "$C2/db/peers-5"

# 3b. limits for misbehaving stations (patronus-xbss.diff) are radio settings in the render, defaults from board.sh
aprender lim "$TWO"
[ "$(seg lim patronus_xbss_max)/$(seg lim patronus_xbss_hold)/$(seg lim patronus_authfail_max)/$(seg lim patronus_authfail_hold_max)" = "6/30/10/3600" ] \
  && [ "$(s24 lim patronus_authfail_window)" = 60 ] && ok "ap: hostapd station limits rendered per radio with the board.sh defaults" || no "ap: station limits: $(grep patronus_ "$A/lim/ap5.conf" | tr '\n' ' ')"
aprender lim2 "$TWO
AP_AUTHFAIL_MAX=0 AP_XBSS_HOLD=x AP_AUTHFAIL_HOLD_MAX=999999"
[ "$(seg lim2 patronus_authfail_max)/$(seg lim2 patronus_xbss_hold)/$(seg lim2 patronus_authfail_hold_max)" = "0/30/86400" ] && grep -q 'AP_XBSS_HOLD=x is not a whole number' "$A/lim2.out" \
  && ok "ap: station limits: 0 = off, a bad value falls back to the default, the top is clamped (with messages)" || no "ap: station limits validation: $(grep patronus_ "$A/lim2/ap5.conf" | tr '\n' ' ')"

# 3c. ap-steer (docs 12.18): in the day it only ASKS (802.11v BSS transition request, after an 802.11k beacon report
# when the station does them); a disconnect only in the quiet hours, only for an idle station that ignored the request
# (or cannot take one), at most once per AP_STEER_KICK_EVERY; busy, strong, exempt and "no better AP" stations stay
ST=$A/st; rm -rf "$ST"; mkdir -p "$ST/dump" "$ST/run" "$ST/sta"
printf 'interface=wl5-m\nbssid=94:00:00:00:00:01\nssid=Home Net\nbss=wl5-g\nbssid=96:00:00:00:00:01\nssid=Guest\n' > "$ST/run/ap5.conf"
printf 'interface=wl24-m\nbssid=94:00:00:00:00:02\nssid=Home Net\n' > "$ST/run/ap24.conf"
echo "aa:00:00:00:00:0f" > "$ST/run/deny-wl5-g"; : > "$ST/run/deny-wl5-m"; : > "$ST/run/deny-wl24-m"
echo "06:aa:bb:cc:11:11 5180 -60 none 80 42 Home_Net" > "$ST/run/peers-5"
echo "06:aa:bb:cc:11:12 2437 -60 none 20 0 Home_Net" > "$ST/run/peers-24"
# fake hostapd_cli: `sta MAC` answers from $ST/sta/MAC, everything else is logged as "NOW IF CMD ARGS"
printf '#!/bin/sh\nif=$4; c=$5; shift 5\ncase "$c" in sta) cat %s/sta/"$1" 2>/dev/null;; *) echo "$AP_STEER_NOW $if $c $*" >> %s/cli.log;; esac\n' "$ST" "$ST" > "$ST/cli"; chmod +x "$ST/cli"
BTM='ext_capab=0400080000000040'; BCN='rrm_enabled_capab=7000000000'
stsay() { # IF MAC SIGNAL BYTES CONNECTED (appends a station to the fake dump of IF)
  printf 'Station %s (on %s)\n\tinactive time:\t100 ms\n\trx bytes:\t%s\n\ttx bytes:\t0\n\tsignal:  \t%s [%s, %s] dBm\n\tsignal avg:\t%s [%s, %s] dBm\n\tconnected time:\t%s seconds\n' \
    "$2" "$1" "$4" "$3" "$3" "$3" "$3" "$3" "$3" "$5" >> "$ST/dump/$1"; }
fdbhead() { printf 'port no\tmac addr\t\tis local?\tageing timer\n' > "$ST/fdb"; }
stround() { # NOW CLOCK BOARD-EXTRA: one round
  printf '. %s\n%s\n' "$O/etc/patronus/board.sh" "$3" > "$ST/board.sh"
  AP_BOARD=$ST/board.sh AP_RENDER_OUT=$ST/run AP_STEER_STATE=$ST/state AP_STEER_DB=$ST/db AP_STEER_NOW=$1 AP_STEER_CLOCK=$2 \
    AP_STEER_DUMP_DIR=$ST/dump AP_STEER_FDB_FILE=$ST/fdb AP_STEER_WIRED="1 2 3 4 5" AP_CLI=$ST/cli \
    sh "$O/usr/libexec/patronus/ap-steer" once >> "$ST/out" 2>&1; rm -f "$ST/dump"/*; }
SB="AP_STEER=1 AP_STEER_AFTER=60"
fdbhead; : > "$ST/cli.log"
echo "$BTM" > "$ST/sta/aa:00:00:00:00:02"; echo "$BTM" > "$ST/sta/aa:00:00:00:00:03"; printf '%s\n%s\n' "$BTM" "$BCN" > "$ST/sta/aa:00:00:00:00:04"
echo "$BTM" > "$ST/sta/aa:00:00:00:00:05"
for n in 1000 1100 1200; do b=$((n * 10))
  stsay wl5-m aa:00:00:00:00:01 -80 "$b" 700           # weak, idle, no 802.11v (legacy)
  stsay wl5-m aa:00:00:00:00:02 -80 "$b" 700           # weak, idle, 802.11v
  stsay wl5-m aa:00:00:00:00:03 -80 $((n * 9000000)) 700   # weak but busy (~72 Mbit/s), 802.11v
  stsay wl5-m aa:00:00:00:00:04 -80 "$b" 700           # weak, idle, 802.11v + 802.11k
  stsay wl5-m aa:00:00:00:00:05 -80 "$b" 700           # weak, idle, exempt
  stsay wl24-m aa:00:00:00:00:06 -50 "$b" 700          # strong
  stround $n 14:00 "$SB AP_STEER_EXEMPT=aa:00:00:00:00:05"; done
grep -q ' deny_acl ' "$ST/cli.log" && no "ap-steer: disconnected a station outside the quiet hours: $(grep deny_acl "$ST/cli.log")" \
  || ok "ap-steer: outside the quiet hours no station is ever disconnected (legacy, 802.11v, 802.11k, busy, exempt, strong)"
[ "$(grep -c 'bss_tm_req aa:00:00:00:00:02 pref=1 abridged=1 valid_int=255 neighbor=06:aa:bb:cc:11:11,0x0000008f,115,36,9,0301ff$' "$ST/cli.log")" = 1 ] \
  && ok "ap-steer: a weak idle 802.11v station is asked once (per AP_STEER_BTM_EVERY) to move to the other unit's BSS of its SSID and band" \
  || { no "ap-steer: no/odd move request for 02"; cat "$ST/cli.log"; }
grep -q 'aa:00:00:00:00:0[1356]' "$ST/cli.log" && no "ap-steer: asked a legacy, busy, exempt or strong station: $(grep 'aa:00:00:00:00:0[1356]' "$ST/cli.log")" \
  || ok "ap-steer: legacy (day), busy, AP_STEER_EXEMPT and strong stations are not asked"
grep -q 'wl5-m req_beacon aa:00:00:00:00:04 7324000032000[1]ffffffffffff0008486f6d65204e6574020100$' "$ST/cli.log" \
  && ! grep -q 'bss_tm_req aa:00:00:00:00:04' "$ST/cli.log" \
  && ok "ap-steer: an 802.11k station is first asked what it hears (active beacon request on the other unit's channel, SSID filter), not moved yet" \
  || { no "ap-steer: 802.11k station not measured first"; grep ':04' "$ST/cli.log"; }
grep -q 'wl5-m set_neighbor 06:aa:bb:cc:11:11 ssid=486f6d65204e6574 nr=06aabbcc11118f00000073240' "$ST/cli.log" \
  && grep -q 'wl24-m set_neighbor 06:aa:bb:cc:11:12 ' "$ST/cli.log" && ! grep -q 'wl5-g set_neighbor' "$ST/cli.log" \
  && ok "ap-steer: the other unit's BSSes are 802.11k neighbors of every BSS with the same SSID (not the guest one)" \
  || { no "ap-steer: neighbor reports"; grep set_neighbor "$ST/cli.log"; }
# the beacon report says the other unit is 20 dB better -> asked to move there
evh() { printf '73240000000000000000000000%s00%s0000000000\n' "$(printf %02x $(( ($2 + 110) * 2 )))" "$(echo "$1" | tr -d :)"; }
{ echo "1250 wl5-m BEACON-RESP-RX aa:00:00:00:00:04 1 00 $(evh 94:00:00:00:00:01 -80)"; echo "1250 wl5-m BEACON-RESP-RX aa:00:00:00:00:04 1 00 $(evh 06:aa:bb:cc:11:11 -60)"; } > "$ST/state/events"
: > "$ST/cli.log"; stsay wl5-m aa:00:00:00:00:04 -80 12000 800; stround 1300 14:00 "$SB"
grep -q 'bss_tm_req aa:00:00:00:00:04 pref=1 abridged=1 valid_int=255 neighbor=06:aa:bb:cc:11:11,' "$ST/cli.log" \
  && grep -q '"event":"btm","mac":"aa:00:00:00:00:04".*it hears -60 dBm there, -80 dBm here' "$ST/db/history" \
  && ok "ap-steer: when the station hears the other unit AP_STEER_MARGIN dB better it is asked to move there (history says why)" \
  || { no "ap-steer: beacon report not used"; cat "$ST/cli.log"; tail -3 "$ST/out"; }
# it accepted and roamed: gone from here, behind a wired port = no disconnect, recorded as a roam
echo "1310 wl5-m BSS-TM-RESP aa:00:00:00:00:04 dialog_token=1 status_code=0 bss_termination_delay=0 target_bssid=06:aa:bb:cc:11:11" > "$ST/state/events"
printf '  1\taa:00:00:00:00:04\tno\t\t   0.10\n' >> "$ST/fdb"; stround 1330 14:00 "$SB"
grep -q '"event":"btm-answer","mac":"aa:00:00:00:00:04".*accepted' "$ST/db/history" && grep -q '"event":"roamed","mac":"aa:00:00:00:00:04".*no disconnect' "$ST/db/history" \
  && ok "ap-steer: the answer and the roam (without a disconnect) are in the history" || { no "ap-steer: roam not recorded"; tail -5 "$ST/db/history"; }
# a beacon report that shows no unit clearly better: left alone, not asked
rm -rf "$ST/state" "$ST/db"; fdbhead; : > "$ST/cli.log"
for n in 2000 2100; do stsay wl5-m aa:00:00:00:00:04 -80 100 700; stround $n 14:00 "$SB"; done
{ echo "2150 wl5-m BEACON-RESP-RX aa:00:00:00:00:04 1 00 $(evh 94:00:00:00:00:01 -78)"; echo "2150 wl5-m BEACON-RESP-RX aa:00:00:00:00:04 1 00 $(evh 06:aa:bb:cc:11:11 -74)"; } > "$ST/state/events"
for n in 2200 2300 2400; do stsay wl5-m aa:00:00:00:00:04 -80 100 800; stround $n 14:00 "$SB"; done
for n in 2500 2600; do stsay wl5-m aa:00:00:00:00:04 -80 100 800; stround $n 02:00 "$SB AP_STEER_QUIET_IDLE=60"; done
! grep -q 'bss_tm_req\|deny_acl' "$ST/cli.log" && grep -q '"event":"stay","mac":"aa:00:00:00:00:04".*best other -74 dBm, here -78 dBm' "$ST/db/history" \
  && ok "ap-steer: hears no unit AP_STEER_MARGIN dB better -> left alone, not asked, not disconnected at night" || { no "ap-steer: moved without a better unit"; cat "$ST/cli.log"; }
# a station that never answers beacon requests is treated as one without 802.11k (it decides itself)
rm -rf "$ST/state" "$ST/db"; : > "$ST/cli.log"
for n in 3000 3100 3300 3500 3700; do stsay wl5-m aa:00:00:00:00:04 -80 100 $((n - 2300)); stround $n 14:00 "$SB AP_STEER_BTM_EVERY=60"; done
grep -q '"event":"measure".*did not answer' "$ST/db/history" && grep -q 'bss_tm_req aa:00:00:00:00:04' "$ST/cli.log" \
  && ok "ap-steer: no beacon report answer -> asked to move anyway, the station measures itself" || { no "ap-steer: silent 802.11k station stuck"; cat "$ST/cli.log"; }
# quiet hours: the last resort
rm -rf "$ST/state" "$ST/db"; fdbhead; : > "$ST/cli.log"; NB="$SB AP_STEER_QUIET_IDLE=300"
echo "$BTM" > "$ST/sta/aa:00:00:00:00:07"; echo "$BTM" > "$ST/sta/aa:00:00:00:00:08"
for n in 4000 4100 4200 4300 4400 4500 4600 4700 4800; do
  stsay wl5-m aa:00:00:00:00:01 -80 100 900                 # legacy, idle
  stsay wl5-m aa:00:00:00:00:09 -80 $(( n > 4600 ? 460000000 : n * 100000 )) 900   # legacy, traffic until 4600
  stsay wl5-m aa:00:00:00:00:07 -80 100 900                 # 802.11v, ignores the request
  stsay wl5-m aa:00:00:00:00:08 -80 100 900                 # 802.11v, declines: no suitable candidate
  [ $n = 4200 ] && echo "4150 wl5-m BSS-TM-RESP aa:00:00:00:00:08 dialog_token=1 status_code=7 bss_termination_delay=0" > "$ST/state/events"
  c=14:00; [ $n -ge 4400 ] && c=02:00; stround $n $c "$NB"; done
k() { grep -c "deny_acl ADD_MAC $1" "$ST/cli.log"; }
[ "$(k aa:00:00:00:00:01)" = 3 ] && [ "$(k aa:00:00:00:00:07)" = 3 ] && [ "$(k aa:00:00:00:00:08)" = 0 ] && [ "$(k aa:00:00:00:00:09)" = 0 ] \
  && [ -z "$(awk '$3 == "deny_acl" && $1 < 4400' "$ST/cli.log")" ] \
  && grep -q '"event":"kick","mac":"aa:00:00:00:00:07".*ignored the move request' "$ST/db/history" \
  && ok "ap-steer: in the quiet hours an idle station that ignored the request (or has no 802.11v) is refused on every BSS; one that declined, or had traffic, is not" \
  || { no "ap-steer: quiet-hour disconnects: 01=$(k aa:00:00:00:00:01) 07=$(k aa:00:00:00:00:07) 08=$(k aa:00:00:00:00:08) 09=$(k aa:00:00:00:00:09)"; grep deny_acl "$ST/cli.log"; }
# at most once per AP_STEER_KICK_EVERY: it comes back, is left alone (RETRY 60 here), is weak again -> not disconnected again
for n in 4900 5000 5100 5200 5300 5400 5500; do stsay wl5-m aa:00:00:00:00:01 -80 100 $((n - 4850)); stround $n 02:00 "$NB AP_STEER_RETRY=60 AP_STEER_RETRY_MAX=60"; done
[ "$(k aa:00:00:00:00:01)" = 3 ] && ok "ap-steer: a device is disconnected at most once per AP_STEER_KICK_EVERY" || { no "ap-steer: kicked again: $(k aa:00:00:00:00:01)"; grep 'aa:00:00:00:00:01' "$ST/db/history" | tail -3; }
rm -rf "$ST/state" "$ST/db"; : > "$ST/cli.log"
for n in 6000 6100 6200 6300 6400 6500; do stsay wl5-m aa:00:00:00:00:01 -80 100 900; stround $n 02:00 "$NB AP_STEER_LEGACY=never"; done
for n in 6600 6700 6800 6900 7000; do stsay wl5-m aa:00:00:00:00:01 -80 100 900; stround $n 02:00 "$NB AP_STEER_KICK=never"; done
grep -q deny_acl "$ST/cli.log" && no "ap-steer: AP_STEER_LEGACY/KICK=never still disconnected" || ok "ap-steer: AP_STEER_LEGACY=never / AP_STEER_KICK=never: never disconnected"
for n in 7100 7200 7300 7400 7500; do stsay wl5-m aa:00:00:00:00:01 -80 100 900; stround $n 06:30 "$NB AP_STEER_QUIET=23:00-06:00"; done
for n in 7600 7700; do stsay wl5-m aa:00:00:00:00:01 -80 100 900; stround $n 23:30 "$NB AP_STEER_QUIET=23:00-06:00"; done
[ "$(k aa:00:00:00:00:01)" = 3 ] && [ -z "$(awk '$3 == "deny_acl" && $1 < 7600' "$ST/cli.log")" ] \
  && ok "ap-steer: AP_STEER_QUIET may wrap midnight (06:30 outside, 23:30 inside 23:00-06:00)" || { no "ap-steer: quiet window wrap"; cat "$ST/cli.log"; }
# a bad move is undone fast: a weak 802.11k station that just arrived from another unit is measured at once
rm -rf "$ST/state" "$ST/db"; : > "$ST/cli.log"; fdbhead; printf '  2\taa:00:00:00:00:04\tno\t\t   0.10\n' >> "$ST/fdb"
stsay wl24-m aa:00:00:00:00:06 -50 100 700; stround 8000 14:00 "$SB"; fdbhead
stsay wl5-m aa:00:00:00:00:04 -82 100 20; stround 8030 14:00 "$SB"
grep -q 'req_beacon aa:00:00:00:00:04' "$ST/cli.log" && ok "ap-steer: a weak station that just arrived from another unit is measured at once (no AP_STEER_AFTER wait)" \
  || { no "ap-steer: arrival not measured"; cat "$ST/cli.log"; tail -3 "$ST/out"; }
{ echo "8040 wl5-m BEACON-RESP-RX aa:00:00:00:00:04 1 00 $(evh 94:00:00:00:00:01 -82)"; echo "8040 wl5-m BEACON-RESP-RX aa:00:00:00:00:04 1 00 $(evh 06:aa:bb:cc:11:11 -63)"; } > "$ST/state/events"
stsay wl5-m aa:00:00:00:00:04 -82 100 50; stround 8060 14:00 "$SB"
grep -q 'bss_tm_req aa:00:00:00:00:04 .*neighbor=06:aa:bb:cc:11:11' "$ST/cli.log" && grep -q 'arrived from another unit' "$ST/db/history" \
  && ok "ap-steer: ... and asked straight back when it hears the other unit clearly better" || { no "ap-steer: bad move not undone"; cat "$ST/cli.log"; }
# answers reach ap-steer through ap-event (hostapd_cli -a)
rm -f "$ST/state/events"; AP_STEER_STATE=$ST/state AP_STEER_NOW=9000 sh "$O/usr/libexec/patronus/ap-event" wl5-m BSS-TM-RESP aa:00:00:00:00:02 dialog_token=3 status_code=7
grep -qx '9000 wl5-m BSS-TM-RESP aa:00:00:00:00:02 dialog_token=3 status_code=7' "$ST/state/events" && ok "ap-event: queues 802.11v/k answers for ap-steer" || { no "ap-event: answer not queued"; cat "$ST/state/events"; }
# status: the reason is right, and the JSON for the Wi-Fi page parses
stsay wl5-m aa:00:00:00:00:04 -82 100 80; stround 9100 14:00 "$SB"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['active'] and d['stations'] and d['peers'], d" "$ST/state/status.json" 2>"$ST/js.err" \
  && ok "ap-steer: status.json (Wi-Fi page) parses and lists peers + stations" || { no "ap-steer: status.json"; cat "$ST/state/status.json" "$ST/js.err"; }
AP_BOARD=$ST/board.sh AP_RENDER_OUT=$ST/run AP_STEER_STATE=$ST/state AP_STEER_DB=$ST/db AP_STEER_NOW=9100 AP_STEER_CLOCK=14:00 sh "$O/usr/libexec/patronus/ap-steer" status > "$ST/status" 2>&1 \
  && grep -q 'steering: on' "$ST/status" && grep -q 'last steps:' "$ST/status" && ok "ap-steer status runs on a unit with records" || { no "ap-steer status failed"; cat "$ST/status"; }
# two units, no ping-pong (quiet hours, legacy station): A disconnects a weak station, it lands on B even weaker, B sends
# it back, A then keeps it. Each unit moves a station at most once per AP_STEER_RETRY: at most one round trip per RETRY.
PP=$A/pp; rm -rf "$PP"; for u in a b; do mkdir -p "$PP/$u/run" "$PP/$u/dump"; printf 'interface=wl5-m\n' > "$PP/$u/run/ap5.conf"
  printf '#!/bin/sh\necho "$AP_STEER_NOW $6 $7" >> %s/%s/cli.log\n' "$PP" "$u" > "$PP/$u/cli"; chmod +x "$PP/$u/cli"; : > "$PP/$u/cli.log"; done
ppround() { # UNIT NOW
  printf '. %s\nAP_STEER=1 AP_STEER_AFTER=60 AP_STEER_BLOCK=30 AP_STEER_RETRY=3600 AP_STEER_QUIET_IDLE=60 AP_STEER_KICK_EVERY=1 %s\n' "$O/etc/patronus/board.sh" "${PPX:-}" > "$PP/$1/board.sh"
  AP_BOARD=$PP/$1/board.sh AP_RENDER_OUT=$PP/$1/run AP_STEER_STATE=$PP/$1/state AP_STEER_DB=$PP/$1/db AP_STEER_NOW=$2 AP_STEER_CLOCK=02:00 \
    AP_STEER_DUMP_DIR=$PP/$1/dump AP_STEER_FDB_FILE=$PP/$1/fdb AP_STEER_WIRED="1" AP_CLI=$PP/$1/cli sh "$O/usr/libexec/patronus/ap-steer" once >> "$PP/$1/out" 2>&1; }
pploop() { # END: the station between the two units from t=10000; trips = "unit@time" of every move
PM=aa:00:00:00:00:a1; loc=a; conn=700; trips=
for t in $(seq 10000 100 $1); do other=b; [ $loc = b ] && other=a
  sig=-75; [ $loc = b ] && sig=-82
  : > "$PP/$loc/dump/wl5-m"; : > "$PP/$other/dump/wl5-m"
  printf 'Station %s (on wl5-m)\n\trx bytes:\t100\n\ttx bytes:\t0\n\tsignal:  \t%s dBm\n\tsignal avg:\t%s dBm\n\tconnected time:\t%s seconds\n' \
    $PM $sig $sig $conn > "$PP/$loc/dump/wl5-m"
  printf 'port no\tmac addr\t\tis local?\tageing timer\n  7\t%s\tno\t\t   0.10\n' $PM > "$PP/$loc/fdb"
  printf 'port no\tmac addr\t\tis local?\tageing timer\n  1\t%s\tno\t\t   0.10\n' $PM > "$PP/$other/fdb"
  n=$(grep -c "ADD_MAC $PM" "$PP/$loc/cli.log"); ppround a $t; ppround b $t
  if [ "$(grep -c "ADD_MAC $PM" "$PP/$loc/cli.log")" -gt "$n" ]; then trips="$trips $loc@$t"; loc=$other; conn=95; else conn=$((conn + 100)); fi
done; }
pploop 21000
movesA=$(grep -c "ADD_MAC $PM" "$PP/a/cli.log"); movesB=$(grep -c "ADD_MAC $PM" "$PP/b/cli.log")
first=$(awk -v m=$PM '$2 == "ADD_MAC" && $3 == m && $1 < 13600' "$PP/a/cli.log" "$PP/b/cli.log" | wc -l)
case "$trips" in " a@"*" b@"*) ;; *) trips="BAD$trips";; esac
[ "$first" = 2 ] && [ "${trips#BAD}" = "$trips" ] && grep -q "$PM back (wl5-m, -75 dBm): came back: no better access point for it (time 1 in a row), left alone" "$PP/a/out" \
  && ok "ap-steer, two units: moved A->B, weaker on B, sent back once, then left alone on A (one round trip within AP_STEER_RETRY)" \
  || { no "ap-steer two units: moves $trips"; tail -5 "$PP/a/out" "$PP/b/out"; }
gap=$(for u in a b; do awk -v m=$PM '$2 == "ADD_MAC" && $3 == m { if (p != "" && $1 - p < 3600) print "'$u'", p, $1; p = $1 }' "$PP/$u/cli.log"; done)
[ -z "$gap" ] && [ "$movesA" -le 4 ] && [ "$movesB" -le 4 ] \
  && ok "ap-steer, two units over 11000 s: each unit moves the station at most once per AP_STEER_RETRY (A $movesA, B $movesB moves)" \
  || no "ap-steer two units: moves closer than AP_STEER_RETRY: $gap (A $movesA, B $movesB)"
# back-off: a station that keeps coming back (no better access point) is left alone twice as long each time, at most
# AP_STEER_RETRY_MAX: A's moves 3600, then 7200 s apart; with the maximum at 7200 the gaps stay 7200 (one outage per max)
agaps() { awk -v m=$PM '$2 == "ADD_MAC" && $3 == m { if (p != "") printf "%d ", int(($1 - p + 50) / 100) * 100; p = $1 }' "$PP/a/cli.log"; }
g=$(agaps); case "$g" in "3600 7200 "*) ok "ap-steer back-off: a returning station's hold doubles per return (A's moves $g s apart)";;
  *) no "ap-steer back-off: A's moves $g s apart (trips$trips)"; tail -3 "$PP/a/out";; esac
rm -rf "$PP"; for u in a b; do mkdir -p "$PP/$u/run" "$PP/$u/dump"; printf 'interface=wl5-m\n' > "$PP/$u/run/ap5.conf"
  printf '#!/bin/sh\necho "$AP_STEER_NOW $6 $7" >> %s/%s/cli.log\n' "$PP" "$u" > "$PP/$u/cli"; chmod +x "$PP/$u/cli"; : > "$PP/$u/cli.log"; done
PPX=AP_STEER_RETRY_MAX=7200 pploop 40000; g=$(agaps)
case "$g" in "3600 7200 7200 7200"*) ok "ap-steer back-off: capped at AP_STEER_RETRY_MAX (A's moves $g s apart)";;
  *) no "ap-steer back-off cap: A's moves $g s apart"; tail -3 "$PP/a/out";; esac
grep -q 'time 3 in a row' "$PP/a/out" && ok "ap-steer back-off: the log says how many times in a row" || no "ap-steer back-off: no 'time N in a row'"
# auto = only when another access point is known; 0 = off, and status says it is off by the setting
ST2=$A/st2; rm -rf "$ST2"; mkdir -p "$ST2/run" "$ST2/dump"; printf 'interface=wl24-m\nbssid=94:00:00:00:00:02\nssid=Home Net\n' > "$ST2/run/ap24.conf"
printf '#!/bin/sh\nc=$5; shift 5\ncase "$c" in sta) ;; *) echo "$c $*" >> %s/cli.log;; esac\n' "$ST2" > "$ST2/cli"; chmod +x "$ST2/cli"; : > "$ST2/cli.log"
printf 'port no\tmac addr\t\tis local?\tageing timer\n' > "$ST2/fdb"
s2() { printf '. %s\n%s\n' "$O/etc/patronus/board.sh" "$2" > "$ST2/board.sh"
  printf 'Station aa:00:00:00:00:07 (on wl24-m)\n\trx bytes:\t100\n\ttx bytes:\t0\n\tsignal avg:\t-80 dBm\n\tconnected time:\t900 seconds\n' > "$ST2/dump/wl24-m"
  AP_BOARD=$ST2/board.sh AP_RENDER_OUT=$ST2/run AP_STEER_STATE=$ST2/state AP_STEER_DB=$ST2/db AP_STEER_NOW=$1 AP_STEER_CLOCK=02:00 \
    AP_STEER_DUMP_DIR=$ST2/dump AP_STEER_FDB_FILE=$ST2/fdb AP_STEER_WIRED=1 AP_CLI=$ST2/cli sh "$O/usr/libexec/patronus/ap-steer" ${3:-once} >> "$ST2/out" 2>&1; }
for n in 3000 3100 3200 3300; do s2 $n "AP_STEER=auto AP_STEER_AFTER=60 AP_STEER_QUIET_IDLE=60"; done
grep -q 'deny_acl\|bss_tm_req' "$ST2/cli.log" && no "ap-steer auto: moved a station with no other access point known" || ok "ap-steer: AP_STEER=auto does nothing while no other access point is known"
echo "06:aa:bb:cc:11:12 2437 -60 none 20 0 Home_Net" > "$ST2/run/peers-24"
for n in 3400 3500; do s2 $n "AP_STEER=auto AP_STEER_AFTER=60 AP_STEER_QUIET_IDLE=60"; done
grep -q "ADD_MAC aa:00:00:00:00:07" "$ST2/cli.log" && ok "ap-steer: AP_STEER=auto steers once ap-coord heard a peer" || no "ap-steer auto with peers-24: nothing moved"
rm -rf "$ST2/state" "$ST2/db"; : > "$ST2/cli.log"
for n in 4000 4100 4200 4300; do s2 $n "AP_STEER=off AP_STEER_AFTER=60 AP_STEER_QUIET_IDLE=60"; done
[ -s "$ST2/cli.log" ] && grep -v set_neighbor "$ST2/cli.log" | grep . >/dev/null && no "ap-steer: AP_STEER=off still steered: $(cat "$ST2/cli.log")" || ok "ap-steer: AP_STEER=off turns it off"
: > "$ST2/out"; s2 4300 "AP_STEER=off" status
grep -q 'steering: idle (off: switched off in the settings' "$ST2/out" && ! grep -q 'no other access point' "$ST2/out" \
  && ok "ap-steer status: off by the setting says so (not 'no other access point known')" || { no "ap-steer status reason"; cat "$ST2/out"; }
grep -q '"reason":"off: switched off in the settings' "$ST2/state/status.json" && ok "ap-steer status.json: same reason for the Wi-Fi page" || { no "status.json reason"; cat "$ST2/state/status.json"; }
# the hostapd config: 802.11v/k on by default, off by setting, never 802.11r
aprender kv "$TWO"
[ "$(grep -c '^bss_transition=1$' "$A/kv/ap5.conf")" = 2 ] && [ "$(grep -c '^rrm_neighbor_report=1$' "$A/kv/ap24.conf")" = 2 ] \
  && [ "$(grep -c '^rrm_beacon_report=1$' "$A/kv/ap5.conf")" = 2 ] && ! grep -q '^wnm_sleep_mode\|^ieee80211r\|^mobility_domain' "$A/kv/ap5.conf" "$A/kv/ap24.conf" \
  && ok "ap: every BSS gets 802.11v BSS transition + 802.11k neighbor/beacon reports, no WNM sleep, never 802.11r" \
  || { no "ap: 802.11v/k lines"; grep -n 'bss_transition\|rrm_\|wnm\|80211r' "$A/kv/ap5.conf"; }
aprender kv0 "$TWO
AP_BSS_TRANSITION=0 AP_RRM=0 AP_WNM_SLEEP=1"
! grep -q '^bss_transition\|^rrm_' "$A/kv0/ap5.conf" && [ "$(grep -c '^wnm_sleep_mode=1$' "$A/kv0/ap5.conf")" = 2 ] \
  && ok "ap: AP_BSS_TRANSITION=0 / AP_RRM=0 / AP_WNM_SLEEP=1 are honoured" || { no "ap: 802.11v/k settings ignored"; grep -n 'bss_transition\|rrm_\|wnm' "$A/kv0/ap5.conf"; }
# the time zone of every hour setting comes from AP_TZ
[ "$(sh -c ". $O/etc/patronus/board.sh; echo \$TZ")" = UTC0 ] && grep -q '^export TZ="${AP_TZ:-UTC0}"$' "$O/etc/patronus/board.sh" \
  && ok "board.sh: TZ is exported from AP_TZ (default UTC0)" || no "board.sh: TZ not exported"
for c in 1:+ 6:+ 7:+ 8:- 11:- auto:+; do ch=${c%%:*}; dir=${c#*:}
  aprender h24$ch "$TWO
AP_CHAN24=$ch AP_HT24=40"
  case "$(s24 h24$ch ht_capab)" in "[HT40$dir][LDPC]"*) ok "ap: 2.4 GHz ch $ch / 40 MHz -> HT40$dir";; *) no "ap: 2.4 GHz ch $ch / 40 MHz: $(s24 h24$ch ht_capab)";; esac; done
aprender h24x "$TWO
AP_CHAN24=14"
[ "$(s24 h24x channel)" = 0 ] && grep -q 'AP_CHAN24=14 is not a 2.4 GHz channel' "$A/h24x.out" && case "$(s24 h24x ht_capab)" in "[LDPC]"*) true;; *) false;; esac \
  && ok "ap: an invalid 2.4 GHz channel falls back to auto (with a message); 20 MHz writes no HT40 flag" || no "ap: AP_CHAN24=14 not handled"
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
# live: `ap airtime` (docs 12.20) writes mac80211's airtime queue limit + fairness for each radio whose driver has AQL,
# and leaves a driver without it alone
DB=$A/dbg; mkdir -p "$DB/phy0" "$DB/phy1"; for p in phy0 phy1; do : > "$DB/$p/aql_enable"; : > "$DB/$p/aql_txq_limit"; : > "$DB/$p/airtime_flags"; done
FA=$A/fakeaql; mkdir -p "$FA"
printf '#!/bin/sh\ncase "$*" in "phy phy0 info"|"phy phy1 info") echo "		* [ AQL ]: Airtime-based queue limits";; esac\n' > "$FA/iw"; chmod +x "$FA/iw"
printf '. %s\nAP_SSIDS=m\nAP_AQL_LOW24=1500 AP_AQL_HIGH24=4000 AP_ATF=off\n' "$O/etc/patronus/board.sh" > "$A/board-air.sh"
ao=$(PATH=$FA:$PATH AP_BOARD=$A/board-air.sh AP_DEBUGFS=$DB AP_PHY24=phy1 AP_PHY5=phy0 sh "$O/usr/libexec/patronus/ap" airtime 2>&1)
[ "$(cat "$DB/phy1/aql_enable")" = 1 ] && [ "$(cat "$DB/phy1/aql_txq_limit")" = "3 1500 4000" ] && [ "$(cat "$DB/phy1/airtime_flags")" = 0 ] \
  && [ "$(cat "$DB/phy0/aql_txq_limit")" = "3 5000 12000" ] \
  && ok "ap airtime: per-band queue limits (2.4 GHz 1500/4000 us, 5 GHz defaults), fairness off, no restart" || { no "ap airtime: $ao"; head "$DB"/phy*/*; }
# image defaults (board.sh): 2.4 GHz 2500/5000 us, 5 GHz 5000/12000 us; a bad 2.4 GHz value falls back to the 2.4 GHz default
printf '. %s\nAP_SSIDS=m\n' "$O/etc/patronus/board.sh" > "$A/board-aird.sh"
ao=$(PATH=$FA:$PATH AP_BOARD=$A/board-aird.sh AP_DEBUGFS=$DB AP_PHY24=phy1 AP_PHY5=phy0 sh "$O/usr/libexec/patronus/ap" airtime 2>&1)
[ "$(cat "$DB/phy1/aql_txq_limit")" = "3 2500 5000" ] && [ "$(cat "$DB/phy0/aql_txq_limit")" = "3 5000 12000" ] && [ "$(cat "$DB/phy1/airtime_flags")" = 3 ] \
  && ok "ap airtime: image defaults 2.4 GHz 2500/5000 us, 5 GHz 5000/12000 us" || no "ap airtime defaults: $ao"
printf '. %s\nAP_SSIDS=m\nAP_AQL_LOW24=x AP_AQL_HIGH24=9\n' "$O/etc/patronus/board.sh" > "$A/board-airx.sh"
: > "$DB/phy1/aql_txq_limit"
ao=$(PATH=$FA:$PATH AP_BOARD=$A/board-airx.sh AP_DEBUGFS=$DB AP_PHY24=phy1 AP_PHY5=phy0 sh "$O/usr/libexec/patronus/ap" airtime 2>&1)
[ "$(cat "$DB/phy1/aql_txq_limit")" = "3 2500 5000" ] && ok "ap airtime: an invalid 2.4 GHz limit falls back to the 2.4 GHz default" || no "ap airtime fallback: $ao"
printf '#!/bin/sh\nexit 0\n' > "$FA/iw"; : > "$DB/phy1/aql_txq_limit"
ao=$(PATH=$FA:$PATH AP_BOARD=$A/board-air.sh AP_DEBUGFS=$DB AP_PHY24=phy1 AP_PHY5=phy0 sh "$O/usr/libexec/patronus/ap" airtime 2>&1)
case "$ao" in *"no airtime queue limit"*) [ ! -s "$DB/phy1/aql_txq_limit" ] && ok "ap airtime: a driver without AQL (stock modules) is left alone, said so" || no "ap airtime wrote without AQL";;
  *) no "ap airtime without AQL: $ao";; esac
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
    gpg --homedir "$g" ${MKTIME:+--faked-system-time $MKTIME} --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "test $1 <$1@example.invalid>" ed25519 sign 1d >/dev/null 2>&1; }
  if command -v gpg >/dev/null && command -v gpgv >/dev/null; then
    mkkey rel; mkkey foreign; gpg --homedir "$F/gpg-rel" --batch --export > "$KR"
  else no "gpg/gpgv missing: the release signature cases cannot run (install gnupg gpgv)"; fi
  # sigfor KEY FILE: binary detached signature of FILE on stdout
  sigfor() { gpg --homedir "$F/gpg-$1" ${SIGTIME:+--faked-system-time $SIGTIME} --batch --pinentry-mode loopback --passphrase '' --detach-sign --output - "$2" 2>/dev/null; }
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
  # no RTC on the board: the early boot re-verifies a staged upgrade while the clock still says 1970, so the release key
  # (and every signature) is "created in the future" for gpgv; that must not fail the check (a unit refused its signed
  # upgrade this way). Same condition on the host: a key and signature made one day ahead of the clock.
  if command -v gpg >/dev/null; then
    FT=$(( $(date +%s) + 86400 )); MKTIME=$FT mkkey future; gpg --homedir "$F/gpg-future" --batch --export > "$F/keyring-future.gpg"
    KEYRING=$F/keyring-future.gpg t "flash check: a key/signature newer than the box clock (no RTC, early boot at 1970) is still good" \
      PF check "$(SIGN=future SIGTIME=$FT mkimg future)"
  fi
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
[ $rc = 0 ] && case "$out" in *"920 PEBs - 24 reserved"*"kernel 42 "*"rollback copy "*) true;; *) false;; esac && ok "nand-budget: 25 MB root fits with its rollback copy, stock kernel = 42 LEBs" || no "nand-budget: $out"
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

# 3b. boot rollback (patronus-guard): the bootloader script it writes into a U-Boot environment (a file in U-Boot's
#     format, fw_setenv/fw_printenv from u-boot-tools), idempotence, refusal of a non-stock bootcmd, trial arm/confirm
if command -v mkenvimage >/dev/null && command -v fw_printenv >/dev/null; then
  G=$O/usr/sbin/patronus-guard; GC=$W/gconf; GR=$W/grun; mkdir -p $GC $GR $W/gdata
  printf 'bootcmd=bootipq; ping 192.168.1.2; run lfq; bootipq; httpd 192.168.1.1; reset\nbootargs=console=ttyMSM0,115200n8\n' > $W/env.txt
  mkenvimage -s 0x40000 -o $W/env.img $W/env.txt
  cp $O/etc/patronus/boot-guard.board $O/etc/patronus/boot-guard.conf $GC/
  printf 'GUARD_ENV_MTD=%s\nGUARD_UB_VOL="ubi part fs"\n' "$W/env.img" >> $GC/boot-guard.board
  echo BUILD=host-old > $GR/release
  GE="GUARD_CONF_DIR=$GC GUARD_RUN=$GR GUARD_RELEASE=$GR/release PATRONUS_DATA=$W/gdata"
  pe() { fw_printenv -c $GR/fw_env.config -n "$1" 2>/dev/null; }
  t "guard env-install on a stock environment" env $GE sh "$G" env-install
  t "bootcmd = guard prefix + stock boot + pat_failed + stock rest" sh -c "[ \"\$(fw_printenv -c $GR/fw_env.config -n bootcmd)\" = 'run pat_boot; bootipq; run pat_failed; ping 192.168.1.2; run lfq; bootipq; httpd 192.168.1.1; reset' ]"
  t "trial: count down + save BEFORE booting, watchdog + trial flag only for this boot" sh -c "fw_printenv -c $GR/fw_env.config -n pat_trial | grep 'setexpr pat_left \${pat_left} - 1; setexpr pat_boots \${pat_boots} + 1; run pat_save; setenv bootargs \${bootargs} patronus.trial=\${pat_boots} watchdog.handle_boot_enabled=0; run pat_wdt' >/dev/null"
  t "revert: both old parts read into RAM before anything is written, then state reverted + save" sh -c "fw_printenv -c $GR/fw_env.config -n pat_revert | grep 'run pat_vol && run pat_rd_r && run pat_rd_k && run pat_wr_r && run pat_wr_k && setenv pat_state reverted; if test \"\${pat_state}\" = revert; then setenv pat_state revert-failed; fi; run pat_save' >/dev/null"
  t "copy primitives are U-Boot ubi read/write of the prev/live volumes" sh -c "[ \"\$(fw_printenv -c $GR/fw_env.config -n pat_rd_r)\" = 'ubi read \${pat_ra} rootfs_prev \${pat_rsz}' ] && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_wr_k)\" = 'ubi write \${pat_ka} kernel \${pat_ksz}' ]"
  t "a revert that fails in the bootloader is marked revert-failed (both callers), never retried in a reset loop" sh -c "fw_printenv -c $GR/fw_env.config -n pat_boot | grep 'then run pat_revert; elif' >/dev/null && fw_printenv -c $GR/fw_env.config -n pat_trial | grep 'else setenv pat_state revert; run pat_save; run pat_revert; fi' >/dev/null && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_failed)\" = 'if test \"\${pat_state}\" = trial; then reset; fi' ]"
  t "watchdog: 30 s x 32768 Hz ticks, APCS WDT registers" sh -c "[ \"\$(fw_printenv -c $GR/fw_env.config -n pat_wdt_ticks)\" = 0xf0000 ] && fw_printenv -c $GR/fw_env.config -n pat_wdt | grep 'mw.l 0xb017008 1' >/dev/null"
  cp $W/env.img $W/env.before; t "env-install again: nothing written (NAND wear)" env $GE sh "$G" env-install
  t "env-install is idempotent" cmp -s $W/env.img $W/env.before
  printf 'GUARD_WATCHDOG=0\nGUARD_ATTEMPTS=3\n' > $GC/boot-guard.conf
  t "a setting change rewrites the script (watchdog off: no kernel args, pat_wdt=true)" sh -c "env $GE sh '$G' env-install && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_wdt)\" = true ] && ! fw_printenv -c $GR/fw_env.config -n pat_trial | grep handle_boot >/dev/null"
  printf 'PREV_KSZ=5242880\nPREV_RSZ=16998400\n' > $GR/prev-sizes
  t "arm: trial with 3 boots, sizes in hex, previous build recorded" sh -c "env $GE sh '$G' arm host-new && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_state)\" = trial ] && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_left)\" = 3 ] && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_rsz)\" = 0x1036000 ] && [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_prev)\" = host-old ]"
  tn_msg "can-arm refuses while a trial runs" "still running" env $GE sh "$G" can-arm /dev/null /dev/null
  t "ok: confirm clears the trial and logs the event" sh -c "env $GE sh '$G' ok >/dev/null 2>&1; [ \"\$(fw_printenv -c $GR/fw_env.config -n pat_state)\" = ok ] && grep -q '|confirmed|' $W/gdata/boot-guard/events"
  t "status --json is valid JSON" sh -c "env $GE sh '$G' status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"state\"]==\"ok\" and d[\"installed\"] and d[\"settings\"][\"attempts\"]==3, d'"
  t "env-remove restores the stock bootcmd and drops every pat_ variable" sh -c "env $GE sh '$G' env-remove && [ \"\$(fw_printenv -c $GR/fw_env.config -n bootcmd)\" = 'bootipq; ping 192.168.1.2; run lfq; bootipq; httpd 192.168.1.1; reset' ] && ! fw_printenv -c $GR/fw_env.config | grep '^pat_' >/dev/null"
  head -c 262144 /dev/zero > $W/env.img; cp $W/env.img $W/env.before
  tn_msg "an environment with a bad CRC is never written (tools' default env would replace the board's)" "not readable" env $GE sh "$G" env-install
  t "... and the bad-CRC environment is untouched" cmp -s $W/env.img $W/env.before
  printf 'bootcmd=run custom_boot\n' > $W/env2.txt; mkenvimage -s 0x40000 -o $W/env.img $W/env2.txt; cp $W/env.img $W/env.before
  tn_msg "a bootcmd that is not the stock one is left alone" "not the stock one" env $GE sh "$G" env-install
  t "... and the environment is untouched" cmp -s $W/env.img $W/env.before
else sk "boot rollback environment cases (no mkenvimage/fw_printenv: u-boot-tools)"; fi

# 4. package-managed accounts (shared with the Slate)
if out=$(sh "$D/../../embedded-common/tests/accounts-sync.sh" 2>&1); then ok "accounts-sync: $(echo "$out" | tail -1)"; else no "accounts-sync tests"; echo "$out" | grep FAIL | sed 's/^/    /'; fi

echo "ax1800 tooling tests: $pass passed, $failn failed, $skip skipped"
[ "$failn" = 0 ]
