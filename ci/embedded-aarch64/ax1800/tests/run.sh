#!/bin/sh
# Host tests for the GL-AX1800 image tooling (no router, no root): `sh ci/embedded-aarch64/ax1800/tests/run.sh`.
# Needs python3; mksquashfs/unsquashfs and ubinize for the image-format cases (the builder image has them; skipped without).
#  - every script parses; OpenRC <-> systemd service parity; no udev units shipped in the systemd overlay
#  - check-rootfs.sh accepts a good root and rejects the mistakes it exists for (busybox init, no ETPhoneHome, 802.11r)
#  - the AP renderer never writes 802.11r unless asked; explicit unique BSSIDs; 5 GHz centre channels; caldata path
#  - patronus-flash check/sysupgrade and upgrade-install verify against a fake UBI: every guard fails closed
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
         patronus-web:patronus-web dropbear:patronus-dropbear patronus-ntpd:patronus-ntpd patronus-syslogd:patronus-syslogd patronus-klogd:patronus-klogd; do
  t "parity ${p%%:*} (OpenRC) = ${p#*:}.service (systemd)" sh -c "[ -x '$D/overlay-openrc/etc/init.d/${p%%:*}' ] && [ -L '$D/overlay-systemd/etc/systemd/system/multi-user.target.wants/${p#*:}.service' ] && [ -f '$D/overlay-systemd/etc/systemd/system/${p#*:}.service' ]"
done
n=$(ls "$D/overlay-systemd/etc/systemd/system" | grep -c 'udev\|hwdb')
[ "$n" = 0 ] && ok "systemd overlay ships no udev/hwdb units (devtmpfs board; assemble.sh drops them)" || no "systemd overlay still has $n udev/hwdb units"
bad=$(find "$D/overlay-systemd/etc/systemd/system" -maxdepth 1 -type f -size 0)
[ -z "$bad" ] && ok "systemd masks are /dev/null links, not empty unit files" || no "empty unit files (not masks): $bad"

# 1c. every command the flash guard / installer runs on the box exists there: a busybox applet (busybox-applets.txt) or a
#     packaged tool (mtd-utils UBI tools); od was missing once and the guard refused every image on the QEMU gate
for c in od tail head tr cut mktemp sha256sum wc cmp date logger mknod pivot_root sed grep sleep tar dd mount umount cat ls \
         basename mv rm cp sync mkdir rmdir uname reboot; do
  grep -qx "$c" "$D/busybox-applets.txt" && ok "busybox applet for $c (flash guard/installer)" || no "no busybox applet for $c (used on the box by fwcheck.sh/upgrade-install)"; done

# 2. check-rootfs.sh
mkroot() { r=$W/root-$1; rm -rf "$r"; mkdir -p "$r/bin" "$r/sbin" "$r/usr/bin" "$r/usr/sbin" "$r/root/.ssh" "$r/etc/init.d" "$r/etc/runlevels/default" \
    "$r/usr/libexec/patronus" "$r/etc/pam.d" "$r/lib/security" "$r/etc/patronus" "$r/lib/firmware/ath11k/IPQ6018/hw1.0" "$r/lib/firmware/IPQ6018" "$r/lib/modules/6.12.112"
  printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > "$r/etc/passwd"; echo 'root:!:1::::::' > "$r/etc/shadow"
  echo "ssh-ed25519 AAAA test" > "$r/root/.ssh/authorized_keys"; echo "http 80/tcp" > "$r/etc/services"
  : > "$r/bin/busybox"; chmod +x "$r/bin/busybox"; ln -s busybox "$r/bin/sh"
  for f in usr/sbin/patronus-flash usr/libexec/patronus/fwcheck.sh usr/libexec/patronus/upgrade-install usr/libexec/patronus/ubi-data usr/sbin/patronus-init usr/libexec/patronus/early \
           usr/libexec/patronus/ath11k-caldata usr/libexec/patronus/ap usr/libexec/patronus/ntp-sync usr/libexec/patronus/board-network etc/pam.d/patronus lib/security/pam_unix.so \
           usr/sbin/hostapd usr/sbin/dropbear usr/bin/patronus-cli lib/firmware/ath11k/IPQ6018/hw1.0/board-2.bin lib/firmware/IPQ6018/q6_fw.mdt \
           lib/firmware/IPQ6018/m3_fw.mdt lib/firmware/regulatory.db usr/libexec/patronus/etph-run; do : > "$r/$f"; chmod +x "$r/$f"; done
  ln -s patronus-cli "$r/usr/bin/patronus-web"; cp "$O/etc/patronus/board.sh" "$r/etc/patronus/board.sh"
  cp "$O/usr/libexec/patronus/early" "$O/usr/libexec/patronus/ath11k-caldata" "$r/usr/libexec/patronus/"
  for b in ubinfo ubimkvol ubirmvol ubirsvol ubiupdatevol ubiblock iw ip sha256sum pivot_root; do ln -s /bin/busybox "$r/usr/sbin/$b"; done
  echo x > "$r/lib/modules/6.12.112/modules.dep"; for m in ath11k_ahb qca-nss-dp qca-ssdk mac80211 cfg80211 nf_tables nfnetlink_log nft_reject_inet nf_conntrack; do : > "$r/lib/modules/6.12.112/$m.ko"; done
  printf '\177ELF' > "$r/usr/sbin/etphonehome"; chmod +x "$r/usr/sbin/etphonehome"
  echo INIT=openrc > "$r/etc/patronus-init"; ln -s /usr/sbin/patronus-init "$r/sbin/init"
  for b in openrc-init openrc-run supervise-daemon; do : > "$r/sbin/$b"; chmod +x "$r/sbin/$b"; done
  printf '#!/bin/sh\nexec /sbin/openrc-shutdown -r now "$@"\n' > "$r/sbin/reboot"; chmod +x "$r/sbin/reboot"
  for s in patronus-board patronus-apply patronus-applyd patronus-web dropbear patronus-etph; do : > "$r/etc/init.d/$s"; chmod +x "$r/etc/init.d/$s"; done
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
AP_CHAN5=$ch AP_HT5=80"
  [ "$(seg c$ch vht_oper_centr_freq_seg0_idx)" = $want ] && [ "$(seg c$ch he_oper_centr_freq_seg0_idx)" = $want ] && [ "$(seg c$ch vht_oper_chwidth)" = 1 ] \
    && [ "$(seg c$ch ht_capab)" = "[HT40$dir]" ] && [ "$(seg c$ch channel)" = $ch ] \
    && ok "ap: 5 GHz ch $ch / 80 MHz -> centre $want, HT40$dir" || { no "ap: ch $ch / 80 MHz: seg0=$(seg c$ch vht_oper_centr_freq_seg0_idx) he=$(seg c$ch he_oper_centr_freq_seg0_idx) ht=$(seg c$ch ht_capab)"; cat "$A/c$ch.out"; }
done
for c in 36:38:+ 40:38:- 149:151:+ 153:151:-; do
  ch=${c%%:*}; r=${c#*:}; want=${r%:*}; dir=${r#*:}
  aprender w$ch "$TWO
AP_CHAN5=$ch AP_HT5=40"
  [ "$(seg w$ch vht_oper_centr_freq_seg0_idx)" = $want ] && [ "$(seg w$ch vht_oper_chwidth)" = 0 ] && [ "$(seg w$ch ht_capab)" = "[HT40$dir]" ] \
    && ok "ap: 5 GHz ch $ch / 40 MHz -> centre $want, HT40$dir" || no "ap: ch $ch / 40 MHz: seg0=$(seg w$ch vht_oper_centr_freq_seg0_idx) ht=$(seg w$ch ht_capab)"
done
aprender auto "$TWO
AP_CHAN5=auto AP_HT5=80"
[ "$(seg auto channel)" = 0 ] && ! grep -q 'centr_freq_seg0_idx' "$A/auto/ap5.conf" && [ "$(seg auto vht_oper_chwidth)" = 1 ] \
  && ok "ap: 5 GHz auto (ACS) at 80 MHz leaves the centre channel to hostapd" || no "ap: ACS config wrong: $(grep -E 'channel|centr|chwidth' "$A/auto/ap5.conf" | tr '\n' ' ')"
aprender bad "$TWO
AP_CHAN5=150"
[ "$(seg bad channel)" = 0 ] && grep -q 'not a 5 GHz channel' "$A/bad.out" && ok "ap: an off-raster 5 GHz channel falls back to auto, with a message" || no "ap: AP_CHAN5=150 not handled"
grep -q centr_freq "$A/two/ap24.conf" && no "ap: 2.4 GHz config got a 5 GHz centre channel" || ok "ap: 2.4 GHz config has no VHT/HE centre channel"
[ "$(stat -c %a "$A/two/ap5.conf")" = 600 ] && ok "ap: config is 0600 (holds the keys)" || no "ap: config mode $(stat -c %a "$A/two/ap5.conf")"

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
  # mkimg NAME [board-in-release] [meta-board] [dist] [init]
  mkimg() { n=$1; rb=${2:-glinet,gl-ax1800}; mb=${3:-glinet,gl-ax1800}; dist=${4:-Patronus}; init=${5:-openrc}
    s=$F/src-$n; rm -rf "$s"; mkdir -p "$s/r/etc" "$s/r/usr/sbin" "$s/t/sysupgrade-glinet_gl-ax1800"
    printf 'PATRONUS_TIER=embedded\nBOARD=%s\nBUILD=%s\nINIT=%s\n' "$rb" "$n" "$init" > "$s/r/etc/patronus-release"; echo "INIT=$init" > "$s/r/etc/patronus-init"
    for b in patronus-init patronus-flash etphonehome; do echo x > "$s/r/usr/sbin/$b"; done
    T=$s/t/sysupgrade-glinet_gl-ax1800
    mksquashfs "$s/r" "$T/root" -quiet -noappend -all-root >/dev/null; printf '\320\015\376\355' > "$T/kernel"; head -c 300000 /dev/urandom >> "$T/kernel"
    cp "$s/r/etc/patronus-release" "$T/patronus-release"; [ -n "${TREL:-}" ] && sed -i "s/^BOARD=.*/BOARD=$TREL/" "$T/patronus-release"; echo "CONTROL" > "$T/CONTROL"; (cd "$T" && sha256sum kernel root > patronus.sha256)
    (cd "$s/t" && tar cf "$F/$n.tar" sysupgrade-glinet_gl-ax1800)
    [ "$mb" = none ] || python3 - "$F/$n.tar" "$mb" "$dist" "$D/fwmeta.py" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("fwmeta", sys.argv[4]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
data = open(sys.argv[1], "rb").read()
meta = {"metadata_version": "1.1", "compat_version": "1.0", "supported_devices": [sys.argv[2]], "version": {"dist": sys.argv[3], "version": "t"}}
payload = b"\0" * 8 + (json.dumps(meta) + "\n").encode()
open(sys.argv[1], "ab").write(payload + m.trailer_for(data, payload))
PY
    echo "$F/$n.tar"; }
  PF() { env PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="${COMPAT:-$F/compat}" FW_UBINFO="$F/bin/ubinfo" sh "$O/usr/sbin/patronus-flash" "$@"; }
  good=$(mkimg good)
  t "fwmeta.py reads the test metadata back" python3 "$D/fwmeta.py" show "$good"
  t "flash check: good image" PF check "$good"
  COMPAT=$F/compat-other tn_msg "flash check: refuses on another board" "image is for glinet,gl-ax1800" PF check "$good"
  tn_msg "flash check: refuses an image without metadata" "no image metadata" PF check "$(mkimg nometa glinet,gl-ax1800 none)"
  tn_msg "flash check: refuses metadata for another board" "does not list" PF check "$(mkimg otherboard glinet,gl-ax1800 glinet,gl-mt6000)"
  tn_msg "flash check: refuses an OpenWrt image" "not a Patronus image" PF check "$(mkimg owrt glinet,gl-ax1800 glinet,gl-ax1800 OpenWrt)"
  tn_msg "flash check: refuses a root built for another board" "not for\|not built for" PF check "$(mkimg rootboard glinet,gl-mt6000)"
  tn_msg "flash check: refuses a root image built for another board (tar says this board)" "not built for" PF check "$(TREL=glinet,gl-ax1800 mkimg rootonly glinet,gl-mt6000)"
  tn_msg "flash check: refuses a raw squashfs" "no image metadata\|not a tar" PF check "$F/src-good/t/sysupgrade-glinet_gl-ax1800/root"
  c=$F/corrupt.tar; cp "$good" "$c"; python3 - "$c" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); i = b.find(b"hsqs"); b[i + 600] ^= 0xFF; open(p, "wb").write(bytes(b))
PY
  tn_msg "flash check: refuses a corrupt root (sha256)" "sha256" PF check "$c"
  x=$F/extra.tar; rm -rf "$F/xx"; cp -r "$F/src-nometa/t" "$F/xx"; echo e > "$F/xx/sysupgrade-glinet_gl-ax1800/extra"
  (cd "$F/xx" && tar cf "$x" sysupgrade-glinet_gl-ax1800); python3 "$D/fwmeta.py" add "$x" glinet,gl-ax1800 --version t
  tn_msg "flash check: refuses an unexpected tar member" "unexpected tar member" PF check "$x"
  if env FAKE_KID=0 FAKE_RID=0 FAKE_ROOT_LEBS=160 PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="$F/compat" FW_UBINFO="$F/bin/ubinfo" sh "$O/usr/sbin/patronus-flash" check "$good" >"$W/out" 2>&1; then
    no "flash check: accepted volume ids kernel=0 rootfs=0"; else grep -q "rootfs=0" "$W/out" && ok "flash check: refuses a UBI whose rootfs is not volume 1" || { no "flash check: wrong volume ids, wrong message"; cat "$W/out"; }; fi
  # a root that needs more LEBs than volume + free
  big=$(mkimg big); if env FAKE_ROOT_LEBS=0 FAKE_AVAIL=0 PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="$F/compat" FW_UBINFO="$F/bin/ubinfo" sh "$O/usr/sbin/patronus-flash" check "$big" >"$W/out" 2>&1; then
    no "flash check: accepted an image that does not fit"; else grep -q "more LEBs" "$W/out" && ok "flash check: refuses an image that does not fit the UBI" || { no "flash check: no-room case, wrong message"; cat "$W/out"; }; fi
  t "flash sysupgrade: stages a good image" PF sysupgrade "$good"
  [ -f "$F/data/.upgrade/ready" ] && [ -s "$F/data/.upgrade/root" ] && [ ! -e "$F/data/.upgrade.new" ] && ok "staged: ready marker + parts" || no "staged layout wrong: $(ls -a "$F/data" "$F/data/.upgrade" 2>&1)"
  tn_msg "flash sysupgrade: refuses a second staging" "already staged" PF sysupgrade "$good"
  UV() { env PATH="$F/bin:$PATH" PATRONUS_DATA="$F/data" PATRONUS_LIB="$LIB" PATRONUS_DT_COMPAT="${COMPAT:-$F/compat}" FW_UBINFO="$F/bin/ubinfo" sh "$LIB/upgrade-install" verify; }
  t "upgrade-install verify: accepts the staged image (early boot re-check)" UV
  COMPAT=$F/compat-other tn "upgrade-install verify: refuses on another board" UV
  [ -d "$F/data/.upgrade-rejected" ] && [ ! -e "$F/data/.upgrade" ] && ok "rejected upgrade moved aside (normal boot goes on)" || no "rejected upgrade not moved aside"
  t "flash sysupgrade: stage again after a rejection" PF sysupgrade "$good"
  printf 'x' >> "$F/data/.upgrade/root"; tn "upgrade-install verify: refuses a staged root changed after staging" UV
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

echo "ax1800 tooling tests: $pass passed, $failn failed, $skip skipped"
[ "$failn" = 0 ]
