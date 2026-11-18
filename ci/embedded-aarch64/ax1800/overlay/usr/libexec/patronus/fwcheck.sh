#!/bin/sh
# fwcheck.sh: image validation shared by patronus-flash (staging an upgrade) and the early-boot installer (re-checked
# right before anything is written). Sourced, POSIX sh + busybox. Nothing here writes to flash.
# A Patronus GL-AX1800 upgrade image is the sysupgrade tar assemble.sh makes:
#   sysupgrade-glinet_gl-ax1800/{CONTROL,kernel,root,patronus-release,patronus.sha256} + OpenWrt fwtool metadata trailer
# Checks (each one fails closed):
#   - this box is a GL-AX1800 (device tree compatible), so an image is never written to another board
#   - fwtool metadata: present, supported_devices lists this board, dist is Patronus
#   - RELEASE SIGNATURE: the metadata's `patronus_sig` is a valid OpenPGP signature of patronus.sha256 by a key in the box's
#     release keyring (FW_KEYRING, the Errant Solutions release key built into this firmware); checked with gpgv BEFORE the root
#     image is opened, so an unsigned, foreign-signed or modified image is refused before anything parses it
#   - the tar holds exactly the board's sysupgrade directory; sha256 of kernel and root match patronus.sha256
#   - kernel is a FIT (FDT magic), root is a squashfs whose /etc/patronus-release names this board and whose
#     /etc/patronus-init is openrc or systemd, with patronus-init and ETPhoneHome inside
#   - kernel + root fit the UBI device (current volumes + free LEBs), the settings volume keeps FW_DATA_MIN_KIB
# Test hooks: PATRONUS_DT_COMPAT (compatible file), PATRONUS_UBI, FW_UBINFO (ubinfo command), FW_DATA_MIN_KIB, FW_KEYRING.
FW_BOARD=glinet,gl-ax1800
FW_DIR=sysupgrade-glinet_gl-ax1800
FW_LEB=126976
FW_DATA_MIN_KIB=${FW_DATA_MIN_KIB:-4096}
FW_KEYRING=${FW_KEYRING:-/usr/share/openpgp-keys/errantsolutions.gpg}

fw_err() { echo "patronus-flash: REFUSED: $*" >&2; logger -t patronus-flash "REFUSED: $*" 2>/dev/null; return 1; }

fw_board_ok() {
  c=${PATRONUS_DT_COMPAT:-/proc/device-tree/compatible}
  [ -r "$c" ] || { fw_err "cannot read the board's device tree compatible ($c)"; return 1; }
  tr '\0' '\n' < "$c" | grep -x "$FW_BOARD" >/dev/null || fw_err "this board is '$(tr '\0' ' ' < "$c")', the image is for $FW_BOARD"
}

# fw_meta <file>: print the fwtool metadata JSON (OpenWrt fwimage trailer: 'FWx0' crc type pad size, big-endian)
fw_meta() {
  n=$(wc -c < "$1"); [ "$n" -gt 64 ] || return 1
  t=$(tail -c 16 "$1" | od -An -tx1 -v | tr -d ' \n')
  [ "$(echo "$t" | cut -c1-8)" = 46577830 ] && [ "$(echo "$t" | cut -c17-18)" = 01 ] || return 1
  size=$(( 0x$(echo "$t" | cut -c25-32) )); [ "$size" -gt 24 ] && [ "$size" -lt "$n" ] || return 1
  tail -c "$size" "$1" | head -c $((size - 16)) | tail -c +9
}

fw_meta_ok() {
  m=$(fw_meta "$1") || { fw_err "$1 has no image metadata (not a Patronus sysupgrade image)"; return 1; }
  echo "$m" | tr -d ' \n' | grep '"supported_devices":\[[^]]*"'"$FW_BOARD"'"' >/dev/null || { fw_err "image metadata does not list $FW_BOARD"; return 1; }
  echo "$m" | tr -d ' \n' | grep '"dist":"Patronus"' >/dev/null || fw_err "image metadata is not a Patronus image (use OpenWrt's own sysupgrade for OpenWrt images)"
}

# fw_sig_extract <image> <out>: the binary signature from the metadata's "patronus_sig" (base64) into <out>; 1 = none
fw_sig_extract() {
  s=$(fw_meta "$1" | tr -d ' \n' | sed -n 's/.*"patronus_sig":"\([A-Za-z0-9+/=]*\)".*/\1/p')
  [ -n "$s" ] || return 1
  printf '%s' "$s" | base64 -d > "$2" 2>/dev/null && [ -s "$2" ]
}

# fw_sig_ok <dir>: <dir>/patronus.sha256.sig is a good signature of <dir>/patronus.sha256 by a release key of this box
fw_sig_ok() {
  d=$1
  [ -s "$d/patronus.sha256.sig" ] || { fw_err "the image is not signed (no release signature): unsigned firmware is never installed"; return 1; }
  [ -s "$FW_KEYRING" ] || { fw_err "no release signing key on this box ($FW_KEYRING): cannot check the image"; return 1; }
  command -v gpgv >/dev/null 2>&1 || { fw_err "gpgv is missing: cannot check the release signature"; return 1; }
  g=$d/.gnupg; rm -rf "$g"; mkdir -p "$g" && chmod 700 "$g"
  # --ignore-time-conflict: the board has no RTC, and the early boot re-verifies a staged upgrade before the clock is set
  # (1970), so the key and every signature look "made in the future"; the time of a release signature proves nothing here
  st=$(GNUPGHOME=$g gpgv --ignore-time-conflict --status-fd 1 --keyring "$FW_KEYRING" "$d/patronus.sha256.sig" "$d/patronus.sha256" 2>/dev/null); rm -rf "$g"
  fp=$(echo "$st" | sed -n 's/^\[GNUPG:\] VALIDSIG \([0-9A-F]*\) .*/\1/p' | head -1)
  [ -n "$fp" ] || { fw_err "release signature check FAILED: the image was modified or is not signed by the Patronus release key"; return 1; }
  echo "signature: good, release key $fp" >&2
}

# fw_root_file <root.squashfs> <path>: print one file of the squashfs (unsquashfs when there is one, else a loop mount)
fw_root_file() {
  if command -v unsquashfs >/dev/null 2>&1; then unsquashfs -cat "$1" "$2" 2>/dev/null; return; fi
  mp=$(mktemp -d /tmp/fwroot.XXXXXX) || return 1
  if mount -t squashfs -o loop,ro "$1" "$mp" 2>/dev/null; then cat "$mp/$2" 2>/dev/null; rc=$?; umount "$mp"; else rc=1; fi
  rmdir "$mp"; return $rc
}
fw_root_has() {
  if command -v unsquashfs >/dev/null 2>&1; then unsquashfs -lls "$1" "$2" 2>/dev/null | grep -E " squashfs-root/$2( |\$)" >/dev/null; return; fi
  mp=$(mktemp -d /tmp/fwroot.XXXXXX) || return 1
  if mount -t squashfs -o loop,ro "$1" "$mp" 2>/dev/null; then [ -e "$mp/$2" ] || [ -L "$mp/$2" ]; rc=$?; umount "$mp"; else rc=1; fi
  rmdir "$mp"; return $rc
}

fw_magic() { head -c 4 "$1" | od -An -tx1 | tr -d ' \n'; }

# fw_ubi_room <kernel> <root>: kernel and root fit the UBI device (the installer resizes volumes 0 and 1 in place)
fw_ubi_room() {
  U=${PATRONUS_UBI:-/dev/ubi0}; ui=${FW_UBINFO:-ubinfo}
  [ -e "$U" ] || [ -n "${FW_UBINFO:-}" ] || { fw_err "no UBI device $U"; return 1; }
  volleb() { $ui "$U" -N "$1" 2>/dev/null | sed -n 's/^Size: *\([0-9]*\) LEBs.*/\1/p'; }
  avail=$($ui "$U" 2>/dev/null | sed -n 's/^Amount of available logical eraseblocks: *\([0-9]*\).*/\1/p')
  kv=$(volleb kernel); rv=$(volleb rootfs)
  [ -n "$avail" ] && [ -n "$kv" ] && [ -n "$rv" ] || { fw_err "cannot read the UBI layout (kernel/rootfs volumes)"; return 1; }
  kid=$($ui "$U" -N kernel 2>/dev/null | sed -n 's/^Volume ID: *\([0-9]*\).*/\1/p'); rid=$($ui "$U" -N rootfs 2>/dev/null | sed -n 's/^Volume ID: *\([0-9]*\).*/\1/p')
  [ "$kid" = 0 ] && [ "$rid" = 1 ] || { fw_err "UBI volumes kernel=$kid rootfs=$rid, the board boots kernel=0 rootfs=1 (reinstall with factory.ubi)"; return 1; }
  kn=$(( ($(wc -c < "$1") + FW_LEB - 1) / FW_LEB )); rn=$(( ($(wc -c < "$2") + FW_LEB - 1) / FW_LEB ))
  grow=0; [ "$kn" -gt "$kv" ] && grow=$((grow + kn - kv)); [ "$rn" -gt "$rv" ] && grow=$((grow + rn - rv))
  [ "$grow" -le "$avail" ] || { fw_err "image needs $grow more LEBs than the UBI device has free ($avail)"; return 1; }
  # patronus_data (or OpenWrt's rootfs_data) is not shrunk: it must already leave room, nothing else to check
  echo "ubi: kernel $kn LEBs (volume $kv), root $rn LEBs (volume $rv), free $avail" >&2
}

# fw_check_parts <dir>: the extracted parts are a valid, complete Patronus image for this board
fw_check_parts() {
  d=$1
  for f in kernel root patronus.sha256 patronus-release; do [ -s "$d/$f" ] || { fw_err "image has no $f"; return 1; }; done
  (cd "$d" && grep -E '^[0-9a-f]{64}  (kernel|root)$' patronus.sha256 | sha256sum -c - >/dev/null 2>&1) || { fw_err "sha256 of kernel/root does not match patronus.sha256 (corrupt download?)"; return 1; }
  [ "$(grep -cE '^[0-9a-f]{64}  (kernel|root)$' "$d/patronus.sha256")" = 2 ] || { fw_err "patronus.sha256 must list kernel and root"; return 1; }
  fw_sig_ok "$d" || return 1
  [ "$(fw_magic "$d/kernel")" = d00dfeed ] || { fw_err "kernel is not a FIT image"; return 1; }
  [ "$(fw_magic "$d/root")" = 68737173 ] || { fw_err "root is not a squashfs"; return 1; }
  grep -qx "BOARD=$FW_BOARD" "$d/patronus-release" || { fw_err "patronus-release is not for $FW_BOARD"; return 1; }
  rel=$(fw_root_file "$d/root" etc/patronus-release) || { fw_err "cannot read /etc/patronus-release from the root image"; return 1; }
  echo "$rel" | grep -x "BOARD=$FW_BOARD" >/dev/null || { fw_err "the root image is not built for $FW_BOARD"; return 1; }
  [ "$rel" = "$(cat "$d/patronus-release")" ] || { fw_err "root image and tar disagree about the build (patronus-release)"; return 1; }
  init=$(fw_root_file "$d/root" etc/patronus-init)
  case "$init" in INIT=openrc|INIT=systemd) ;; *) fw_err "root image has no OpenRC/systemd init record ($init)"; return 1;; esac
  for f in usr/sbin/patronus-init usr/sbin/patronus-flash usr/sbin/etphonehome; do
    fw_root_has "$d/root" "$f" || { fw_err "root image lacks /$f"; return 1; }; done
  fw_ubi_room "$d/kernel" "$d/root"
}

# fw_check_tar <image.tar> <outdir>: board + metadata + layout checks, parts extracted into <outdir> and checked
fw_check_tar() {
  img=$1; out=$2
  [ -f "$img" ] || { fw_err "no such file $img"; return 1; }
  fw_board_ok || return 1
  fw_meta_ok "$img" || return 1
  list=$(tar tf "$img" 2>/dev/null) || { fw_err "$img is not a tar (sysupgrade image)"; return 1; }
  for m in $list; do case "$m" in "$FW_DIR"/|"$FW_DIR"/CONTROL|"$FW_DIR"/kernel|"$FW_DIR"/root|"$FW_DIR"/patronus-release|"$FW_DIR"/patronus.sha256) ;;
    *) fw_err "unexpected tar member '$m' (an image for another board?)"; return 1;; esac; done
  mkdir -p "$out" && tar xf "$img" -C "$out" 2>/dev/null || { fw_err "cannot unpack $img into $out (space?)"; return 1; }
  for f in kernel root patronus.sha256 patronus-release; do [ -f "$out/$FW_DIR/$f" ] && mv "$out/$FW_DIR/$f" "$out/$f"; done
  rm -rf "${out:?}/$FW_DIR"
  rm -f "$out/patronus.sha256.sig"; fw_sig_extract "$img" "$out/patronus.sha256.sig" || rm -f "$out/patronus.sha256.sig"
  fw_check_parts "$out"
}
