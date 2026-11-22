#!/bin/sh
# nor-kernel-test.sh: the NOR kernel trial + rollback of the GL-AR750S, end to end on a host (docs/embedded-routers.md 6e).
#   sh nor-kernel-test.sh [ubsim-binary]
# - flash: fake MTD partitions (files) with the board's real layout; flash_erase writes 0xff like NOR; power cuts are injected
#   by killing nor-kernel right after the N-th erase (CUT_AT=N), i.e. with that region blank
# - device tools: nor-kernel runs under busybox sh with ONLY busybox applets on PATH (the unit's tool set: xxd, crc32, awk ...)
# - bootloader: every power-on is ubsim (tests/uboot-sim): GL's own hush parser + test/echo/run at a pinned commit, the GL
#   main_loop for the AR750S, the build's default environment when the stored one has a bad CRC, uImage CRC checks in bootm
# - kernels: fake lzma uImages carrying the board's DT compatible (CI), or with REAL=<dir> the real ones:
#   REAL dir holds u-boot.bin (the unit's u-boot partition), kernel-old.bin, kernel-new.bin (OpenWrt uImages)
set -u
D=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/nk-test.XXXX"); trap 'rm -rf "$W"' EXIT
pass=0; failn=0
ok() { echo "PASS: $*"; pass=$((pass+1)); }
no() { echo "FAIL: $*"; failn=$((failn+1)); }
check() { name=$1; shift; if "$@" >"$W/out" 2>&1; then ok "$name"; else no "$name"; sed 's/^/    /' "$W/out" | tail -n 30; fi; }

UBSIM=${1:-}
if [ -z "$UBSIM" ]; then sh "$D/tests/uboot-sim/build.sh" "$W/ubs" >"$W/build.log" 2>&1 || { cat "$W/build.log"; echo "FAIL: ubsim build"; exit 1; }; UBSIM=$W/ubs/ubsim; fi
command -v busybox >/dev/null || { echo "FAIL: busybox needed (the device tool set)"; exit 1; }
DEFENV=$D/overlay/usr/share/patronus/uboot/gl-ar750s-1.1.4-gcf378d80.env
NK=$D/overlay/usr/libexec/patronus/nor-kernel
BOARDCOMPAT=glinet,gl-ar750s-nor-nand

# --- device tool set: busybox applets only, plus flash_erase (mtd-utils on the unit) and a quiet logger ---
mkdir -p "$W/bb"; for a in $(busybox --list); do ln -s "$(command -v busybox)" "$W/bb/$a"; done
rm -f "$W/bb/logger"; printf '#!/bin/sh\nexit 0\n' > "$W/bb/logger"
cat > "$W/bb/flash_erase" <<'EOF'
#!/bin/sh
# flash_erase [-q] <dev> <offset> <blocks>: NOR erase = 0xff; erase size from the fake /proc/mtd. CUT_AT: power cut after the
# N-th erase (the erased region stays blank, the caller is killed before it writes)
[ "$1" = -q ] && shift; dev=$1 off=$(($2)) n=$3; name=${dev##*/}
es=$((0x$(grep "^$name:" "$PATRONUS_PROC_MTD" | cut -d' ' -f3)))
c=$(($(cat "$NK_ERASES" 2>/dev/null || echo 0) + 1)); echo $c > "$NK_ERASES"; echo "$name $off $n" >> "$NK_ERASES.log"
tr '\000' '\377' < /dev/zero | head -c $((es * n)) | dd of="$dev" bs="$es" seek=$((off / es)) conv=notrunc 2>/dev/null
if [ -n "${CUT_AT:-}" ] && [ "$c" = "$CUT_AT" ]; then kill -9 $PPID; exit 1; fi
EOF
chmod 755 "$W/bb/flash_erase" "$W/bb/logger"

# --- images ---
mkimg() { # out kver [compat] [pad-bytes]: an lzma uImage named like OpenWrt's, whose payload carries the DT compatible
  python3 - "$@" <<'EOF'
import sys, lzma, struct, zlib, os
out, kver = sys.argv[1], sys.argv[2]; compat = sys.argv[3] if len(sys.argv) > 3 else 'glinet,gl-ar750s-nor-nand'
pad = int(sys.argv[4]) if len(sys.argv) > 4 else 300000
# like a real FDT: the root "compatible" property header (FDT_PROP, len, nameoff) directly before the strings, nameoff non-zero
val = compat.encode() + b'\0qca,qca9563\0'
payload = b'Linux version ' + kver.encode() + b'\0' + os.urandom(pad) + struct.pack('>III', 3, len(val), 0x1b) + val
data = lzma.compress(payload, format=lzma.FORMAT_ALONE, preset=0)
name = ('MIPS OpenWrt Linux-' + kver).encode()[:32].ljust(32, b'\0')
h = struct.pack('>IIIIIIIBBBB', 0x27051956, 0, 0, len(data), 0x80060000, 0x80060000, zlib.crc32(data), 5, 5, 2, 3) + name
h = h[:4] + struct.pack('>I', zlib.crc32(h)) + h[8:]
open(out, 'wb').write(h + data)
EOF
}
if [ -n "${REAL:-}" ]; then
  cp "$REAL/u-boot.bin" "$W/u-boot.bin"; cp "$REAL/kernel-old.bin" "$W/kold"; cp "$REAL/kernel-new.bin" "$W/knew"
else
  python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(0x40000))" "$W/u-boot.bin"
  mkimg "$W/kold" 6.12.112; mkimg "$W/knew" 6.12.118
fi
KOLD=$(dd if="$W/kold" bs=1 skip=32 count=32 2>/dev/null | tr -d '\000'); KOLD=${KOLD##*Linux-}
KNEW=$(dd if="$W/knew" bs=1 skip=32 count=32 2>/dev/null | tr -d '\000'); KNEW=${KNEW##*Linux-}
mkimg "$W/kbad-board" 6.12.118 glinet,gl-ar300m-nor
mkimg "$W/kprefix" 6.12.118 xglinet,gl-ar750s-nor-nand
mkimg "$W/kbig" 6.12.118 "$BOARDCOMPAT" 0; python3 -c "
import sys,struct,zlib,os
d=os.urandom(0x400000); n=b'MIPS OpenWrt Linux-6.12.118'.ljust(32,b'\0')
h=struct.pack('>IIIIIIIBBBB',0x27051956,0,0,len(d),0x80060000,0x80060000,zlib.crc32(d),5,5,2,3)+n; h=h[:4]+struct.pack('>I',zlib.crc32(h))+h[8:]
open(sys.argv[1],'wb').write(h+d)" "$W/kbig"
mkimg "$W/k999" 6.12.999
cp "$W/knew" "$W/kcorrupt"; printf 'X' | dd of="$W/kcorrupt" bs=1 seek=5000 conv=notrunc 2>/dev/null

python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(0x10000)); open(sys.argv[2],'wb').write(os.urandom(0xba0000))" "$W/art.bin" "$W/stale.bin"
# --- unit: fake /proc/mtd + partitions, root (modules, release, shipped kernels), board ---
newunit() {
  rm -rf "$W/u"; mkdir -p "$W/u/dev" "$W/u/run" "$W/u/data" "$W/u/lib/modules/$KOLD" "$W/u/lib/modules/$KNEW" "$W/u/kernels"
  cat > "$W/u/proc_mtd" <<'EOF'
dev:    size   erasesize  name
mtd0: 00040000 00010000 "u-boot"
mtd1: 00010000 00010000 "u-boot-env"
mtd2: 00010000 00010000 "art"
mtd3: 00400000 00010000 "kernel"
mtd4: 00ba0000 00010000 "nor_reserved"
mtd5: 08000000 00020000 "ubi"
EOF
  cp "$W/u-boot.bin" "$W/u/dev/mtd0"
  ff() { tr '\000' '\377' < /dev/zero | head -c $(($1)); }
  ff 0x10000 > "$W/u/dev/mtd1"                                  # the stock unit: environment never saved
  cp "$W/art.bin" "$W/u/dev/mtd2"                               # art (calibration)
  { cat "$W/kold"; ff $((0x400000 - $(wc -c < "$W/kold"))); } > "$W/u/dev/mtd3"
  cp "$W/stale.bin" "$W/u/dev/mtd4"                             # stale GL stock data
  echo kernel > "$W/u/lib/modules/$KOLD/modules.dep"; echo kernel > "$W/u/lib/modules/$KNEW/modules.dep"
  echo "BOARD=$BOARDCOMPAT" > "$W/u/release"
  cp "$W/knew" "$W/u/kernels/$KNEW.uImage"; cp "$W/kold" "$W/u/kernels/$KOLD.uImage"
  cp "$W/kbad-board" "$W/kprefix" "$W/kbig" "$W/k999" "$W/u/kernels/" ; (cd "$W/u/kernels" && sha256sum * > SHA256SUMS)
  mkdir -p "$W/u/envdir"; cp "$DEFENV" "$W/u/envdir/"
  { echo ". '$D/overlay/etc/patronus/board.sh' 2>/dev/null"
    echo "KSLOT_UBOOT_PROVEN='$(sha256sum < "$W/u-boot.bin" | cut -d' ' -f1):/usr/share/patronus/uboot/${DEFENV##*/}'"
    echo "KSLOT_KERNEL_DIR='$W/u/kernels'"; } > "$W/u/board.sh"
  sha256sum < "$W/u/dev/mtd0" > "$W/u/mtd0.sha"; sha256sum < "$W/u/dev/mtd2" > "$W/u/mtd2.sha"
  rm -f "$W/erases" "$W/erases.log"; RUNNING=$KOLD
}
nk() { # nor-kernel as the unit runs it (busybox sh, busybox applets only)
  env -i PATH="$W/bb" HOME=/ PATRONUS_BOARD="$W/u/board.sh" PATRONUS_PROC_MTD="$W/u/proc_mtd" PATRONUS_MTD_DEV="$W/u/dev" \
    PATRONUS_MODULES="$W/u/lib/modules" PATRONUS_KSTATE="$W/u/data/kernel" PATRONUS_GUARD_RUN="$W/u/run" PATRONUS_FLASH_TMP="$W/u" \
    PATRONUS_RELEASE="$W/u/release" PATRONUS_UBOOT_ENV_DIR="$W/u/envdir" PATRONUS_UNAME_R="$RUNNING" NK_ERASES="$W/erases" \
    ${CUT_AT:+CUT_AT=$CUT_AT} ${FORCE:+FORCE=$FORCE} busybox sh "$NK" "$@"
}
# one power-on: U-Boot (ubsim) on the joined NOR image, then (if a kernel booted and reached userspace) the early-boot check
power_on() { # [noboot]: the booted kernel hangs before userspace
  cat "$W/u/dev/mtd0" "$W/u/dev/mtd1" "$W/u/dev/mtd2" "$W/u/dev/mtd3" "$W/u/dev/mtd4" > "$W/nor.bin"
  "$UBSIM" "$W/nor.bin" "$DEFENV" > "$W/boot.log" 2>&1
  dd if="$W/nor.bin" of="$W/u/dev/mtd1" bs=65536 skip=4 count=1 2>/dev/null   # saveenv is the only write U-Boot does
  BOOTED=$(sed -n 's/^BOOT //p' "$W/boot.log"); BADDR=${BOOTED%% *}; BNAME=${BOOTED#* }
  [ -n "$BOOTED" ] || { BADDR=FAILSAFE; RUNNING=; echo "power-on: FAILSAFE"; return 0; }
  RUNNING=${BNAME##*Linux-}; echo "power-on: U-Boot booted $BADDR ($RUNNING)"
  rm -f "$W/u/run/kernel-trial"; [ "${1:-}" = noboot ] && return 0
  nk boot-check; BC=$?; return 0
}
untouched() { [ "$(sha256sum < "$W/u/dev/mtd0")" = "$(cat "$W/u/mtd0.sha")" ] && [ "$(sha256sum < "$W/u/dev/mtd2")" = "$(cat "$W/u/mtd2.sha")" ]; }
slotsha() { nk kver-of "$1"; }
pslot() { nk kver-of P; }
envv() { nk env-get "$1"; }
snap() { cat "$W/u/dev/mtd1" "$W/u/dev/mtd3" "$W/u/dev/mtd4" | sha256sum; }
wait_state() { j=0; while [ $j -lt 60 ]; do [ "$(envv pat_state)" = "$1" ] && return 0; sleep 1; j=$((j+1)); done; return 1; }

echo "== kernels: old $KOLD, new $KNEW ($([ -n "${REAL:-}" ] && echo real images || echo fake images)) =="

# 1. stock unit: U-Boot boots the committed kernel with the default environment
newunit; power_on >/dev/null
check "stock: U-Boot boots the kernel partition (default env)" sh -c "[ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KOLD' ] && grep -q 'bad CRC, using default environment' '$W/boot.log'"

# 2. install gates: nothing on flash changes when an install is refused
s0=$(snap)
t_ref() { name=$1 pat=$2; shift 2; nk install "$@" > "$W/r" 2>&1; rc=$?
  if [ $rc -ne 0 ] && grep -q "$pat" "$W/r" && [ "$(snap)" = "$s0" ] && untouched; then ok "refused: $name"; else no "refused: $name (rc $rc)"; sed 's/^/    /' "$W/r"; fi; }
t_ref "image with a bad data CRC" "not a valid uImage" "$W/kcorrupt"
t_ref "kernel for another board" "device tree is not for" "$W/u/kernels/kbad-board"
t_ref "kernel whose compatible only ends in the board string" "device tree is not for" "$W/u/kernels/kprefix"
t_ref "kernel larger than a slot" "larger than" "$W/u/kernels/kbig"
t_ref "kernel this root has no modules for" "no modules for 6.12.999" "$W/u/kernels/k999"
cp "$W/knew" "$W/knew-unlisted"; printf 'Z' >> "$W/knew-unlisted"
t_ref "kernel the root does not ship (not in SHA256SUMS)" "is not one this root ships" "$W/knew-unlisted"
mv "$W/u/release" "$W/u/release.x"; t_ref "no BOARD= in the release file" "no BOARD=" "$KNEW"; mv "$W/u/release.x" "$W/u/release"
cp "$W/u/board.sh" "$W/u/board.ok"; echo "KSLOT_UBOOT_PROVEN='0000:/x'" >> "$W/u/board.sh"
t_ref "bootloader build the trial script was not proven on" "not one the trial script was proven on" "$KNEW"; cp "$W/u/board.ok" "$W/u/board.sh"
echo "KSLOT_T_MTD=u-boot" >> "$W/u/board.sh"; t_ref "a slot configured on the u-boot partition" "refusing to write the u-boot partition" "$KNEW"
cp "$W/u/board.ok" "$W/u/board.sh"; echo "KSLOT_T_MTD=art" >> "$W/u/board.sh"; t_ref "a slot configured on the art partition" "refusing to write the art partition" "$KNEW"
cp "$W/u/board.ok" "$W/u/board.sh"

# 3. good trial: install -> trial boot -> commit -> the new kernel is the default, the old one kept in K
newunit; power_on >/dev/null
check "install $KNEW (trial armed)" nk install "$KNEW"
check "install wrote only u-boot-env + the T slot; u-boot/art/kernel untouched" sh -c "untouched() { [ \"\$(sha256sum < '$W/u/dev/mtd0')\" = \"\$(cat '$W/u/mtd0.sha')\" ] && [ \"\$(sha256sum < '$W/u/dev/mtd2')\" = \"\$(cat '$W/u/mtd2.sha')\" ]; }; untouched && ! grep -qv -e '^mtd1 ' -e '^mtd4 0 ' '$W/erases.log'"
check "kernel partition still holds $KOLD after install" sh -c "[ '$(pslot)' = '$KOLD' ]"
power_on >/dev/null
check "power-on 1: U-Boot boots the TRIAL slot ($KNEW) and counts it" sh -c "[ '$BADDR' = 0x9f460000 ] && [ '$RUNNING' = '$KNEW' ] && grep -q 'patronus: trial kernel $KNEW boot ox' '$W/boot.log' && [ -f '$W/u/run/kernel-trial' ]"
check "commit after a confirmed trial boot" nk commit
check "after commit: P=$KNEW, K=$KOLD, T=$KNEW, state committed" sh -c "[ '$(nk kver-of P)' = '$KNEW' ] && [ '$(nk kver-of K)' = '$KOLD' ] && [ '$(nk kver-of T)' = '$KNEW' ] && [ '$(envv pat_state)' = committed ] && [ -z '$(envv pat_try)' ]"
power_on >/dev/null
check "power-on 2: U-Boot boots the kernel partition = $KNEW, no trial" sh -c "[ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KNEW' ] && ! grep -q 'trial kernel' '$W/boot.log'"
check "u-boot + art never written in the whole sequence" untouched
s1=$(snap); nk install "$KNEW" > "$W/r" 2>&1
check "install of the committed kernel again is a no-op" sh -c "grep -q 'already the committed kernel' '$W/r' && [ '$(snap)' = '$s1' ]"

# 4. kernel rollback: K back into the kernel partition
check "kernel-rollback to $KOLD" nk rollback
power_on >/dev/null
check "after rollback U-Boot boots $KOLD from the kernel partition; T keeps $KNEW" sh -c "[ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KOLD' ] && [ '$(nk kver-of T)' = '$KNEW' ]"

# 5. trial kernel that never reaches userspace: U-Boot gives up after KSLOT_TRIES boots, P untouched
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; p0=$(sha256sum < "$W/u/dev/mtd3")
power_on noboot >/dev/null; b1=$BADDR; power_on noboot >/dev/null; b2=$BADDR; power_on noboot >/dev/null; b3=$BADDR; power_on >/dev/null
check "hanging trial kernel: 3 trial boots, then U-Boot falls back to $KOLD by itself" sh -c "[ '$b1 $b2 $b3' = '0x9f460000 0x9f460000 0x9f460000' ] && [ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KOLD' ] && [ '$(sha256sum < "$W/u/dev/mtd3")' = '$p0' ]"
check "  early boot records that U-Boot gave up (state failed-seen, event)" sh -c "[ '$(envv pat_state)' = failed-seen ] && grep -q 'gave up on the trial kernel' '$W/u/data/kernel/events'"
power_on >/dev/null; check "  and keeps booting $KOLD" sh -c "[ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KOLD' ]"

# 6. trial boots but is not confirmed: the guard aborts it, next boot = committed kernel
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null
check "unconfirmed trial boot: abort" sh -c "[ '$RUNNING' = '$KNEW' ]" ; nk abort "boot not confirmed" >/dev/null 2>&1
power_on >/dev/null; check "  next power-on boots $KOLD" sh -c "[ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KOLD' ]"

# 7. the trial slot is unreadable for U-Boot (corrupted after arming): falls through to the committed kernel at once
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1
printf 'X' | dd of="$W/u/dev/mtd4" bs=1 seek=4000 conv=notrunc 2>/dev/null
power_on >/dev/null; check "corrupted trial slot: U-Boot's bootm refuses it and boots $KOLD in the same power-on" sh -c "grep -q 'Bad Data CRC' '$W/boot.log' && [ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KOLD' ]"
check "  early boot aborts the trial (the trial kernel did not start)" sh -c "grep -q 'did not start' '$W/u/data/kernel/events' && [ -z '$(envv pat_try)' ]"

# 8. trial kernel without modules in this root: early boot aborts at once (rc 3 -> the early boot restarts)
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; rm -rf "$W/u/lib/modules/$KNEW"
power_on >/dev/null; check "trial kernel without modules in the root: boot-check aborts (rc 3)" sh -c "[ '$BC' = 3 ] && [ -z '$(envv pat_try)' ]"
power_on >/dev/null; check "  next power-on boots $KOLD" sh -c "[ '$RUNNING' = '$KOLD' ]"

# 9. power cuts: at every flash erase of install and of commit; after the cut every power-on must boot a kernel, and a
#    re-run (install again / commit / the early-boot resume) must end in a consistent state
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; NI=$(cat "$W/erases"); rm -f "$W/erases"
power_on >/dev/null; nk commit >/dev/null 2>&1; NC=$(cat "$W/erases")
echo "   (install = $NI erases, commit = $NC erases)"
i=1; while [ $i -le "$NI" ]; do
  newunit; power_on >/dev/null; CUT_AT=$i nk install "$KNEW" >/dev/null 2>&1; rm -f "$W/erases"
  power_on >/dev/null; b=$RUNNING
  [ -z "$(envv pat_try)" ] || { power_on >/dev/null; }
  check "power cut at install erase $i/$NI: boots ($b), install re-run succeeds" sh -c "[ -n '$b' ]"
  nk abort x >/dev/null 2>&1; nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null
  check "  then the trial boots $KNEW" sh -c "[ '$RUNNING' = '$KNEW' ] && [ '$BADDR' = 0x9f460000 ]"
  i=$((i+1)); done
i=1; while [ $i -le "$NC" ]; do
  newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null; rm -f "$W/erases"
  CUT_AT=$i nk commit >/dev/null 2>&1; rm -f "$W/erases"
  power_on >/dev/null; b1="$BADDR $RUNNING"
  # the early boot resumes an interrupted commit; if the cut blanked the environment, U-Boot ran its defaults (the kernel
  # partition, still intact at that point) and the operator simply installs again
  wait_state committed >/dev/null 2>&1 || { [ "$(envv pat_state)" = "" ] && { nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null; }; nk commit >/dev/null 2>&1; }
  power_on >/dev/null
  check "power cut at commit erase $i/$NC: first power-on boots a kernel ($b1), ends committed on $KNEW" sh -c "[ '${b1#* }' != '' ] && [ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KNEW' ] && [ '$(nk kver-of K)' = '$KOLD' ]"
  i=$((i+1)); done

# 10. the cut that matters most: the kernel partition erased (blank) mid-commit -> U-Boot's bootcmd rescue boots slot T
nth_erase() { grep -n "^$1 " "$W/erases.log" | head -n1 | cut -d: -f1; }   # index of the first erase of a partition
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null; rm -f "$W/erases" "$W/erases.log"
CUT_AT=999 nk commit >/dev/null 2>&1; PE=$(nth_erase mtd3)
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null; rm -f "$W/erases" "$W/erases.log"
CUT_AT=$PE nk commit >/dev/null 2>&1; blank=$(tr -d '\377' < "$W/u/dev/mtd3" | wc -c)
power_on noboot >/dev/null
check "kernel partition blank after a cut: bootm fails, bootcmd's pat_rescue boots slot T ($KNEW)" sh -c "[ '$blank' = 0 ] && grep -q 'Bad Magic Number' '$W/boot.log' && [ '$BADDR' = 0x9f460000 ] && [ '$RUNNING' = '$KNEW' ]"
nk boot-check >/dev/null 2>&1; wait_state committed >/dev/null 2>&1
power_on >/dev/null; check "  the early boot resumes the commit; next power-on boots $KNEW from the kernel partition" sh -c "[ '$BADDR' = 0x9f060000 ] && [ '$RUNNING' = '$KNEW' ] && [ '$(nk kver-of K)' = '$KOLD' ]"

# 11. environment erased by a cut (bad CRC): U-Boot uses its defaults = the committed kernel; a new install works
newunit; power_on >/dev/null; rm -f "$W/erases" "$W/erases.log"; CUT_AT=999 nk install "$KNEW" >/dev/null 2>&1; EE=$(nth_erase mtd1)
newunit; power_on >/dev/null; rm -f "$W/erases" "$W/erases.log"; CUT_AT=$EE nk install "$KNEW" >/dev/null 2>&1
power_on >/dev/null; check "environment blank after a cut: U-Boot's defaults boot $KOLD" sh -c "grep -q 'bad CRC' '$W/boot.log' && [ '$RUNNING' = '$KOLD' ]"
rm -f "$W/erases"; nk install "$KNEW" >/dev/null 2>&1; power_on >/dev/null; check "  a new install then works (trial boots $KNEW)" sh -c "[ '$RUNNING' = '$KNEW' ]"

# 12. the environment the tool writes is exactly what U-Boot reads back (CRC, layout) and keeps GL's own commands
newunit; power_on >/dev/null; nk install "$KNEW" >/dev/null 2>&1
cat "$W/u/dev/mtd0" "$W/u/dev/mtd1" "$W/u/dev/mtd2" "$W/u/dev/mtd3" "$W/u/dev/mtd4" > "$W/n2"; "$UBSIM" "$W/n2" "$DEFENV" > "$W/b2" 2>&1
check "written environment: U-Boot accepts its CRC (no default-env warning)" sh -c "! grep -q 'bad CRC' '$W/b2' && grep -q 'patronus: trial kernel' '$W/b2'"
for v in lu rlf lc firmware_addr; do
  nk env-get $v > "$W/ev.got"; grep "^$v=" "$DEFENV" | cut -d= -f2- > "$W/ev.want"
  check "  GL's own $v kept verbatim in the saved environment" cmp "$W/ev.got" "$W/ev.want"
done

# 13. the boot guard decides a trial: confirmed -> patronus-flash kernel-commit, unconfirmed -> kernel-abort + restart, root kept
G=$D/overlay/usr/sbin/patronus-guard
mkdir -p "$W/gbin"; printf '#!/bin/sh\necho "flash $*" >> "%s/gcalls"\n' "$W" > "$W/gbin/rec-flash"; printf '#!/bin/sh\necho reboot >> "%s/gcalls"\n' "$W" > "$W/gbin/rec-reboot"
chmod 755 "$W/gbin/rec-flash" "$W/gbin/rec-reboot"
gd() { rm -rf "$W/grun" "$W/gdata" "$W/gcalls"; mkdir -p "$W/grun" "$W/gdata"; }
g() { PATRONUS_GUARD_GRACE=0 PATRONUS_GUARD_RUN="$W/grun" PATRONUS_GUARD_DATA="$W/gdata" PATRONUS_FLASH="$W/gbin/rec-flash" PATRONUS_REBOOT="$W/gbin/rec-reboot" PATRONUS_GUARD_GW= sh "$G" "$@"; }
gd; echo ox > "$W/grun/kernel-trial"; g arm >/dev/null 2>&1
check "guard: unconfirmed trial-kernel boot -> kernel-abort + restart, the root is NOT reverted" sh -c "grep -q 'flash kernel-abort' '$W/gcalls' && grep -q reboot '$W/gcalls' && ! grep -q 'flash openwrt' '$W/gcalls'"
gd; echo ox > "$W/grun/kernel-trial"; g ok >/dev/null 2>&1
check "guard: operator-confirmed trial-kernel boot -> kernel-commit" sh -c "grep -q 'flash kernel-commit' '$W/gcalls' && ! grep -q reboot '$W/gcalls'"
gd; g arm >/dev/null 2>&1
check "guard: no trial -> the usual root revert (unchanged behaviour)" grep -q 'flash openwrt' "$W/gcalls"

echo "nor-kernel: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
