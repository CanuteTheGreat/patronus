#!/bin/sh
# Host tests for the device-profile tooling (ci/hw-profile/hwprofile.py) and for the Slate scripts that consume it.
# No router, no root: `sh ci/hw-profile/tests/run.sh`. Needs python3 only (the stdlib TOML fallback is exercised too).
set -u
D=$(cd "$(dirname "$0")/.." && pwd); ROOT=$(cd "$D/../.." && pwd); H="python3 $D/hwprofile.py"
SLATE=$ROOT/profiles/hw/ath79-gl-ar750s.toml; S=$ROOT/ci/embedded-mips/slate
W=$(mktemp -d "${TMPDIR:-/tmp}/hwp-tests.XXXX"); trap 'rm -rf "$W"' EXIT
pass=0; failn=0
ok() { echo "PASS: $*"; pass=$((pass+1)); }
no() { echo "FAIL: $*"; failn=$((failn+1)); }
t() { name=$1; shift; if "$@" >"$W/out" 2>&1; then ok "$name"; else no "$name"; sed 's/^/    /' "$W/out"; fi; }
tn() { name=$1; shift; if "$@" >"$W/out" 2>&1; then no "$name (expected failure)"; sed 's/^/    /' "$W/out"; else ok "$name"; fi; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1: got '$2' want '$3'"; fi; }

t "validate: every profiles/hw/*.toml" $H validate
t "py_compile hwprofile.py" python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$D/hwprofile.py"

# Golden values: what assemble.sh/nor-budget.sh/nor-ci.sh hard-coded for the Slate before they read the profile.
# If any differs, the Slate images change: that is a deliberate act (update both), never a side effect.
eval "$($H env "$SLATE")"
eq "slate board id"          "$HW_DEVICE_OPENWRT_BOARD" "glinet,gl-ar750s-nor-nand"
eq "slate sysupgrade dir"    "$HW_SYSUPGRADE_DIR" "sysupgrade-glinet_gl-ar750s-nor-nand"
eq "slate board file id"     "$HW_BOARD_ID" "glinet_gl-ar750s-nor-nand"
eq "slate stock image name"  "$HW_STOCK_SYSUPGRADE" "openwrt-25.12.6-ath79-nand-glinet_gl-ar750s-nor-nand-squashfs-sysupgrade.bin"
eq "slate stock sha256"      "$HW_OPENWRT_STOCK_SHA256" "3d58b599daca2a239f745cf5d739d624d6262302000df1615295ca03c594ed03"
eq "slate musl loader"       "$HW_ARCH_MUSL_LDSO" "ld-musl-mips-sf.so.1"
eq "slate hostname"          "$HW_DEVICE_HOSTNAME" "slate"
eq "slate kernel label"      "$HW_KERNEL_LABEL" "OpenWrt 25.12.6 ath79/nand"
eq "slate NOR layout"        "$HW_NOR_FIRMWARE_KIB/$HW_NOR_DATA_MIN_KIB/$HW_NOR_MARGIN_KIB/$HW_NOR_SYSTEMD_KNOWN_FREE_KIB" "16000/1024/256/-832"
eq "slate init variants"     "$HW_INIT" "openrc systemd"

# the stdlib fallback parser (used on interpreters without tomllib) must agree with tomllib
a=$($H env "$SLATE" | md5sum); b=$(HWPROFILE_NO_TOMLLIB=1 $H env "$SLATE" | md5sum)
eq "fallback TOML parser == tomllib" "$a" "$b"

# negative cases: each mistake is rejected
mk() { n=$1; shift; python3 "$D/tests/mutate.py" "$SLATE" "$W/ath79-$n.toml" "$@" && echo "$W/ath79-$n.toml"; }
tn "rejects RAM below the tier minimum"   $H validate "$(mk ram 'ram_mb      = 128=>ram_mb      = 64')"
tn "rejects an unknown status level"      $H validate "$(mk lvl 'level          = "tested"=>level          = "works"')"
tn "rejects tested without evidence"      $H validate "$(mk ev 'evidence       = "Real board=>evidence_x     = "Real board')"
tn "rejects an arch missing from arch.toml" $H validate "$(mk arch 'arch_packages  = "mips_24kc"=>arch_packages  = "mips_9999"')"
tn "rejects a wrong tier name"            $H validate "$(mk tier 'tier        = "embedded"=>tier        = "tiny"')"
cp "$SLATE" "$W/ath79-copy.toml"; tn "rejects a duplicate device id (two files)" $H validate "$SLATE" "$W/ath79-copy.toml"
cp "$SLATE" "$W/ramips-bad-name.toml"; tn "rejects a file name that does not start with the target" $H validate "$W/ramips-bad-name.toml"

# gen: skeleton from OpenWrt's profiles.json: validates, is untested, refuses to overwrite
FX=$D/tests/fixtures/ath79-nand-profiles.json
other=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print([k for k in d['profiles'] if k!='glinet_gl-ar750s-nor-nand'][0])" "$FX")
mkdir -p "$W/gen"
t "gen: skeleton from profiles.json" $H gen "$FX" "$other" --out "$W/gen"
g=$(ls "$W/gen"/*.toml | head -1)
t "gen: output validates" $H validate "$g"
eq "gen: status is untested" "$($H get "$g" status.level)" "untested"
tn "gen: refuses to overwrite" $H gen "$FX" "$other" --out "$W/gen"

# list / matrix
t "list --json parses" sh -c "$H list --json | python3 -c 'import json,sys; json.load(sys.stdin)'"
eq "matrix: slate x (openrc, systemd)" "$($H matrix | python3 -c 'import json,sys; print(",".join(sorted(e["init"] for e in json.load(sys.stdin)["include"] if e["device"] == "glinet-gl-ar750s-nor-nand")))')" "openrc,systemd"
eq "matrix: gl-ax1800 x (openrc, systemd), aarch64 musl" "$($H matrix | python3 -c 'import json,sys; print(",".join(sorted(e["init"] + ":" + e["rust_target"] for e in json.load(sys.stdin)["include"] if e["device"] == "glinet-gl-ax1800")))')" "openrc:aarch64-unknown-linux-musl,systemd:aarch64-unknown-linux-musl"

# GL-AX1800 profile: the values its image scripts read (ci/embedded-aarch64/ax1800)
AX=$ROOT/profiles/hw/qualcommax-gl-ax1800.toml
eval "$($H env "$AX")"
eq "ax1800 board id"         "$HW_DEVICE_OPENWRT_BOARD" "glinet,gl-ax1800"
eq "ax1800 sysupgrade dir"   "$HW_SYSUPGRADE_DIR" "sysupgrade-glinet_gl-ax1800"
eq "ax1800 musl loader"      "$HW_ARCH_MUSL_LDSO" "ld-musl-aarch64.so.1"
eq "ax1800 NAND geometry"    "$HW_NAND_UBI_MTD_BYTES/$HW_NAND_PEB_BYTES/$HW_NAND_LEB_BYTES/$HW_NAND_RESERVED_PEBS" "120586240/131072/126976/24"
eq "ax1800 init variants"    "$HW_INIT" "openrc systemd"

# the consumers hold no device constants any more
for f in assemble.sh nor-budget.sh nor-ci.sh; do
  if grep -E 'ar750s-nor-nand|ld-musl-mips|echo "slate"|sysupgrade-glinet|FIRMWARE_KIB:-16000' "$S/$f" >/dev/null; then no "$f still hard-codes a Slate constant"; else ok "$f has no hard-coded Slate constant"; fi
done

# nor-budget.sh reads the layout from the profile: same numbers as the old 16000/1024/256 defaults
: > "$W/k"; : > "$W/r"; truncate -s 3000000 "$W/k"; truncate -s 9000000 "$W/r"
out=$(sh "$S/nor-budget.sh" "$W/r" "$W/k"); rc=$?
eq "nor-budget exit (fits)" "$rc" "0"
case "$out" in *"= 12"*" of 16000 KiB"*"margin wanted 256 KiB"*) ok "nor-budget uses the profile layout";; *) no "nor-budget output: $out";; esac
truncate -s 15500000 "$W/r"; sh "$S/nor-budget.sh" "$W/r" "$W/k" >/dev/null 2>&1; eq "nor-budget exit (over budget)" "$?" "1"

echo "hw-profile tests: $pass passed, $failn failed"
[ "$failn" = 0 ]
