#!/bin/bash
# qemu-bundle.sh <out-dir> [openrc|systemd]: INSIDE the embedded builder image (pembed-slate-img:ci, as nor-ci.sh): build the multi-call binary from
# this checkout, assemble the NOR-profile root of the GL-AR750S for each init variant with a THROWAWAY unit (a fresh ssh key pair, fresh dropbear host
# keys, no Wi-Fi uplink, never a real unit's private files), prepare the QEMU test root (the shipped root with OpenWrt's malta/be netfilter modules
# instead of the ath79 ones: the gate boots OpenWrt's malta kernel, kmods-malta.pin), and pack everything a small test host needs to run
# qemu-gate.py WITHOUT building anything: <out-dir>/patronus-embedded-qemu-<sha8>-<init>.tar + .sha256 (manifest.json lists every file's sha256 and
# the source commit). Env: SOURCE_REV (commit), QB_DIR (work dir, default /out/qemu-bundle), NOR_CI_* as nor-ci.sh.
# The malta kernel (vmlinux.elf) is downloaded from downloads.openwrt.org and verified against kmods-malta.pin here, so the test host needs no
# internet; the kmods tar comes from the Forgejo generic package patronus-owrt-kernel-malta (sha256 pinned).
set -euo pipefail
H=$(cd "$(dirname "$0")" && pwd); SRC=$(cd "$H/../../.." && pwd)
D=${1:?usage: qemu-bundle.sh <out-dir> [openrc|systemd]}; INITS=${2:-"openrc systemd"}; SUF=${2:+-$2}
SHA=$(echo "${SOURCE_REV:-local}" | cut -c1-8); mkdir -p "$D"; D=$(cd "$D" && pwd)
QB=${QB_DIR:-/out/qemu-bundle}; rm -rf "$QB"; mkdir -p "$QB/unit/hostapd" "$QB/cache"
# --- the pinned malta kernel + kmods
eval "$(grep -E '^(MALTA_KERNEL_[A-Z0-9_]+|MALTA_KMOD_TAR_[A-Z0-9_]+)=' "$H/kmods-malta.pin")"
fetch() { # url sha256 dest
  curl -fsSL --retry 3 -o "$3.part" "$1" && echo "$2  $3.part" | sha256sum -c - >/dev/null || { echo "qemu-bundle: download/sha256 failed for $1" >&2; exit 1; }; mv "$3.part" "$3"; }
fetch "$MALTA_KERNEL_URL" "$MALTA_KERNEL_SHA256" "$QB/cache/vmlinux.elf"
fetch "$MALTA_KMOD_TAR_URL" "$MALTA_KMOD_TAR_SHA256" "$QB/cache/kmods.tar"
# --- throwaway unit: a known ssh key pair (the gate's way in) and valid dropbear host keys (dropbear's own key blob: type, seed+public)
U=$QB/unit
ssh-keygen -q -t ed25519 -N '' -C slate-qemu-gate -f "$QB/ci_ed25519"; cp "$QB/ci_ed25519.pub" "$U/authorized_keys"; rm -f "$QB/ci_ed25519.pub"
echo 'root:*:1::::::' > "$U/shadow-root"
printf 'UNIT_HOSTNAME=slate-gate\n' > "$U/unit.conf"
{ echo 'network={'; echo ' ssid="qemu-gate-unused"'; echo ' key_mgmt=NONE'; echo ' disabled=1'; echo '}'; } > "$U/wpa_supplicant.conf"
python3 - "$U" <<'PY'
import struct, subprocess, sys, os
d = sys.argv[1]
def s(b): return struct.pack(">I", len(b)) + b
priv = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-outform", "DER"], capture_output=True, check=True).stdout
seed = priv[-32:]
pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=priv, capture_output=True, check=True).stdout[-32:]
blob = s(b"ssh-ed25519") + s(seed + pub)
# only the ed25519 key is generated here; dropbear (-R) creates the others if a client asks for them
open(os.path.join(d, "dropbear_ed25519_host_key"), "wb").write(blob)
PY
# --- build + assemble (nor-ci.sh with this unit), then the test roots
export NOR_CI_DIR=$QB/nor NOR_CI_UNIT=$U NOR_CI_VARIANTS="$INITS" SOURCE_REV="${SOURCE_REV:-local}"
bash "$H/nor-ci.sh" || echo "qemu-bundle: nor-ci.sh reported an overage (informational for systemd, see its output); the roots below were still assembled"
B=$QB/bundle; rm -rf "$B"; mkdir -p "$B/gate"
cp "$H/qemu-gate.py" "$B/gate/"; cp "$QB/ci_ed25519" "$B/ci_ed25519"; chmod 600 "$B/ci_ed25519"; cp "$QB/cache/vmlinux.elf" "$B/vmlinux.elf"
KV=$(tar -tf "$QB/cache/kmods.tar" | sed -n 's#^\./lib/modules/\([^/]*\)/$#\1#p' | head -1)
for init in $INITS; do
  SQ=$QB/nor/out/nor-$init/root.squashfs; [ -s "$SQ" ] || { echo "no $init root at $SQ" >&2; exit 1; }
  T=$QB/t-$init; rm -rf "$T"; mkdir -p "$T"; unsquashfs -q -d "$T/r" "$SQ" >/dev/null
  # the shipped modules are ath79's: swap in malta's netfilter set (same release, same version string), and say so for the early boot
  rm -rf "$T/r/lib/modules" "$T/r/etc/modules.d" "$T/r/etc/modules-boot.d"; mkdir -p "$T/r/lib/modules" "$T/r/etc/modules.d"
  tar -xf "$QB/cache/kmods.tar" -C "$T/r"; depmod -b "$T/r" "$KV"; : > "$T/r/etc/patronus/qemu-kmods"
  # the WAN of the test unit is the emulator's second NIC (the board's Wi-Fi uplinks do not exist there)
  sed -i 's/^wan_interfaces *=.*/wan_interfaces = ["eth1"]/' "$T/r/etc/patronus/patronus.toml"; grep -q '^wan_interfaces = \["eth1"\]' "$T/r/etc/patronus/patronus.toml"
  mkdir -p "$B/$init"; mksquashfs "$T/r" "$B/$init/root.img" -comp xz -b 256K -noappend -no-xattrs -all-root -quiet >/dev/null
  rm -rf "$T"
done
python3 - "$B" "${SOURCE_REV:-local}" "$KV" <<'PY'
import hashlib, json, os, sys, time
b, rev, kv = sys.argv[1:4]
files = {}
for r, _, fs in os.walk(b):
    for f in fs:
        p = os.path.join(r, f)
        if f == "manifest.json": continue
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for c in iter(lambda: fh.read(1 << 20), b""): h.update(c)
        files[os.path.relpath(p, b)] = {"sha256": h.hexdigest(), "size": os.path.getsize(p)}
json.dump({"source": rev, "built": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "board": "glinet,gl-ar750s", "kernel": kv,
           "qemu": "qemu-system-mips -M malta -m 128", "files": files}, open(os.path.join(b, "manifest.json"), "w"), indent=1, sort_keys=True)
PY
tar -C "$B" -cf "$D/patronus-embedded-qemu-$SHA$SUF.tar" --sort=name --owner=0 --group=0 .
( cd "$D" && sha256sum "patronus-embedded-qemu-$SHA$SUF.tar" > "patronus-embedded-qemu-$SHA$SUF.tar.sha256" )
ls -la "$D"/patronus-embedded-qemu-$SHA$SUF.tar*
