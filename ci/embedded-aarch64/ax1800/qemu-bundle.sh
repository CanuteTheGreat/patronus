#!/bin/bash
# qemu-bundle.sh <out-dir> [openrc|systemd]: INSIDE the builder container after ci-build.sh, pack everything a small test host needs to run the
# GL-AX1800 QEMU gate WITHOUT building anything: for each init variant the test root (GATE_PREP_ONLY of qemu-gate.sh: the shipped
# root with the virt kernel's netfilter kmods) and the sysupgrade tar, plus the pinned virt kernel, the throwaway CI ssh key,
# qemu-gate.sh and fwmeta.py. Output: <out-dir>/patronus-embedded-qemu-<sha8>[-<init>].tar + .sha256 (manifest.json inside lists every file's
# sha256 and the source commit). Env: SOURCE_REV (commit), OUT (default /out), HERE-relative scripts.
set -euo pipefail
H=$(cd "$(dirname "$0")" && pwd); OUT=${OUT:-/out}; D=${1:?usage: qemu-bundle.sh <out-dir> [openrc|systemd]}; INITS=${2:-"openrc systemd"}; SUF=${2:+-$2}
SHA=$(echo "${SOURCE_REV:-local}" | cut -c1-8)
B=$D/bundle; rm -rf "$B"; mkdir -p "$B/gate"
cp "$H/qemu-gate.sh" "$H/fwmeta.py" "$B/gate/"
cp "$OUT/stock/virt-kernel.bin" "$B/virt-kernel.bin"
cp "$OUT/unit/ci_ed25519" "$B/ci_ed25519"; chmod 600 "$B/ci_ed25519"
for init in $INITS; do
  i=$(ls -d "$OUT"/images/$init/*/ 2>/dev/null | head -1) || true
  [ -n "$i" ] || { echo "no $init image in $OUT/images (bundle holds the variants that were built)"; continue; }
  mkdir -p "$B/$init"
  VIRT_KERNEL=$OUT/stock/virt-kernel.bin UNIT_DIR=$OUT/unit RESULTS=$D/prep-$init GATE_PREP_ONLY="$B/$init/root.img" bash "$H/qemu-gate.sh" $init "$i"
  cp "$i"/patronus-*-sysupgrade.tar "$B/$init/"
done
python3 - "$B" "${SOURCE_REV:-local}" <<'PY'
import hashlib, json, os, sys, time
b, rev = sys.argv[1], sys.argv[2]
files = {}
for r, _, fs in os.walk(b):
    for f in fs:
        p = os.path.join(r, f)
        if f == "manifest.json": continue
        files[os.path.relpath(p, b)] = {"sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(), "size": os.path.getsize(p)}
json.dump({"source": rev, "built": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "board": "glinet,gl-ax1800", "qemu": "qemu-system-aarch64 -M virt -m 512",
           "files": files}, open(os.path.join(b, "manifest.json"), "w"), indent=1, sort_keys=True)
PY
tar -C "$B" -cf "$D/patronus-embedded-qemu-$SHA$SUF.tar" --sort=name --owner=0 --group=0 .
( cd "$D" && sha256sum "patronus-embedded-qemu-$SHA$SUF.tar" > "patronus-embedded-qemu-$SHA$SUF.tar.sha256" )
ls -la "$D"/patronus-embedded-qemu-$SHA$SUF.tar*
