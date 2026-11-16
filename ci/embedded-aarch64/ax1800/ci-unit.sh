#!/bin/sh
# ci-unit.sh <dir>: a throwaway per-unit directory for CI/QEMU builds (assemble.sh UNIT_DIR): root password locked, a
# fresh CI ssh key (<dir>/ci_ed25519, its .pub as authorized_keys), fresh dropbear host keys, no ap.env (Wi-Fi off).
# Real units take these files from their private directory, never from the repository or CI.
set -eu
D=${1:?usage: ci-unit.sh <dir>}
mkdir -p "$D"; chmod 700 "$D"
echo 'root:!:20000:0:99999:7:::' > "$D/shadow-root"
rm -f "$D/ci_ed25519" "$D/ci_ed25519.pub"
ssh-keygen -q -t ed25519 -N '' -C patronus-ci -f "$D/ci_ed25519"
cp "$D/ci_ed25519.pub" "$D/authorized_keys"
for t in ed25519 ecdsa rsa; do rm -f "$D/dropbear_${t}_host_key"; dropbearkey -t $t -f "$D/dropbear_${t}_host_key" >/dev/null 2>&1; done
ls "$D"
