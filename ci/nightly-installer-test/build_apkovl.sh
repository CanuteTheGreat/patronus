#!/usr/bin/env bash
# Builds the Alpine apkovl overlay that drives the nightly realistic
# installer test. Run inside the Linux CI container (has the freshly
# built patronus-install binary next to it). Produces
# patronus.apkovl.tar.gz containing:
#   - /usr/local/bin/patronus-install   (the real installer binary)
#   - /etc/patronus/answer.toml         (unattended install config)
#   - /etc/local.d/patronus-ci.start    (autorun harness script)
#   - /etc/runlevels/default/local      (enables the "local" service)
#   - /etc/network/interfaces           (dhcp on eth0)
#   - /etc/runlevels/boot/networking    (bring eth0 up: the report channel)
#   - /etc/.default_boot_services       (Alpine init otherwise skips its default
#                                        sysinit/boot services when an apkovl exists)
#   - /etc/apk/repositories             (boot media first, then the 3.20 mirror)
# iso_remaster.sh puts the overlay on the ISO itself, where Alpine's init finds
# it without needing network in the initramfs.
set -euo pipefail

BIN="${1:?usage: build_apkovl.sh <patronus-install-binary> <answer.toml> <start-script> <outfile>}"
ANSWER="${2:?missing answer.toml}"
STARTSCRIPT="${3:?missing start script}"
OUT="${4:?missing output path}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/usr/local/bin" \
         "$WORK/etc/patronus" \
         "$WORK/etc/local.d" \
         "$WORK/etc/runlevels/default" \
         "$WORK/etc/runlevels/boot" \
         "$WORK/etc/apk" \
         "$WORK/etc/network"

cp "$BIN" "$WORK/usr/local/bin/patronus-install"
chmod 755 "$WORK/usr/local/bin/patronus-install"

cp "$ANSWER" "$WORK/etc/patronus/answer.toml"

cp "$STARTSCRIPT" "$WORK/etc/local.d/patronus-ci.start"
chmod 755 "$WORK/etc/local.d/patronus-ci.start"

ln -sf /etc/init.d/local "$WORK/etc/runlevels/default/local"
ln -sf /etc/init.d/networking "$WORK/etc/runlevels/boot/networking"
touch "$WORK/etc/.default_boot_services"
cat > "$WORK/etc/apk/repositories" <<'EOF'
/media/cdrom/apks
http://dl-cdn.alpinelinux.org/alpine/v3.20/main
http://dl-cdn.alpinelinux.org/alpine/v3.20/community
EOF

cat > "$WORK/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

# apkovl must be a gzipped tar rooted at /, with real symlinks preserved.
tar -C "$WORK" -czf "$OUT" --owner=0 --group=0 .
echo "Built apkovl: $OUT ($(du -h "$OUT" | cut -f1))"
