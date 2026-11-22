#!/bin/sh
# patch-survey.sh <openwrt-src> <kernel-tarball> <target-patch-dir>...: apply OpenWrt's kernel patch series (generic backport/pending/hack,
# then each target dir given) to a fresh kernel tree in order and report every patch that does not apply, telling "already in
# the kernel" (reverse applies) from "context moved" (needs a refresh). Read-only on the OpenWrt tree; used when a kernel bump breaks
# the patch step, to see ALL conflicts at once instead of one per build.
set -u
S=$1; T=$2; shift 2
K=${KEEP:-$(mktemp -d)}; mkdir -p "$K"; tar -xf "$T" -C "$K" --strip-components=1
cd "$K"
line=$(sed -n 's/^PATCHVER:=//p;s/^KERNEL_PATCHVER:=//p' "$S"/target/linux/qualcommax/Makefile 2>/dev/null | head -1); line=${line:-6.12}
# OpenWrt copies the generic and target `files` overlays into the tree before it patches (some patches modify files they add)
for f in "$S/target/linux/generic/files" "$S/target/linux/generic/files-$line" $(for t in "$@"; do echo "$(dirname "$t")/files" "$(dirname "$t")/files-$line"; done); do
  [ -d "$f" ] && cp -a "$f"/. "$K"/
done
n=0; bad=0
for d in "$S/target/linux/generic/backport-$line" "$S/target/linux/generic/pending-$line" "$S/target/linux/generic/hack-$line" "$@"; do
  [ -d "$d" ] || continue
  for p in $(ls "$d"/*.patch | sort); do
    n=$((n+1))
    # dry run first: a patch that does not apply leaves the tree untouched (later patches that depend on it may then be reported too)
    if patch -p1 -s -N --dry-run < "$p" >/dev/null 2>&1; then patch -p1 -s -N --no-backup-if-mismatch < "$p" >/dev/null 2>&1; continue; fi
    if patch -p1 -R -s --dry-run < "$p" >/dev/null 2>&1; then echo "ALREADY-IN-KERNEL ${d#$S/target/linux/}/$(basename "$p")"; else echo "CONTEXT-MOVED     ${d#$S/target/linux/}/$(basename "$p")"; fi
    bad=$((bad+1))
  done
done
echo "surveyed $n patches, $bad not applying"
[ -n "${KEEP:-}" ] || rm -rf "$K"
