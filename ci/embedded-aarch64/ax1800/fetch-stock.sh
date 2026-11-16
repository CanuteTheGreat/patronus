#!/bin/sh
# fetch-stock.sh [dir]: download + sha256-verify the OpenWrt artefacts in stock.pin; unpack the stock root.
# Prints (KEY=value lines): STOCK_SYSUPGRADE, STOCK_ROOT (unsquashed rootfs), VIRT_KERNEL, FACTORY_UBI (layout reference). Idempotent; cache = <dir> (default ./stock-cache).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); . "$HERE/stock.pin"
D=$(readlink -f "${1:-${STOCK_CACHE:-./stock-cache}}"); mkdir -p "$D"
get() { f=$D/$1; if ! { [ -f "$f" ] && echo "$3  $f" | sha256sum -c - >/dev/null 2>&1; }; then
  curl -fsSL -o "$f.part" "$2"; mv "$f.part" "$f"
  echo "$3  $f" | sha256sum -c - >&2 || { rm -f "$f"; echo "fetch-stock: sha256 mismatch for $1" >&2; exit 1; }; fi; }
get "$OWRT_SYSUPGRADE" "$OWRT_SYSUPGRADE_URL" "$OWRT_SYSUPGRADE_SHA256"
get "$OWRT_VIRT_KERNEL" "$OWRT_VIRT_KERNEL_URL" "$OWRT_VIRT_KERNEL_SHA256"
get "$OWRT_FACTORY_UBI" "$OWRT_FACTORY_UBI_URL" "$OWRT_FACTORY_UBI_SHA256"
if [ ! -f "$D/root/.done" ]; then
  rm -rf "$D/root" "$D/su"; mkdir -p "$D/su"; tar xf "$D/$OWRT_SYSUPGRADE" -C "$D/su" --wildcards '*/root' '*/kernel' '*/CONTROL'
  unsquashfs -q -no-xattrs -d "$D/root" "$D"/su/*/root >/dev/null 2>&1 || true   # device nodes need root: ignored
  [ -d "$D/root/lib/modules" ] || { echo "fetch-stock: unsquashfs failed" >&2; exit 1; }
  touch "$D/root/.done"
fi
echo "STOCK_SYSUPGRADE=$D/$OWRT_SYSUPGRADE"; echo "STOCK_ROOT=$D/root"; echo "VIRT_KERNEL=$D/$OWRT_VIRT_KERNEL"; echo "FACTORY_UBI=$D/$OWRT_FACTORY_UBI"
