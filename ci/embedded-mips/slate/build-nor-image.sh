#!/bin/bash
# Rebuilds the NOR-budget CI builder image (pembed-slate-img:ci) on the arm64 build host (the CI host), reproducibly from
# the scripts in this directory, and optionally pushes it to the Forgejo registry so a docker prune cannot lose it.
#   build-nor-image.sh [REGISTRY_REF]      e.g. git.canutethegreat.com/canutethegreat/pembed-slate-img:ci
# Takes 2-4 h (crossdev gcc, systemd, rust). Run it detached: `systemd-run --user ... build-nor-image.sh`. Log: $D/out/build.log
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REF=${1:-}
SRC=$(cd "$HERE/../../.." && pwd)
D=$(agent-workdir new pembed-nor --ttl 12); C=pembed-nor-build-$$
agent-workdir track "$D" container "$C"
mkdir -p "$D/w" "$D/out"; cp "$HERE"/*.sh "$HERE/busybox.portage-env" "$D/w/"
eval "$(python3 "$SRC/ci/hw-profile/hwprofile.py" env "$SRC/profiles/hw/ath79-gl-ar750s.toml")"
printf 'STOCK_NAME=%s\nSTOCK_SHA256=%s\nSTOCK_URL=https://downloads.openwrt.org/releases/25.12.6/targets/ath79/nand/%s\n' \
  "$HW_STOCK_SYSUPGRADE" "$HW_OPENWRT_STOCK_SHA256" "$HW_STOCK_SYSUPGRADE" > "$D/w/stock.env"
docker run -d --name "$C" -v "$D/w:/w" -v "$D/out:/out" --memory 14g gentoo/stage3:arm64-openrc sleep infinity >/dev/null
docker exec "$C" bash /w/nor-image-inner.sh > "$D/out/build.log" 2>&1 || { echo "BUILD FAILED, see $D/out/build.log"; exit 1; }
docker commit -c 'CMD ["/bin/bash"]' "$C" pembed-slate-img:ci >/dev/null
docker rm -f "$C" >/dev/null
echo "image pembed-slate-img:ci built"
if [ -n "$REF" ]; then docker tag pembed-slate-img:ci "$REF"; docker push "$REF"; fi
agent-workdir done "$D"
