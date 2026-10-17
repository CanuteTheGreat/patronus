#!/usr/bin/env bash
# Netlab: prove kernel state, not just API answers. Builds the SHIPPED
# binaries (patronus-cli as `patronus`, patronus-web), then runs every
# ci/netlab/lane-*.sh inside ONE capped sibling container that builds its own
# network namespaces + veth pairs (`ip netns` needs CAP_SYS_ADMIN; writable
# /proc/sys needs systempaths=unconfined; the container is still capped and
# not --privileged).
#
# Usage: ci/netlab/run.sh [lane-script ...]   (default: all lane-*.sh)
#
# Same sibling-container pattern as ci/privileged-tests.sh: the Forgejo
# runner drops --cap-add from the job container, so the job builds and a
# docker sibling with real capabilities runs the tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${NETLAB_IMAGE:-catthehacker/ubuntu:act-latest}
C=netlab-${GITHUB_RUN_ID:-local}-$$
OUT=$(mktemp -d)
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$OUT"; }
trap cleanup EXIT

if [ $# -eq 0 ]; then set -- ci/netlab/lane-*.sh; fi

cargo build -p patronus-cli -p patronus-web --bins
cp target/debug/patronus-cli "$OUT/patronus"
cp target/debug/patronus-web "$OUT/patronus-web"
for s in "$@"; do cp "$s" "$OUT/"; done
names=$(for s in "$@"; do basename "$s"; done | tr '\n' ' ')

cat > "$OUT/inner.sh" <<INNER
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list.d/*ppa*.list /etc/apt/sources.list.d/*ppa*.sources
for i in 1 2 3; do apt-get update -qq && break; [ "\$i" = 3 ] && exit 1; sleep 15; done
apt-get install -y -qq nftables iproute2 curl python3 >/dev/null
echo "--- netlab container: \$(uname -m), kernel \$(uname -r)"
grep Cap /proc/self/status
ip netns add probe && ip netns del probe && echo "network namespaces: ok"
cd /t
for s in $names; do echo "##### \$s"; bash "/t/\$s"; done
INNER

case "$(uname -m)" in
  x86_64) PLATFORM=linux/amd64 ;;
  aarch64|arm64) PLATFORM=linux/arm64 ;;
  *) echo "unsupported build arch $(uname -m)"; exit 1 ;;
esac
docker create --name "$C" --platform "$PLATFORM" \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
  --memory 2g --memory-swap 2g --cpus 2 -w /t "$IMAGE" bash /t/inner.sh >/dev/null
docker cp "$OUT/." "$C:/t/"
docker start -a "$C"
rc=$(docker inspect -f '{{.State.ExitCode}}' "$C")
exit "$rc"
