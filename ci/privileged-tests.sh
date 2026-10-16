#!/usr/bin/env bash
# Run the #[ignore]d tests that need real kernel netfilter / raw sockets:
#   * patronus-web rule apply/delete against real nftables
#   * patronus-sdwan ICMP/UDP health probes (raw sockets)
#   * the nft "source=any" validation harness (real RuleManager -> real nft)
#
# The forgejo runner does not pass `--cap-add` from a job's
# `container.options` through to the job container (CapEff there lacks
# CAP_NET_ADMIN, run 388), so the test binaries are compiled here (with the
# job's cargo cache) and executed in a capped sibling container that really
# has CAP_NET_ADMIN + CAP_NET_RAW. The sibling proves its capabilities
# before running anything, so this fails loudly instead of skipping.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${PRIV_TEST_IMAGE:-catthehacker/ubuntu:act-latest}
C=ppriv-${GITHUB_RUN_ID:-local}-$$
OUT=$(mktemp -d)
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$OUT"; }
trap cleanup EXIT

test_bins() {
  cargo test "$@" --no-run --message-format=json | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(m["executable"])'
}

WEB=$(test_bins -p patronus-web --lib)
SDWAN=$(test_bins -p patronus-sdwan --lib)
[ -x "$WEB" ] && [ -x "$SDWAN" ] || { echo "could not locate test binaries (web=$WEB sdwan=$SDWAN)"; exit 1; }
cargo build -p patronus-firewall --example nft_any_source_validation
cp "$WEB" "$OUT/web-tests"
cp "$SDWAN" "$OUT/sdwan-tests"
cp target/debug/examples/nft_any_source_validation "$OUT/nft-any"

cat > "$OUT/run.sh" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list.d/*ppa*.list /etc/apt/sources.list.d/*ppa*.sources
for i in 1 2 3; do apt-get update -qq && break; [ "$i" = 3 ] && exit 1; sleep 15; done
apt-get install -y -qq nftables iproute2 >/dev/null
echo "--- capabilities of the test container"
grep Cap /proc/self/status
nft add table inet patronus_ci_probe
nft delete table inet patronus_ci_probe
echo "nftables is writable here"
cd /t
echo "=== patronus-web real nftables tests"
./web-tests --ignored --test-threads=1
echo "=== patronus-sdwan ICMP/UDP probe tests"
./sdwan-tests health:: --ignored --test-threads=1
echo "=== nft source=any validation harness"
./nft-any
EOF

docker create --name "$C" --cap-add NET_ADMIN --cap-add NET_RAW \
  --memory 2g --memory-swap 2g --cpus 2 -w /t "$IMAGE" bash /t/run.sh >/dev/null
docker cp "$OUT/." "$C:/t/"
docker start -a "$C"
rc=$(docker inspect -f '{{.State.ExitCode}}' "$C")
exit "$rc"
