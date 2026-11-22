#!/bin/sh
# Host tests of kernel-track.sh with local release data (no network).
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
today=$(date +%F); old=$(date -d '10 days ago' +%F 2>/dev/null || date -v-10d +%F)
cat > "$T/rel.json" <<EOF
{"releases":[{"moniker":"stable","version":"7.3.5","released":{"isodate":"$today"}},
 {"moniker":"longterm","version":"6.12.120","released":{"isodate":"$old"}},
 {"moniker":"longterm","version":"6.6.162","released":{"isodate":"$old"}}]}
EOF
printf '%s  linux-6.12.120.tar.xz\n%s  linux-6.12.119.tar.xz\n' "$(printf a%.0s $(seq 64))" "$(printf b%.0s $(seq 64))" > "$T/sums"
pin() { printf 'OWRT_TAG=v1\nKERNEL_LINE=%s\nKERNEL_PATCH=%s\nKERNEL_SHA256=x\nOWRT_STOCK_PATCH=1\n' "$1" "$2" > "$T/pin"; }
run() { KERNEL_PIN=$T/pin KERNEL_RELEASES_URL=$T/rel.json KERNEL_SUMS_URL=$T/sums sh "$HERE/kernel-track.sh" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pin 6.12 118
out=$(run --print); case $out in "pinned 6.12.118 newest 6.12.120"*) ;; *) fail "print: $out";; esac
if run --check >/dev/null 2>&1; then fail "old lag must be red"; fi
MAX_LAG_DAYS=30 run --check >/dev/null || fail "within allowed lag must pass"
out=$(run --bump); [ "$out" = "bump 6.12.118 6.12.120" ] || fail "bump: $out"
grep -q '^KERNEL_PATCH=120$' "$T/pin" || fail "patch not rewritten"
grep -q "^KERNEL_SHA256=$(printf a%.0s $(seq 64))\$" "$T/pin" || fail "hash not rewritten"
grep -q '^KERNEL_LINE=6.12$' "$T/pin" || fail "line must stay as configured"
[ -z "$(run --bump)" ] || fail "second bump must be a no-op"
run --check >/dev/null || fail "current pin must pass"
pin 6.6 162; out=$(run --print); case $out in "pinned 6.6.162 newest 6.6.162"*) ;; *) fail "other line: $out";; esac
pin 5.99 1; if run --print >/dev/null 2>&1; then fail "EOL line must error"; fi
pin 6.12 118; printf '%s  linux-6.12.118.tar.xz\n' "$(printf c%.0s $(seq 64))" > "$T/sums"
if run --bump >/dev/null 2>&1; then fail "missing hash must error"; fi
grep -q '^KERNEL_PATCH=118$' "$T/pin" || fail "pin touched despite missing hash"
echo "kernel-track tests: ok"
