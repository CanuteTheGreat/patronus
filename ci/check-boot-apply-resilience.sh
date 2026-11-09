#!/usr/bin/env bash
# Regression test: the boot apply must survive a transient failure.
# Found 2026-11-09 (azkaban patronus-lab): after `qm stop`/`qm start` the VM came back with
# patronus-firewall Stopped while patronus-web was up, so nothing was forwarded (no retry,
# and the router's health check only proves ping + HTTPS).
#   systemd: unit must be Restart=on-failure with no start limit, ordered after local-fs/udev.
#   OpenRC : start() must retry; run against a fake `patronus` that fails N times.
set -eu
cd "$(dirname "$0")/.."
F=gentoo/net-firewall/patronus/files
fail() { echo "FAIL: $*" >&2; exit 1; }

U=$F/patronus-firewall.service
grep -Eq '^Restart=on-failure' "$U" || fail "$U: no Restart=on-failure"
grep -Eq '^StartLimitIntervalSec=0' "$U" || fail "$U: start limit not disabled"
grep -Eq '^After=.*local-fs.target' "$U" || fail "$U: not ordered after local-fs.target"
grep -Eq '^RequiresMountsFor=/var/lib/patronus' "$U" || fail "$U: store mount not required"
grep -Eq '^Before=network.target' "$U" || fail "$U: lost Before=network.target"
echo "ok systemd unit"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fake=$T/patronus
cat > "$fake" <<'EOS'
#!/bin/sh
n=$(cat "$COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$COUNT"
[ "$n" -gt "$FAILS" ]
EOS
chmod +x "$fake"
sed "s#/usr/bin/patronus#$fake#g" "$F/patronus-firewall.initd" | sed '1d' > "$T/initd.sh"
run() { # run <fails-before-success> -> prints "<rc> <calls>"
  COUNT=$T/count FAILS=$1 sh -c '
    rm -f "$COUNT"; export COUNT FAILS
    ebegin() { :; }; eend() { return "$1"; }; checkpath() { :; }; sleep() { :; }
    description=; extra_started_commands=
    . "$0"
    start; rc=$?
    echo "$rc $(cat "$COUNT")"' "$T/initd.sh"
}
[ "$(run 0)" = "0 1" ] || fail "openrc: clean apply should run once, got: $(run 0)"
[ "$(run 2)" = "0 3" ] || fail "openrc: 2 transient failures should succeed on try 3, got: $(run 2)"
[ "$(run 4)" = "0 5" ] || fail "openrc: 4 failures should succeed on try 5, got: $(run 4)"
r=$(run 99); [ "${r%% *}" != "0" ] && [ "${r##* }" = "5" ] || fail "openrc: permanent failure must report failure after 5 tries, got: $r"
echo "ok openrc retry"
if command -v systemd-analyze >/dev/null 2>&1; then
  bad=$(systemd-analyze verify "$U" 2>&1 | grep 'patronus-firewall' | grep -v 'not found\|/usr/bin/patronus' || true)
  [ -z "$bad" ] || fail "systemd-analyze: $bad"
fi
echo "boot-apply resilience: pass"
