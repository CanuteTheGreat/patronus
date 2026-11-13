#!/usr/bin/env bash
# Init parity gate (owner rule: Patronus supports OpenRC AND systemd fully).
# Static, no container needed. Fails when a service is shipped for one init
# system but not the other:
#   1. every files/<name>.initd has a files/<name>.service (or <name>@.service)
#      and the reverse (timers/cron pair: ipdb is covered by its own rule);
#   2. every ebuild installs both halves under the matching USE flag, and the
#      same set of services under each;
#   3. no Rust source spawns rc-service / rc-update / systemctl outside the
#      init abstraction (crates/patronus-core/src/service.rs) -- new call sites
#      must go through ServiceManager, which picks the backend at run time.
# Usage: ci/check-init-parity.sh [repo-root]
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
F=gentoo/net-firewall/patronus/files
rc=0
bad() { echo "::error::[init-parity] $*"; rc=1; }

# 1. file pairs
for i in "$F"/*.initd; do
  n=$(basename "$i" .initd)
  [ -f "$F/$n.service" ] || [ -f "$F/$n@.service" ] || bad "$i has no systemd unit ($n.service or $n@.service)"
done
for u in "$F"/*.service; do
  n=$(basename "$u" .service); n=${n%@}
  [ "$n" = patronus-ipdb ] && continue   # timer + cron pair, checked below
  [ -f "$F/$n.initd" ] || bad "$u has no OpenRC script ($n.initd)"
done
[ -f "$F/patronus-ipdb.timer" ] && [ -f "$F/patronus-ipdb.cron" ] || bad "patronus-ipdb needs both .timer and .cron"

# 2. ebuilds install the same services under both flags
for e in gentoo/net-firewall/patronus/patronus-*.ebuild; do
  sd=$(sed -n 's/.*systemd_dounit "${FILESDIR}\/\(patronus-[a-z-]*\)@\?\.service".*/\1/p' "$e" | sort -u)
  oc=$(sed -n 's/.*newinitd "${FILESDIR}\/\(patronus-[a-z-]*\)\.initd".*/\1/p' "$e" | sort -u)
  # ipdb is timer vs cron, not a unit/initd pair
  sd=$(echo "$sd" | grep -v '^patronus-ipdb$' || true)
  if [ "$sd" != "$oc" ]; then
    bad "$e installs different services per init: systemd-only=[$(comm -23 <(echo "$sd") <(echo "$oc") | tr '\n' ' ')] openrc-only=[$(comm -13 <(echo "$sd") <(echo "$oc") | tr '\n' ' ')]"
  fi
  grep -q '|| ( systemd openrc )' "$e" || bad "$e: REQUIRED_USE must allow systemd or openrc"
done

# 3. nothing but the abstraction talks to the init system
hits=$(grep -rnE 'Command::new\("(rc-service|rc-update|systemctl)"\)|"(rc-service|rc-update|systemctl)",' \
        --include=*.rs crates | grep -v '^crates/patronus-core/src/service.rs' \
        | grep -vE 'power_argv|"systemctl", "(reboot|poweroff)"' || true)
if [ -n "$hits" ]; then
  echo "$hits"
  bad "direct rc-service/rc-update/systemctl use outside patronus_core::service (see docs/design/init-parity.md)"
fi
[ $rc -eq 0 ] && echo "[init-parity] ok"
exit $rc
