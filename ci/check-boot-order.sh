#!/usr/bin/env bash
# Regression test: the second boot pass (patronus-services) must never delay patronus-web or any other unrelated service.
# Found 2026-11-27 (twin rehearsal): with a WAN lease but no uplink the pass retried for ~6 minutes and, because OpenRC starts the
# default runlevel serially and patronus-services sorted before patronus-web, the web UI refused connections the whole time.
#   OpenRC : patronus-services must start after every other service (`after *`) and patronus-web must not depend on it.
#   systemd: patronus-web must not be ordered after / require / want patronus-services.
set -eu
cd "$(dirname "$0")/.."
F=gentoo/net-firewall/patronus/files
fail() { echo "FAIL: $*" >&2; exit 1; }

deps=$(sed -n '/^depend()/,/^}/p' "$F/patronus-services.initd")
grep -Eq '^[[:space:]]*after .*(^|[[:space:]])\*([[:space:]]|$)' <<<"$deps" || fail "patronus-services.initd: depend() lacks 'after *'"
web=$(sed -n '/^depend()/,/^}/p' "$F/patronus-web.initd")
grep -q 'patronus-services' <<<"$web" && fail "patronus-web.initd depends on patronus-services"
echo "ok openrc ordering"

for u in patronus-web.service patronus-applyd.service; do
  grep -Eq '^(After|Requires|Wants|BindsTo|PartOf)=.*patronus-services' "$F/$u" && fail "$u is tied to patronus-services"
done
grep -Eq '^Before=.*patronus-web' "$F/patronus-services.service" && fail "patronus-services.service is ordered before patronus-web"
echo "ok systemd ordering"
echo "boot order: pass"
