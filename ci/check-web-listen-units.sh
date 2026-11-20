#!/usr/bin/env bash
# The web UI listens on 443 + 80 by default and runs as the unprivileged patronus user, so BOTH init systems must grant it
# CAP_NET_BIND_SERVICE (OpenRC `capabilities=` with ^ = ambient, systemd AmbientCapabilities + the bounding set), and nothing
# may fall back to the old single hard-coded port. Static gate, run by rust-ci on every push:
#   1. the OpenRC script and the systemd unit both grant net_bind_service (and still net_admin + net_raw for nft)
#   2. neither pins a port or an address of its own (ports are settings: store, patronus.toml [web], PATRONUS_* environment)
#   3. the shipped patronus.toml has no listen_port / use_tls key (they were never honoured)
#   4. no shipped file brings back an 8443 listener (the default is the standard ports 443 + 80; 8443 is an explicit opt-in)
#   5. the web binary documents its settings (`--help` text names every layer)
# Usage: ci/check-web-listen-units.sh [repo-root]
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
F=gentoo/net-firewall/patronus/files
rc=0
bad() { echo "::error::[web-listen] $*"; rc=1; }

rcs=$(grep -E '^capabilities=' "$F/patronus-web.initd" || true)
for c in cap_net_admin cap_net_raw cap_net_bind_service; do
  grep -qE "\^$c" <<<"$rcs" || bad "$F/patronus-web.initd: capabilities= lacks ^$c ($rcs)"
done
for key in AmbientCapabilities CapabilityBoundingSet; do
  line=$(grep -E "^$key=" "$F/patronus-web.service" || true)
  for c in CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE; do
    grep -q "$c" <<<"$line" || bad "$F/patronus-web.service: $key= lacks $c ($line)"
  done
done
grep -qE '^(User|Group)=patronus' "$F/patronus-web.service" || bad "the unit must run as the unprivileged patronus user"
grep -qE '^command_user=' "$F/patronus-web.initd" || bad "the OpenRC script must run as the unprivileged patronus user"

code=$(grep -vE '^[[:space:]]*(#|Description=|description=)' "$F/patronus-web.initd" "$F/patronus-web.service")
if grep -Eq '(--addr|--port|:8443|:443|:8080|PATRONUS_HTTPS_PORT=|PATRONUS_HTTP_REDIRECT_PORT=)' <<<"$code"; then
  bad "an init file pins a web port itself: $(grep -En '(--addr|--port|:8443|:443|:8080|PATRONUS_HTTPS_PORT=|PATRONUS_HTTP_REDIRECT_PORT=)' <<<"$code" | head -3)"
fi

toml=$(grep -vE '^[[:space:]]*#' "$F/patronus.toml")
grep -Eq '^(listen_port|use_tls)' <<<"$toml" && bad "$F/patronus.toml still has a listen_port/use_tls key (ignored by the server)"

for e in ci/embedded-aarch64/ax1800/overlay/etc/patronus/embedded.env ci/embedded-mips/slate/overlay/etc/patronus/embedded.env \
         ci/embedded-mips/overlay/etc/init.d/patronus ci/embedded-mips/10-assemble-web.sh "$F/patronus-web.initd" "$F/patronus-web.service"; do
  [ -f "$e" ] || continue
  body=$(grep -vE '^[[:space:]]*(#|Description=|description=)' "$e" || true)
  if grep -q '8443' <<<"$body"; then bad "$e names port 8443 (the default listeners are 443 + 80; 8443 is an explicit opt-in setting)"; fi
done
if grep -Eq '^[[:space:]]*extra_https_ports' <<<"$toml"; then bad "$F/patronus.toml enables extra HTTPS ports by default"; fi

help=$(grep -c 'PATRONUS_HTTPS_PORT\|web.https_port\|patronus.toml' crates/patronus-web/src/server.rs || true)
[ "$help" -ge 3 ] || bad "crates/patronus-web/src/server.rs --help text does not document the settings"

[ "$rc" = 0 ] && echo "ok - web listen: both init systems grant net_bind_service, no pinned ports, the default listeners are the standard ports only"
exit "$rc"
