#!/usr/bin/env bash
# Lane J (UI): the IP tunnels page driven in a real browser (ci/tunnels-page-e2e.py, Playwright + Firefox) against
# the shipped patronus-web in the netlab router: menu entry, every setting and form field, phone width in the
# light and dark scheme, refused entries explained on the page, then through the page only: add an IPIP tunnel,
# see it in the table and the live status, have the far end (plain iproute2 in the "internet" namespace) ping the
# router through it, edit its MTU, add a route, disable it (the link goes), delete everything. Needs Playwright +
# Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing). The data plane
# behind it is proven by lane-j-tunnels.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-tunnels-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/tunnels-page-e2e.py" ] || { echo "SKIP lane-j-tunnels-ui: ci/tunnels-page-e2e.py was not copied next to the scenarios"; exit 0; }
export PATH="$NL_T:$PATH"
nl_kill_daemons

nl_write_installer_toml
nl_boot "$DB"
# the far end of the tunnel the page makes: plain iproute2, a different implementation from the one under test
INET ip link add far-ipip type ipip remote "$NL_RTR_WAN" local "$NL_WWW" ttl 64
INET ip addr add 10.99.0.2/30 dev far-ipip; INET ip link set far-ipip up
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"
nl_ok "booted with the LAN address the page serves on"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_FAR="$NL_WWW" E2E_LOCAL="$NL_RTR_WAN" \
      E2E_FAR_CHECK="ip netns exec nl-inet ping -c2 -W2 10.99.0.1" \
      E2E_LINK_CHECK="ip netns exec nl-rtr ip -d link show tn-site" \
      "$PW/bin/python" "$NL_T/tunnels-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the tunnels page e2e failed (exit $rc)"
n=$(grep -c '^PASS: ' <<<"$out" || true)
[ "$n" -ge 20 ] || nl_fail "only $n page checks ran"
nl_ok "$n page checks passed in Firefox"
nl_web_stop
echo "ALL TUNNEL UI CHECKS PASSED"
