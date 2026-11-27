#!/usr/bin/env bash
# Lane W (UI): the network map page driven in Firefox (ci/netmap-page-e2e.py, Playwright) against the shipped
# patronus-web on the deliberately flat LAN of lane-w-netmap.sh: menu entry, the map with every device, the
# flat-network banner, Mermaid + PNG export, node details, list view, the advisor's Apply button (pressed: the
# devices are isolated and the finding goes away), phone width, and the read-only live view opened with a share key
# in a browser that never signed in. Needs Playwright + Firefox at /opt/pw (ci/netlab/run.sh installs them).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-w-netmap-ui.db
. "$(dirname "$0")/fixtures/netmap-topo.sh"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/netmap-page-e2e.py" ] || nl_fail "ci/netmap-page-e2e.py was not copied next to the scenarios"

rm -f "$DB" "$NL_T/nl-jar"
map_boot
nl_web_start "$DB"; nl_login
nl_api_ok "settings" PUT /map/settings '{"probe":"ping"}'
wake
nl_api_ok "discover" POST /map/discover
for spec in "10 laptop computer" "11 nas infra" "12 front-cam camera" "13 living-tv media" "14 printer printer"; do
  set -- $spec
  nl_api_ok "label $2" PUT /map/devices/02:aa:00:00:00:$1 "{\"name\":\"$2\",\"class\":\"$3\"}"
done
nl_ok "flat LAN discovered and labelled"
out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_MIN_DEVICES=5 E2E_SHOTS=/t/netmap-shots \
      "$PW/bin/python" "$NL_T/netmap-page-e2e.py" 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the network map page e2e failed (exit $rc)"
want_deny "after Apply in the browser: cam -> laptop tcp 7000" http_ok nl-cam 192.168.50.10 7000
nl_ok "network map page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-w-netmap-ui"
