#!/usr/bin/env bash
# Lane J (UI): the intrusion detection pages driven in a real browser (ci/ids-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web with real Suricata in the netlab router: the menu entry, every setting and
# collection, the seeded rule sets with their licences, a refused entry, 390 px phone layout in the light and the
# dark scheme, then through the pages only: add a rule set from a local HTTP source, "Update rule sets now",
# add a policy, change a setting, make matching traffic, find the alert in the alert browser, suppress its rule
# with one click and delete the entry again.
# Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are
# missing); the API behind every button is also proven by lane-j-ids.sh and the web crate's tests.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-ids-ui.db
EVE=/var/log/suricata/eve.json
rm -f "$DB" "$NL_T/nl-jar" "$EVE"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/ids-page-e2e.py" ] || { echo "SKIP lane-j-ids-ui: ci/ids-page-e2e.py was not copied next to the scenarios"; exit 0; }
suri_up() { pgrep -f '^/usr/bin/suricata -c' >/dev/null; }

nl_write_installer_toml
pkill -f '^/usr/bin/suricata -c' 2>/dev/null || true; sleep 1; rm -rf /var/lib/patronus/net /run/patronus
mkdir -p /var/log/suricata
export PATRONUS_IDS_TICK_SECS=2
nl_boot "$DB"
nl_web_start "$DB"; nl_login

SRC=/t/ids-ui-src
rm -rf "$SRC"; mkdir -p "$SRC/rules"
printf '%s\n' 'alert tcp any any -> any 80 (msg:"Netlab UI evil-set"; flow:to_server; content:"evil-set"; classtype:trojan-activity; sid:2900001; rev:1;)' > "$SRC/rules/netlab-ui.rules"
tar -czf "$SRC/set.tar.gz" -C "$SRC" rules
nl_bg INET python3 -m http.server 8081 --bind 0.0.0.0 --directory "$SRC"
src_up() { R curl -sf -m 3 -o /dev/null "http://$NL_WWW:8081/set.tar.gz"; }
nl_wait 20 src_up || nl_fail "the local rule source did not come up"

nl_api_ok "enable IDS on the WAN" PUT /svc/ids '{"enabled":true,"mode":"ids","interface":"@wan","home_net":"192.168.50.0/24","distro_rules":false}'
nl_wait 60 suri_up || nl_fail "suricata did not start"
nl_ok "suricata running in IDS mode"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 \
      E2E_SOURCE_URL="http://$NL_WWW:8081/set.tar.gz" E2E_PROBE_URL="http://$NL_WWW/" E2E_SID=2900001 \
      "$PW/bin/python" "$NL_T/ids-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || { tail -30 "$NL_T/nl-web.log"; nl_fail "the intrusion detection page e2e failed (exit $rc)"; }
nl_ok "intrusion detection pages driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
nl_web_stop
echo "PASS lane-j-ids-ui"
