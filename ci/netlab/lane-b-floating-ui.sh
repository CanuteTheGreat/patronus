#!/usr/bin/env bash
# Lane B (UI): the Firewall page's floating rules, interface groups, limiters, overload tables, categories and
# log summary driven in a real browser (ci/firewall-floating-e2e.py, Playwright + Firefox) against the shipped
# patronus-web in the netlab router: desktop 1280 px and phone 390 px, light and dark. The API behind every
# control is proven with real traffic by lane-b-floating.sh; this proves a person can use it.
# Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-floating-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/firewall-floating-e2e.py" ] || { echo "SKIP lane-b-floating-ui: ci/firewall-floating-e2e.py was not copied next to the scenarios"; exit 0; }

nl_write_installer_toml
ip netns del nl-c2 2>/dev/null || true
nl_up
ip netns add nl-c2; ip -n nl-c2 link set lo up
ip link add rtr-opt netns nl-rtr type veth peer name lan0 netns nl-c2
R ip addr add 192.168.60.1/24 dev rtr-opt; R ip link set rtr-opt up
trap 'nl_stop_servers 2>/dev/null || true; ip netns del nl-c2 2>/dev/null || true' EXIT
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_ok "booted with a second LAN-side port"

# a logging rule and some traffic, so the Logs tab has lines to summarise
nl_api POST /firewall/rules '{"name":"ui-log-block","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"9000","description":"ui-log-block","enabled":true,"log":true}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "log rule: HTTP $NL_CODE $(cat "$NL_OUT")"
for _ in 1 2 3 4 5 6; do C python3 "$NL_T/nl-conn.py" 198.51.100.20 9000 >/dev/null 2>&1 || true; done

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_IFACES=rtr-lan,rtr-opt E2E_LOG=1 E2E_SHOTS="${E2E_SHOTS:-}" \
      "$PW/bin/python" "$NL_T/firewall-floating-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the firewall floating/groups page e2e failed (exit $rc)"
nl_ok "firewall floating rules, groups and limiters driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
