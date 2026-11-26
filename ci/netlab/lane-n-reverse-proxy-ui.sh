#!/usr/bin/env bash
# Lane N (UI): the reverse proxy page driven in a real browser (ci/revproxy-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router: menu entry, every setting and table on the page, phone width
# in the light and dark scheme, a refused listener shown on the page, then "Publish a LAN service", live statistics,
# the configuration check, delete and switch off. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh
# (fails, never skips, when they are missing). The traffic behind it is proven by lane-n-reverse-proxy.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-reverse-proxy-ui.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/revproxy-page-e2e.py" ] || { echo "SKIP lane-n-reverse-proxy-ui: ci/revproxy-page-e2e.py was not copied next to the scenarios"; exit 0; }
command -v haproxy >/dev/null || apt-get install -y -qq haproxy >/dev/null
command -v haproxy >/dev/null || nl_fail "haproxy not installed"
nl_kill_daemons haproxy

nl_write_installer_toml
nl_boot "$DB"
C ip addr add 192.168.50.13/24 dev lan0
nl_bg C python3 "$NL_T/nl-http.py" 192.168.50.13 8080
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"
nl_ok "booted with a LAN server for the page to publish"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_SERVER=192.168.50.13:8080 E2E_WEB_PORT=8443 \
      "$PW/bin/python" "$NL_T/revproxy-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the reverse proxy page e2e failed (exit $rc)"
nl_ok "reverse proxy page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-n-reverse-proxy-ui"
