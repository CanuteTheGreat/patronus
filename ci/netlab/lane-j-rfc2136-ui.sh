#!/usr/bin/env bash
# Lane J (UI): the RFC 2136 dynamic DNS page driven in a real browser (ci/rfc2136-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router and a real BIND (fixtures/rfc2136-named.sh): menu entry, every
# setting and the clients form, phone width in the light and dark scheme, a non-base64 secret refused on the page,
# then a good client published to the server, a wrong secret shown as FAILED, delete and switch off. Needs Playwright
# + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing). The DNS side
# (zone contents, address changes, TCP, reboot) is proven by lane-j-rfc2136.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-rfc2136-ui.db
rm -f "$DB" "$NL_T/nl-jar"
export PATH="$NL_T:$PATH"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/rfc2136-page-e2e.py" ] || { echo "SKIP lane-j-rfc2136-ui: ci/rfc2136-page-e2e.py was not copied next to the scenarios"; exit 0; }

nl_write_installer_toml
nl_kill_daemons
ND=$NL_T/named
NS_IP=198.51.100.54
KEY=$(head -c 32 /dev/urandom | base64 -w0)
KEY512=$(head -c 64 /dev/urandom | base64 -w0)
WRONG=$(head -c 32 /dev/urandom | base64 -w0)
. "$NL_T/fixtures/rfc2136-named.sh"
trap named_stop EXIT

nl_up
named_start
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login
nl_ok "booted with a real DNS server (zone example.net, TSIG required)"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_SERVER="$NS_IP" E2E_ZONE=example.net \
      E2E_KEY_NAME=ddns-key E2E_KEY_SECRET="$KEY" E2E_WRONG_SECRET="$WRONG" \
      "$PW/bin/python" "$NL_T/rfc2136-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the RFC 2136 page e2e failed (exit $rc)"
want_dns e2e.example.net A "$NL_RTR_WAN" "the record the page created is in the real zone"
nl_ok "RFC 2136 page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-j-rfc2136-ui"
