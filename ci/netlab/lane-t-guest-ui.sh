#!/usr/bin/env bash
# Lane T (UI): the guest network page driven in a real browser (ci/guest-page-e2e.py, Playwright + Firefox) against
# the shipped patronus-web in the netlab router: menu entry, every setting on the page, a refused change shown on the
# page, then switching the guest network on/off, the password/QR/voucher/open/close buttons and the live status card.
# SKIPs (exit 0) where Playwright and Firefox cannot be installed (no network): the API behind every button is proven
# by lane-t-guest.sh and the web crate's guest_tests.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-t-guest-ui.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
PW=/opt/pw
if [ ! -x "$PW/bin/playwright" ]; then
  { apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1 \
    && python3 -m venv "$PW" && "$PW/bin/pip" install -q playwright \
    && "$PW/bin/playwright" install --with-deps firefox >/dev/null 2>&1; } \
    || { echo "SKIP lane-t-guest-ui: Playwright/Firefox could not be installed here"; exit 0; }
fi
[ -f "$NL_T/guest-page-e2e.py" ] || { echo "SKIP lane-t-guest-ui: ci/guest-page-e2e.py was not copied next to the scenarios"; exit 0; }

nl_write_installer_toml
ip netns del nl-client2 2>/dev/null || true
nl_up
ip netns add nl-client2; ip -n nl-client2 link set lo up
ip link add gst-a netns nl-rtr type veth peer name g0 netns nl-client2
ip link add gst-b netns nl-rtr type veth peer name g1 netns nl-client2
R ip link set gst-a up; R ip link set gst-b up
trap 'ip netns del nl-client2 2>/dev/null || true' EXIT
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_ok "booted with two spare ports for the guest network"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_PORTS=gst-a,gst-b E2E_DNS_UPSTREAMS=$NL_DNS \
      E2E_LAN_CLASH=192.168.50.5/24 "$PW/bin/python" "$NL_T/guest-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the guest page e2e failed (exit $rc)"
nl_ok "guest page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-t-guest-ui"
