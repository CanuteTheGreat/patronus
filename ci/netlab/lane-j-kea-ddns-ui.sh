#!/usr/bin/env bash
# Lane J (UI): the Kea DDNS page driven in a real browser (ci/kea-ddns-page-e2e.py, Playwright + Firefox) against the
# shipped patronus-web in the netlab router, with real Kea, the real Kea DDNS daemon and Unbound behind it: menu entry,
# every setting, phone width in the light and dark scheme, refusals shown on the page, then through the page only: switch
# it on, see D2 and the receiver run, change a setting, get a lease with a real DHCP client (run from the LAN client's
# namespace) and see its name in the registered names table, switch it off. Needs Playwright + Firefox preinstalled at
# /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing). The DNS behaviour behind it is proven by
# lane-j-kea-ddns.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-kea-ddns-ui.db
rm -f "$DB" "$NL_T/nl-jar"
rm -rf /var/lib/kea/kea-leases4.csv* /var/lib/patronus/net/kea-ddns*
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/kea-ddns-page-e2e.py" ] || { echo "SKIP lane-j-kea-ddns-ui: ci/kea-ddns-page-e2e.py was not copied next to the scenarios"; exit 0; }
export PATH="$NL_T:$PATH"
nl_kill_daemons
pkill -x 'unbound|kea-dhcp4|kea-dhcp-ddns' 2>/dev/null || true
[ ! -e /usr/sbin/kea-dhcp4.parked ] || mv /usr/sbin/kea-dhcp4.parked /usr/sbin/kea-dhcp4
command -v udhcpc >/dev/null || apt-get install -y -qq udhcpc >/dev/null 2>&1 || true
UDHCPC=udhcpc; command -v udhcpc >/dev/null || UDHCPC="busybox udhcpc"
cleanup() {
  pkill -x 'unbound|kea-dhcp4|kea-dhcp-ddns|udhcpc' 2>/dev/null || true
  rm -f /etc/init.d/kea-dhcp4 /etc/kea/kea-dhcp4.conf
  [ ! -e /usr/sbin/kea-dhcp4 ] || mv /usr/sbin/kea-dhcp4 /usr/sbin/kea-dhcp4.parked
}
trap cleanup EXIT

cat > /etc/init.d/kea-dhcp4 <<'SH'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          kea-dhcp4
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: netlab stand-in for the Kea DHCPv4 init script
### END INIT INFO
PIDF=/run/kea-dhcp4-netlab.pid
alive() { [ -f $PIDF ] && kill -0 "$(cat $PIDF)" 2>/dev/null; }
run() {
  mkdir -p /run/kea /var/lib/kea
  ip netns exec nl-rtr /usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf </dev/null >>/var/log/kea4-netlab.log 2>&1 &
  echo $! > $PIDF
}
case "$1" in
  start) alive || run ;;
  stop) alive && kill "$(cat $PIDF)"; rm -f $PIDF ;;
  restart|reload) alive && kill "$(cat $PIDF)"; sleep 0.5; rm -f $PIDF; run ;;
  status) alive ;;
esac
exit 0
SH
chmod 755 /etc/init.d/kea-dhcp4
cat > "$NL_T/nl-udhcpc.sh" <<'EOF2'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    ;;
esac
exit 0
EOF2
chmod +x "$NL_T/nl-udhcpc.sh"
cat > "$NL_T/nl-ui-lease.sh" <<EOF2
#!/bin/sh
ip link set lan0 address 02:00:00:00:00:21
ip addr flush dev lan0
exec $UDHCPC -i lan0 -n -q -t 8 -T 2 -x hostname:uipc -s "$NL_T/nl-udhcpc.sh"
EOF2
chmod +x "$NL_T/nl-ui-lease.sh"

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"
nl_api_ok "DNS resolver, local domain" PUT /dns/settings '{"mode":"resolver","dnssec":false,"local_domain":"lan.example"}'
nl_api_ok "DHCP pool" POST /dhcp/pools '{"interface":"@lan","range_start":"192.168.50.100","range_end":"192.168.50.150","lease_time":3600,"domain":"lan.example"}'
nl_api_ok "apply DHCP" POST /dhcp/apply
nl_wait 15 pgrep -x kea-dhcp4 || nl_fail "kea-dhcp4 is not running"
nl_ok "booted with Kea serving a pool and Unbound as the resolver"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_LEASE_CMD="sh $NL_T/nl-ui-lease.sh" E2E_LEASE_NAME=uipc \
      "$PW/bin/python" "$NL_T/kea-ddns-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || { tail -30 /var/log/kea4-netlab.log 2>/dev/null; nl_fail "the Kea DDNS page e2e failed (exit $rc)"; }
n=$(grep -c '^PASS:' <<<"$out" || true)
nl_ok "$n browser checks passed"
nl_web_stop
echo "ALL KEA DDNS UI CHECKS PASSED"
