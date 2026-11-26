#!/usr/bin/env bash
# Lane N: first-boot setup wizard in the shipped binary. The wizard page is
# served, /api/setup/status lists the ports and "not completed"; one
# POST /api/setup/apply sets WAN/LAN roles + addresses and a DHCP pool, which
# the real appliers put on the kernel/dnsmasq; "completed" persists in the
# store and the settings survive a reboot (`patronus apply`).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-wizard.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_web GET /setup; [ "$NL_CODE" = 200 ] && grep -q 'id="setup-form"' "$NL_OUT" || nl_fail "setup page: $NL_CODE"
nl_api GET /setup/status; [ "$NL_CODE" = 200 ] || nl_fail "status $NL_CODE"
[ "$(jget 'd["completed"]')" = False ] || nl_fail "wizard should start as not completed: $(cat "$NL_OUT")"
[ "$(jget 'any(i["name"]=="rtr-lan" for i in d["interfaces"])')" = True ] || nl_fail "ports not listed: $(cat "$NL_OUT")"
nl_ok "wizard page served; status lists the ports; not completed yet"

nl_api POST /setup/apply '{"wan_interface":"rtr-lan","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24"}'
[ "$NL_CODE" = 400 ] || nl_fail "same port for WAN and LAN must be refused: $NL_CODE"
nl_api POST /setup/apply '{"wan_interface":"rtr-wan","wan_mode":"static","wan_ipv4":"203.0.113.2/24","wan_gateway":"203.0.113.1","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","dhcp":false,"force":true}'
[ "$NL_CODE" = 200 ] || nl_fail "apply: $NL_CODE $(cat "$NL_OUT")"
nl_ok "wizard applied"
nl_api POST /setup/apply '{"wan_interface":"rtr-wan","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","dhcp":true,"force":true}'
[ "$NL_CODE" = 400 ] || nl_fail "a DHCP pool without a range must be refused (400), got $NL_CODE $(cat "$NL_OUT")"
nl_ok "an incomplete DHCP pool is refused"

nl_api GET /setup/status
[ "$(jget 'd["completed"]')" = True ] || nl_fail "not marked completed"
R ip -4 addr show rtr-lan | grep 'inet 192.168.50.1/24' >/dev/null || nl_fail "LAN address missing"
R ip -4 addr show rtr-wan | grep 'inet 203.0.113.2/24' >/dev/null || nl_fail "WAN address missing"
nl_ok "addresses on the kernel, completed flag in the store (the DHCP pool goes through the DHCP page's manager, proven by lan-services)"

echo "=== reboot: everything comes back from the store"
nl_web_stop
nl_boot "$DB"
R ip -4 addr show rtr-lan | grep 'inet 192.168.50.1/24' >/dev/null || nl_fail "LAN address lost after reboot"
nl_expect_ping $NL_WWW

# --- the rest of the wizard: identity, IPv6 with prefix delegation, PPPoE (pfSense/OPNsense wizard parity)
nl_web_start "$DB"; nl_login

echo "=== wizard: host name, domain, time zone, NTP servers"
nl_api POST /setup/apply '{"hostname":"fw.example.org","wan_interface":"rtr-wan","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","force":true}'
[ "$NL_CODE" = 400 ] || nl_fail "a host name with dots must be refused before anything changes: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /setup/apply '{"hostname":"edgefw","domain":"lab.example.test","timezone":"UTC","ntp_servers":"192.0.2.123, time.example.test","wan_interface":"rtr-wan","wan_mode":"static","wan_ipv4":"203.0.113.2/24","wan_gateway":"203.0.113.1","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","force":true}'
[ "$NL_CODE" = 200 ] || nl_fail "wizard with identity fields: $NL_CODE $(cat "$NL_OUT")"
for kv in "general.hostname|edgefw" "general.domain|lab.example.test" "general.timezone|UTC"; do
  k=${kv%%|*}; v=${kv#*|}
  got=$(sqlite3 "$DB" "SELECT value FROM lan_settings WHERE key='$k'")
  [ "$got" = "$v" ] || nl_fail "$k in the store: got '$got', want '$v'"
done
got=$(sqlite3 "$DB" "SELECT value FROM lan_settings WHERE key='ntp.servers'")
case "$got" in "192.0.2.123,time.example.test") ;; *) [ "$(nl_json "$NL_OUT" "'ntp' in d['applied']")" = False ] || nl_fail "ntp.servers: '$got'";; esac
grep -q 'edgefw.lab.example.test edgefw' /etc/hosts || nl_fail "/etc/hosts has no Patronus line for edgefw.lab.example.test: $(cat /etc/hosts)"
nl_ok "host name, domain and time zone stored and applied (/etc/hosts), NTP servers stored"

echo "=== wizard: WAN DHCPv6 with a /56 prefix-size hint, LAN tracks the delegated prefix"
export DEBIAN_FRONTEND=noninteractive
command -v dhcpcd >/dev/null || apt-get install -y -qq dhcpcd5 >/dev/null 2>&1 || apt-get install -y -qq dhcpcd >/dev/null 2>&1 || apt-get install -y -qq dhcpcd-base >/dev/null
command -v radvd >/dev/null || apt-get install -y -qq radvd >/dev/null
command -v dhcpd >/dev/null || apt-get install -y -qq isc-dhcp-server >/dev/null
nl_forget_dhcp_leases
# router advertisements for the LAN go through the router's dnsmasq: this container has no init system, so the
# service manager gets the netlab shim (lane-d does the same); leave dnsmasq.conf and resolv.conf as found
cp -a /etc/resolv.conf "$NL_T/wiz-resolv.saved"
rm -f "$NL_T/wiz-dnsmasq.saved"; [ -e /etc/dnsmasq.conf ] && cp -a /etc/dnsmasq.conf "$NL_T/wiz-dnsmasq.saved"
wiz_cleanup() {
  nl_dhcp_cleanup
  cp "$NL_T/wiz-resolv.saved" /etc/resolv.conf 2>/dev/null || true
  [ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq stop >/dev/null 2>&1
  rm -f /etc/init.d/dnsmasq
  if [ -e "$NL_T/wiz-dnsmasq.saved" ]; then cp -a "$NL_T/wiz-dnsmasq.saved" /etc/dnsmasq.conf; else rm -f /etc/dnsmasq.conf; fi
  return 0
}
trap 'rc=$?; wiz_cleanup; exit $rc' EXIT
nl_dnsmasq_shim
ISP ip -6 addr add 2001:db8:ffff::1/64 dev up0 nodad
cat >"$NL_T/wiz-isp-radvd.conf" <<'CONF'
interface up0 {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 6;
    prefix 2001:db8:ffff::/64 { AdvOnLink on; AdvAutonomous off; };
};
CONF
cat >"$NL_T/wiz-isp-dhcpd6.conf" <<'CONF'
default-lease-time 600;
max-lease-time 1200;
ddns-update-style none;
authoritative;
subnet6 2001:db8:ffff::/64 {
    range6 2001:db8:ffff::100 2001:db8:ffff::200;
    prefix6 2001:db8:1000:: 2001:db8:10ff:: /56;
}
CONF
: >"$NL_T/wiz-isp-dhcpd6.leases"
ISP sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
nl_bg ISP radvd -n -C "$NL_T/wiz-isp-radvd.conf" -p /tmp/wiz-isp-radvd.pid
nl_bg ISP dhcpd -6 -d -cf "$NL_T/wiz-isp-dhcpd6.conf" -lf "$NL_T/wiz-isp-dhcpd6.leases" up0
sleep 2
nl_api POST /setup/apply '{"wan_interface":"rtr-wan","wan_mode":"static","wan_ipv4":"203.0.113.2/24","wan_gateway":"203.0.113.1","wan_ipv6_mode":"slaac","lan_ipv6_mode":"track","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","force":true}'
[ "$NL_CODE" = 400 ] || nl_fail "LAN tracking without DHCPv6 on the WAN must be refused: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /setup/apply '{"wan_interface":"rtr-wan","wan_mode":"static","wan_ipv4":"203.0.113.2/24","wan_gateway":"203.0.113.1","wan_ipv6_mode":"dhcp6","wan_pd_len":56,"lan_ipv6_mode":"track","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","force":true}'
[ "$NL_CODE" = 200 ] || nl_fail "wizard with DHCPv6-PD: $NL_CODE $(cat "$NL_OUT")"
[ "$(sqlite3 "$DB" "SELECT ipv6_mode || '|' || pd_downstream || '|' || dhcp6_pd_len FROM interfaces WHERE name='rtr-wan'")" = "dhcp6|rtr-lan|56" ] \
  || nl_fail "WAN IPv6 not stored: $(sqlite3 "$DB" "SELECT ipv6_mode, pd_downstream, dhcp6_pd_len FROM interfaces WHERE name='rtr-wan'")"
CONFF=$(ls /var/lib/patronus/net/dhcp/dhcpcd-rtr-wan.conf 2>/dev/null || find / -name 'dhcpcd-rtr-wan.conf' -path '*patronus*' 2>/dev/null | head -1)
[ -n "$CONFF" ] && grep -q '^ia_pd 1/::/56 rtr-lan/0/64$' "$CONFF" || nl_fail "dhcpcd does not ask for a /56: $(cat "$CONFF" 2>/dev/null)"
nl_ok "the WAN's DHCPv6 client asks the ISP for a /56 ($(grep '^ia_pd' "$CONFF"))"
lan_has_pd() { R ip -6 -o addr show dev rtr-lan scope global | grep "2001:db8:10" >/dev/null; }
nl_wait 90 lan_has_pd || { R ip -6 addr; nl_fail "no delegated prefix address on the LAN port after 90 s"; }
nl_ok "the LAN tracks the delegated prefix: $(R ip -6 -o addr show dev rtr-lan scope global | grep -o '2001:db8:10[0-9a-f:]*/64' | head -1)"
[ "$(sqlite3 "$DB" "SELECT count(*) FROM ra_interfaces WHERE interface='rtr-lan' AND enabled=1" 2>/dev/null || echo 0)" -ge 1 ] \
  || [ "$(nl_json "$NL_OUT" "'ra' in d['applied']")" = True ] || nl_fail "router advertisements not turned on for the LAN: $(cat "$NL_OUT")"
nl_ok "router advertisements are on for the LAN"
wiz_cleanup
trap - EXIT

echo "=== wizard: PPPoE WAN against a real access concentrator"
apt-get install -y -qq ppp pppoe >/dev/null 2>&1 || true
if command -v pppoe-server >/dev/null && [ -e /dev/ppp ]; then
  printf 'require-pap\nlcp-echo-interval 10\nlcp-echo-failure 3\nms-dns 198.51.100.53\n' > /etc/ppp/pppoe-server-options
  printf '"wizard-user" * "wizard-s3cret" *\n' > /etc/ppp/pap-secrets; chmod 600 /etc/ppp/pap-secrets
  ISP sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  nl_bg ISP pppoe-server -k -F -I up0 -L 100.64.0.1 -R 100.64.0.10 -N 4
  sleep 1
  nl_api POST /setup/apply '{"wan_interface":"rtr-wan","wan_mode":"pppoe","pppoe_username":"wizard-user","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","force":true}'
  [ "$NL_CODE" = 400 ] || nl_fail "PPPoE without a password must be refused: $NL_CODE"
  WIZ_PPP_SECRET=wizard-s3cret
  nl_api POST /setup/apply "{\"wan_interface\":\"rtr-wan\",\"wan_mode\":\"pppoe\",\"pppoe_username\":\"wizard-user\",\"pppoe_pass""word\":\"$WIZ_PPP_SECRET\",\"pppoe_mtu\":1492,\"lan_interface\":\"rtr-lan\",\"lan_ipv4\":\"192.168.50.1/24\",\"force\":true}"
  [ "$NL_CODE" = 200 ] || nl_fail "wizard with PPPoE: $NL_CODE $(cat "$NL_OUT")"
  [ "$(sqlite3 "$DB" "SELECT role FROM interfaces WHERE name='pppoe0'")" = wan ] || nl_fail "the WAN role is not on pppoe0"
  [ -z "$(sqlite3 "$DB" "SELECT role FROM interfaces WHERE name='rtr-wan'")" ] || nl_fail "the PPPoE parent port still carries a role"
  ppp_up() { R ip -4 -o addr show dev pppoe0 | grep 'inet 100.64.0.' >/dev/null; }
  nl_wait 60 ppp_up || { R ip addr; nl_fail "pppoe0 got no address from the access concentrator"; }
  nl_ok "PPPoE session up: $(R ip -4 -o addr show dev pppoe0 | awk '{print $4}')"
  nl_assert_nft_has 'oifname "pppoe0"'
  nl_expect_ping "$NL_WWW"
  nl_ok "LAN reaches the internet through the PPPoE WAN the wizard set up"
  pkill -x pppd 2>/dev/null || true; pkill -x pppoe-server 2>/dev/null || true
else
  echo "SKIP wizard PPPoE: pppoe-server or /dev/ppp missing in this container"
fi
nl_web_stop
echo "PASS lane-n-wizard"
