#!/usr/bin/env bash
# Lane N: DHCPv6 prefix delegation on the WAN. A real ISP-side DHCPv6 server
# (ISC dhcpd with prefix6 + radvd with the M flag) delegates a /56 to the
# router's WAN; Patronus (dhcpcd ia_pd) carves a /64 for the LAN, puts the
# router's address on it, and radvd advertises it so a LAN client configures a
# global IPv6 address from the delegated prefix.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-dhcp6pd.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v dhcpcd >/dev/null || apt-get install -y -qq dhcpcd5 >/dev/null 2>&1 || apt-get install -y -qq dhcpcd >/dev/null 2>&1 || apt-get install -y -qq dhcpcd-base >/dev/null
command -v radvd >/dev/null || apt-get install -y -qq radvd >/dev/null
command -v dhcpd >/dev/null || apt-get install -y -qq isc-dhcp-server >/dev/null
for t in dhcpcd radvd dhcpd; do command -v $t >/dev/null || nl_fail "$t is not installed"; done

nl_write_installer_toml
nl_boot "$DB"

# --- the ISP side: RA with the managed flag + DHCPv6 (IA_NA and prefix6)
ISP ip -6 addr add 2001:db8:ffff::1/64 dev up0 nodad
cat >"$NL_T/isp-radvd.conf" <<'CONF'
interface up0 {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 6;
    prefix 2001:db8:ffff::/64 { AdvOnLink on; AdvAutonomous off; };
};
CONF
cat >"$NL_T/isp-dhcpd6.conf" <<'CONF'
default-lease-time 600;
max-lease-time 1200;
ddns-update-style none;
authoritative;
subnet6 2001:db8:ffff::/64 {
    range6 2001:db8:ffff::100 2001:db8:ffff::200;
    prefix6 2001:db8:1000:: 2001:db8:10ff:: /56;
}
CONF
: >"$NL_T/isp-dhcpd6.leases"
ISP sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
nl_bg ISP radvd -n -C "$NL_T/isp-radvd.conf" -p /tmp/isp-radvd.pid
nl_bg ISP dhcpd -6 -d -cf "$NL_T/isp-dhcpd6.conf" -lf "$NL_T/isp-dhcpd6.leases" up0
sleep 2

nl_web_start "$DB"; nl_login
# Router advertisements on the LAN: the lab has no init system for Patronus' RA
# service, so radvd runs here with the configuration Patronus renders for a LAN
# RA (every /64 on the interface); Patronus' PD hook HUPs it when the prefix arrives.
cat >"$NL_T/lan-radvd.conf" <<'CONF'
interface rtr-lan {
    AdvSendAdvert on;
    IgnoreIfMissing on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 6;
    prefix ::/64 { AdvOnLink on; AdvAutonomous on; };
};
CONF
nl_bg R radvd -n -C "$NL_T/lan-radvd.conf" -p /tmp/lan-radvd.pid
nl_api PUT /interfaces/$NL_LAN_IF '{"role":"lan","ipv4_mode":"static","ipv4":["192.168.50.1/24"],"ipv6_mode":"none","force":true}'
[ "$NL_CODE" = 200 ] || nl_fail "LAN: $NL_CODE $(cat "$NL_OUT")"
nl_api PUT /interfaces/$NL_WAN_IF "{\"role\":\"wan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"203.0.113.2/24\"],\"gateway4\":\"203.0.113.1\",\"ipv6_mode\":\"dhcp6\",\"pd_downstream\":[\"$NL_LAN_IF\"],\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "WAN with prefix delegation: $NL_CODE $(cat "$NL_OUT")"
nl_ok "WAN set to DHCPv6 with prefix delegation to $NL_LAN_IF"

lan_pd() { R ip -6 -o addr show dev "$NL_LAN_IF" scope global | grep -o '2001:db8:10[0-9a-f]*:[0-9a-f:]*/64' | head -1; }
nl_wait 90 sh -c 'ip netns exec nl-rtr ip -6 -o addr show dev rtr-lan scope global | grep "2001:db8:10" >/dev/null' \
  || { R ip -6 addr; nl_fail "no delegated prefix address on the LAN port after 90 s"; }
PD=$(lan_pd)
nl_ok "the router carved $PD out of the delegated /56 for the LAN"

nl_wait 60 sh -c 'ip netns exec nl-client ip -6 -o addr show dev lan0 scope global | grep "2001:db8:10" >/dev/null' \
  || { C ip -6 addr; R sh -c 'cat /etc/radvd.conf; pgrep -a radvd' || true; nl_fail "the LAN client got no address from the delegated prefix"; }
nl_ok "LAN client configured $(C ip -6 -o addr show dev lan0 scope global | grep -o '2001:db8:10[0-9a-f:]*/64' | head -1) from the router's advertisement"
[ "$(sqlite3 "$DB" "SELECT pd_downstream FROM interfaces WHERE name='$NL_WAN_IF'")" = "$NL_LAN_IF" ] || nl_fail "prefix delegation not in the store"
echo "PASS lane-n-dhcp6pd"
