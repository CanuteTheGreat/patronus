#!/usr/bin/env bash
# Lane N: the ISP's DHCPv6 server offers an address (IA_NA) but REFUSES the delegated prefix (IA_PD, status NoPrefixAvail): what a
# real ISP answers a replacement router whose DUID/IAID still hold the old router's binding. Proves, with the real dhcpcd:
#   1. the WAN still gets its IA_NA address (dhcpcd keeps it while the prefix is refused: no config option needed),
#   2. the Interfaces API/page says why there is no prefix, in one readable sentence read from dhcpcd's own log,
#   3. when the ISP grants the prefix later, dhcpcd's next renew delegates it (no restart, no manual step) and the problem goes away.
# The server answers from a GLOBAL address (like a relayed ISP server), see lane-n-dhcp6pd.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-dhcp6pd-refused.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v dhcpcd >/dev/null || apt-get install -y -qq dhcpcd5 >/dev/null 2>&1 || apt-get install -y -qq dhcpcd >/dev/null 2>&1 || apt-get install -y -qq dhcpcd-base >/dev/null
command -v radvd >/dev/null || apt-get install -y -qq radvd >/dev/null
command -v dhcpd >/dev/null || apt-get install -y -qq isc-dhcp-server >/dev/null
for t in dhcpcd radvd dhcpd python3; do command -v $t >/dev/null || nl_fail "$t is not installed"; done

nl_write_installer_toml
nl_boot "$DB"

# short leases: dhcpcd asks for the missing prefix again at every renew (T1 = half the lease)
LEASE=${NL_LEASE:-60}
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
# phase 1: addresses only, no prefix6 pool = IA_PD answered with a "no prefixes available" status
dhcpd6_conf() { # WITH_PREFIX (yes|no)
  cat <<CONF
default-lease-time $LEASE;
max-lease-time $((LEASE * 2));
ddns-update-style none;
authoritative;
subnet6 2001:db8:ffff::/64 {
    range6 2001:db8:ffff::100 2001:db8:ffff::200;
CONF
  [ "$1" = yes ] && echo '    prefix6 2001:db8:1000:: 2001:db8:10ff:: /56;'
  echo '}'
}
dhcpd6_conf no >"$NL_T/isp-dhcpd6.conf"
: >"$NL_T/isp-dhcpd6.leases"
cat >"$NL_T/isp-src.nft" <<'NFT'
table ip6 isp_dhcp6_src {
    chain post { type nat hook postrouting priority 100; ip6 saddr fe80::/10 udp sport 547 udp dport 546 counter snat to 2001:db8:ffff::1; }
}
NFT
ISP nft -f "$NL_T/isp-src.nft" || nl_fail "could not install the global-source rewrite in the ISP namespace"
ISP sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
nl_bg ISP radvd -n -C "$NL_T/isp-radvd.conf" -p /tmp/isp-radvd.pid
nl_bg ISP dhcpd -6 -d -cf "$NL_T/isp-dhcpd6.conf" -lf "$NL_T/isp-dhcpd6.leases" up0
sleep 2

nl_web_start "$DB"; nl_login
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
nl_ok "WAN set to DHCPv6 with prefix delegation to $NL_LAN_IF, the ISP refuses the prefix"

has_wan_na() { ip netns exec nl-rtr ip -6 -o addr show dev rtr-wan scope global | grep "2001:db8:ffff::[12][0-9a-f][0-9a-f]" >/dev/null; }
has_lan_pd() { ip netns exec nl-rtr ip -6 -o addr show dev rtr-lan scope global | grep "2001:db8:10" >/dev/null; }
# problems of the Interfaces API: the first one's kind and message, or "none"
problem() {
  nl_api GET /interfaces
  [ "$NL_CODE" = 200 ] || nl_fail "GET /interfaces: $NL_CODE"
  python3 - "$NL_OUT" <<'PY'
import json, sys
p = json.load(open(sys.argv[1])).get("problems") or []
print("none" if not p else p[0]["interface"] + "|" + p[0]["kind"] + "|" + p[0]["message"])
PY
}
problem_is() { case "$(problem)" in "$1"*) return 0 ;; esac; return 1; }

# 1. the address survives the refused prefix
nl_wait 60 has_wan_na || { R ip -6 addr show dev "$NL_WAN_IF"; tail -30 /run/patronus/patronus-dhcpc.rtr-wan.log || true; nl_fail "the WAN got no IA_NA address while the prefix was refused"; }
nl_ok "the WAN got its IA_NA address although the ISP refused the prefix"
! has_lan_pd || nl_fail "a prefix was delegated although the ISP refused it"

# 2. the page says why
nl_wait 30 problem_is "rtr-wan|pd-refused|The ISP refused the delegated prefix (NoPrefixAvail" \
  || { tail -30 /run/patronus/patronus-dhcpc.rtr-wan.log || true; nl_fail "no readable refusal on the Interfaces API: $(problem)"; }
nl_ok "Interfaces API: $(problem)"
nl_web GET /interfaces
grep -q 'id="problems"' "$NL_OUT" || nl_fail "the Interfaces page has no problems area"
nl_ok "the Interfaces page carries the problems area"

# 3. the ISP grants the prefix; dhcpcd's next renew picks it up
pkill -x dhcpd || true
sleep 1
dhcpd6_conf yes >"$NL_T/isp-dhcpd6.conf"
nl_bg ISP dhcpd -6 -d -cf "$NL_T/isp-dhcpd6.conf" -lf "$NL_T/isp-dhcpd6.leases" up0
nl_ok "the ISP now offers a /56"
nl_wait $((LEASE * 3)) has_lan_pd \
  || { tail -30 /run/patronus/patronus-dhcpc.rtr-wan.log || true; R ip -6 addr; nl_fail "no delegated prefix within $((LEASE * 3)) s of the ISP granting it"; }
nl_ok "dhcpcd delegated the prefix at its next renew: $(R ip -6 -o addr show dev "$NL_LAN_IF" scope global | grep -o '2001:db8:10[0-9a-f:]*/64' | head -1)"
nl_wait 30 problem_is "none" || nl_fail "the problem is still shown after the prefix arrived: $(problem)"
nl_ok "the problem is gone from the Interfaces API"
echo "PASS lane-n-dhcp6pd-refused"
