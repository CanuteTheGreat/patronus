#!/usr/bin/env bash
# Lane J: IP tunnels (USE=tunnels): IPIP, 6in4 (sit) and GIF-style (sit mode any) links made by the
# tunnels page. The far end of every tunnel is the lab's "internet" namespace, configured with plain
# `ip` (not Patronus), so the proof is two independent implementations talking to each other:
#   - validation: bad names, wrong inner address family for the type, bad endpoints, a second address
#     on a non-gif tunnel, a default route without an address, two tunnels the kernel could not tell apart
#   - IPIP: link tn-site (type ipip, endpoints, TTL, MTU, alias, address) in the kernel; the router and the
#     far end ping each other (far end first = the firewall accepts protocol 4 from the remote only);
#     a LAN client reaches a network behind the far end through the tunnel (route row, no NAT) over real TCP
#   - MSS clamp: the SYN that leaves into the tunnel carries MSS 1440 (MTU 1480 - 40); off = untouched
#   - 6in4: link tn-he (sit, ip6ip), IPv6 ping both ways, the default IPv6 route over the tunnel reaches an
#     "internet" address; IPIP and 6in4 on the very same endpoints coexist
#   - GIF-style: one link carries IPv4 and IPv6 (two addresses)
#   - a stranger sending protocol 4 gets no answer and no hole is opened for it in the ruleset
#   - changes: MTU edit keeps the link (same ifindex), a TTL edit re-creates it, disabling removes link,
#     route and firewall rules; foreign links are left alone, a stray tn-* link is removed
#   - the page and the live status; a reboot apply brings everything back
set -euo pipefail
set -E
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"
DB=/t/lane-j-tunnels.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons

FAR_SIT=$NL_WWW        # 198.51.100.10: far end of the ipip + sit tunnels
FAR_GIF=$NL_BLOCKED    # 198.51.100.20: far end of the gif tunnel
STRANGER=198.51.100.30

trap 'rc=$?; [ $rc = 0 ] || { set +e; echo "--- diag: links"; R ip -d link show 2>&1 | grep -A3 "tn-\|foo0"; echo "--- diag: addrs/routes"; R ip addr show 2>&1 | grep -B1 -A3 "tn-"; R ip -4 route; R ip -6 route; echo "--- diag: tunnels table"; R nft list table inet patronus_tunnel 2>&1; echo "--- diag: input rules"; R nft list ruleset 2>&1 | grep -i "tunnel\|l4proto"; echo "--- diag: far end"; INET ip -d link show 2>&1 | grep -A2 "far-"; tail -15 "$NL_T/nl-web.log"; }' EXIT

far_up() {
  # the far ends, plain iproute2 (a different implementation from the one under test)
  INET ip link add far-ipip type ipip remote "$NL_RTR_WAN" local $FAR_SIT ttl 64
  INET ip addr add 10.99.0.2/30 dev far-ipip; INET ip link set far-ipip up
  INET ip addr add 10.77.0.1/24 dev lo               # a network behind the far end
  INET ip route add 192.168.50.0/24 via 10.99.0.1    # the way back to the LAN (no NAT on the router)
  INET ip link add far-sit type sit mode ip6ip remote "$NL_RTR_WAN" local $FAR_SIT ttl 64
  INET ip addr add 2001:db8:6::2/64 dev far-sit; INET ip link set far-sit up
  INET ip -6 addr add 2001:db8:ffff::53/128 dev lo   # an address on the "IPv6 internet"
  INET ip link add far-gif type sit mode any remote "$NL_RTR_WAN" local $FAR_GIF ttl 64
  INET ip addr add 10.97.0.2/30 dev far-gif
  INET ip addr add 2001:db8:97::2/64 dev far-gif; INET ip link set far-gif up
  INET ip addr add $STRANGER/24 dev inet0
  INET ip link add far-bad type ipip remote "$NL_RTR_WAN" local $STRANGER ttl 64
  INET ip addr add 10.98.0.2/30 dev far-bad; INET ip link set far-bad up
}

ifidx() { R cat "/sys/class/net/$1/ifindex"; }
lk() { R ip -d link show "$1"; }
has_link() { R ip link show "$1" >/dev/null 2>&1; }
rm_has() { local out; out=$(R nft list ruleset); grep -F -- "$1" <<<"$out" >/dev/null; }
tid() { nl_api GET /svc/tunnels; nl_json "$NL_OUT" "[r['id'] for r in d['collections']['tunnels'] if r['name']=='$1'][0]"; }
syn_mss() { # DEV: the MSS of the SYN the client's connection sends into DEV
  local cap=/tmp/syn.txt
  rm -f $cap
  ip netns exec nl-rtr timeout 6 tcpdump -nn -v -l -i "$1" -c 1 'tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn' >$cap 2>&1 &
  local tp=$!
  sleep 1
  C curl -s -m 5 -o /dev/null http://10.77.0.1/ || true
  wait $tp 2>/dev/null || true
  grep -o 'mss [0-9]*' $cap | head -1 | cut -d' ' -f2
}

nl_up; far_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login

echo "=== nothing before configuration"
[ -z "$(R ip -br link show | grep '^tn-' || true)" ] || nl_fail "tn-* links exist on a fresh router"
nl_ok "no tn-* link on a fresh router"
R nft list table inet patronus_tunnel >/dev/null 2>&1 && nl_fail "tunnel table present with no tunnel"
nl_ok "no tunnel nft table either"

echo "=== validation (400, nothing stored)"
nl_api_code "uppercase name" 400 POST /svc/tunnels/tunnels '{"name":"Bad","kind":"ipip","remote":"198.51.100.10"}'
nl_api_code "name too long" 400 POST /svc/tunnels/tunnels '{"name":"abcdefghijkl","kind":"ipip","remote":"198.51.100.10"}'
nl_api_code "name with a space" 400 POST /svc/tunnels/tunnels '{"name":"a b","kind":"ipip","remote":"198.51.100.10"}'
nl_api_code "unknown type" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"gre","remote":"198.51.100.10"}'
nl_api_code "remote 0.0.0.0" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"0.0.0.0"}'
nl_api_code "remote loopback" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"127.0.0.1"}'
nl_api_code "remote multicast" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"224.0.0.1"}'
nl_api_code "IPv6 remote" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"sit","remote":"2001:db8::1"}'
nl_api_code "remote = local" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"198.51.100.10","local":"198.51.100.10"}'
nl_api_code "IPv6 address on an IPIP tunnel" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"198.51.100.10","address":"2001:db8::2/64"}'
nl_api_code "IPv4 address on a 6in4 tunnel" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"sit","remote":"198.51.100.10","address":"10.1.1.1/30"}'
nl_api_code "link-local inner address" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"sit","remote":"198.51.100.10","address":"fe80::1/64"}'
nl_api_code "second address on a non-gif tunnel" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"198.51.100.10","address":"10.1.1.1/30","address2":"2001:db8::1/64"}'
nl_api_code "default route without an address" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"sit","remote":"198.51.100.10","default_route":true}'
nl_api_code "MTU below 576" 400 POST /svc/tunnels/tunnels '{"name":"x","kind":"ipip","remote":"198.51.100.10","mtu":500}'
nl_api_code "route to an unknown tunnel" 400 POST /svc/tunnels/routes '{"tunnel":"ghost","destination":"10.5.0.0/16"}'
nl_api GET /svc/tunnels
[ "$(nl_json "$NL_OUT" "len(d['collections']['tunnels']) + len(d['collections']['routes'])")" = 0 ] || nl_fail "a refused change was stored"
nl_ok "16 refused changes, nothing stored, no link made"
[ -z "$(R ip -br link show | grep '^tn-' || true)" ] || nl_fail "a refused change made a link"

echo "=== IPIP tunnel: the link, both directions, a network behind the far end"
nl_api_ok "add the IPIP tunnel" POST /svc/tunnels/tunnels "{\"name\":\"site\",\"kind\":\"ipip\",\"remote\":\"$FAR_SIT\",\"local\":\"$NL_RTR_WAN\",\"address\":\"10.99.0.1/30\",\"mtu\":1480,\"ttl\":64,\"description\":\"site to site\"}"
has_link tn-site || nl_fail "the tunnel link tn-site was not created"
lk tn-site | grep -E "ipip.*remote $FAR_SIT local $NL_RTR_WAN" >/dev/null || { lk tn-site; nl_fail "tn-site has the wrong endpoints"; }
lk tn-site | grep -E "ttl 64" >/dev/null || { lk tn-site; nl_fail "tn-site has the wrong TTL"; }
lk tn-site | grep -E "mtu 1480" >/dev/null || nl_fail "tn-site has the wrong MTU"
[ "$(R cat /sys/class/net/tn-site/ifalias)" = patronus-tunnel ] || nl_fail "tn-site carries no owner alias"
R ip -4 addr show dev tn-site | grep "inet 10.99.0.1/30" >/dev/null || nl_fail "tn-site has no inner address"
R ip link show tn-site | grep -E "<[^>]*UP" >/dev/null || nl_fail "tn-site is not up"
nl_ok "tn-site: type ipip, $FAR_SIT <- $NL_RTR_WAN, ttl 64, mtu 1480, address 10.99.0.1/30, up, owned by Patronus"
nl_assert_nft_has "ip saddr $FAR_SIT ip daddr $NL_RTR_WAN meta l4proto 4 accept" 'iifname "tn-site" meta l4proto { icmp, ipv6-icmp } accept'
# the far end pings first: a NEW inbound protocol-4 flow needs the firewall's rule
INET ping -c2 -W2 10.99.0.1 >/dev/null || { R nft list ruleset | grep -i "l4proto"; nl_fail "the far end cannot ping the router through the tunnel"; }
nl_ok "far end -> router: ping through the IPIP tunnel (inbound protocol 4 accepted from the remote)"
R ping -c2 -W2 10.99.0.2 >/dev/null || nl_fail "the router cannot ping the far end"
nl_ok "router -> far end: ping through the tunnel"
nl_api_ok "route to the network behind the far end" POST /svc/tunnels/routes '{"tunnel":"site","destination":"10.77.0.0/24","description":"behind site"}'
R ip -4 route show 10.77.0.0/24 | grep -E "dev tn-site proto 248" >/dev/null || { R ip -4 route; nl_fail "the route over the tunnel is missing or not marked as ours"; }
C ping -c2 -W2 10.77.0.1 >/dev/null || nl_fail "the LAN client cannot reach the network behind the far end"
nl_ok "LAN client -> 10.77.0.1 through the router and the tunnel"
body=$(C curl -s -m 8 http://10.77.0.1/) || nl_fail "TCP through the tunnel failed"
grep -F "$NL_CLIENT" <<<"$body" >/dev/null || nl_fail "the far end saw another source than the client: $body"
nl_ok "real TCP through the tunnel, the far end sees the client's own address (no NAT): $body"

echo "=== MSS clamp"
nl_assert_nft_has "table inet patronus_tunnel" "tcp option maxseg size set rt mtu"
mss=$(syn_mss tn-site)
[ "$mss" = 1440 ] || nl_fail "the SYN into the tunnel carries MSS '$mss' (want 1440 = MTU 1480 - 40)"
nl_ok "SYN into the tunnel carries MSS 1440 (client asked for 1460)"
nl_api_ok "clamp off" PUT /svc/tunnels '{"clamp_mss":false}'
R nft list table inet patronus_tunnel >/dev/null 2>&1 && nl_fail "the MSS table is still there with clamping off"
mss=$(syn_mss tn-site)
[ "$mss" = 1460 ] || nl_fail "with clamping off the SYN carries MSS '$mss' (want the client's 1460)"
nl_ok "clamp off: table gone, the client's MSS 1460 passes untouched"
nl_api_ok "clamp on" PUT /svc/tunnels '{"clamp_mss":true}'
[ "$(syn_mss tn-site)" = 1440 ] || nl_fail "clamp did not come back"
nl_ok "clamp on again"

echo "=== 6in4 (sit) next to IPIP on the same endpoints"
nl_api_ok "add the 6in4 tunnel (default IPv6 route)" POST /svc/tunnels/tunnels "{\"name\":\"he\",\"kind\":\"sit\",\"remote\":\"$FAR_SIT\",\"local\":\"$NL_RTR_WAN\",\"address\":\"2001:db8:6::1/64\",\"default_route\":true,\"metric\":512}"
lk tn-he | grep -E "sit (ip6ip )?remote $FAR_SIT local $NL_RTR_WAN" >/dev/null || { lk tn-he; nl_fail "tn-he has the wrong type or endpoints"; }
R ip -6 addr show dev tn-he | grep "inet6 2001:db8:6::1/64" >/dev/null || nl_fail "tn-he has no inner IPv6 address"
nl_assert_nft_has "ip saddr $FAR_SIT ip daddr $NL_RTR_WAN meta l4proto 41 accept"
INET ping -6 -c2 -W2 2001:db8:6::1 >/dev/null || nl_fail "the far end cannot ping the router over 6in4"
nl_ok "far end -> router over 6in4 (protocol 41 accepted from the remote)"
R ping -6 -c2 -W2 2001:db8:6::2 >/dev/null || nl_fail "the router cannot ping the far end over 6in4"
R ip -6 route show default | grep -E "dev tn-he .*proto 248.*metric 512|dev tn-he proto 248 metric 512" >/dev/null || { R ip -6 route show; nl_fail "no default IPv6 route over the tunnel"; }
R ping -6 -c2 -W2 2001:db8:ffff::53 >/dev/null || nl_fail "the IPv6 'internet' address is not reachable over the default route"
nl_ok "router -> 6in4 far end, and the default IPv6 route over the tunnel reaches 2001:db8:ffff::53"
R ping -c1 -W2 10.99.0.2 >/dev/null || nl_fail "the IPIP tunnel broke when the 6in4 tunnel came up"
nl_ok "IPIP on the same endpoints keeps working next to 6in4"
nl_api_code "two tunnels with the same endpoints and type" 400 POST /svc/tunnels/tunnels "{\"name\":\"dup\",\"kind\":\"ipip\",\"remote\":\"$FAR_SIT\",\"local\":\"$NL_RTR_WAN\"}"
has_link tn-dup && nl_fail "the refused duplicate was created"
nl_ok "an overlapping duplicate is refused with 400, no link"

echo "=== GIF-style: IPv4 and IPv6 on one link"
nl_api_ok "add the GIF tunnel" POST /svc/tunnels/tunnels "{\"name\":\"gif1\",\"kind\":\"gif\",\"remote\":\"$FAR_GIF\",\"address\":\"10.97.0.1/30\",\"address2\":\"2001:db8:97::1/64\"}"
lk tn-gif1 | grep -E "sit any remote $FAR_GIF" >/dev/null || { lk tn-gif1; nl_fail "tn-gif1 is not a generic (mode any) tunnel to the far end"; }
nl_assert_nft_has "ip saddr $FAR_GIF meta l4proto { 4, 41 } accept"
R ping -c2 -W2 10.97.0.2 >/dev/null || nl_fail "IPv4 over the GIF link failed"
R ping -6 -c2 -W2 2001:db8:97::2 >/dev/null || nl_fail "IPv6 over the GIF link failed"
INET ping -c2 -W2 10.97.0.1 >/dev/null || nl_fail "far end -> router IPv4 over GIF failed"
INET ping -6 -c2 -W2 2001:db8:97::1 >/dev/null || nl_fail "far end -> router IPv6 over GIF failed"
nl_ok "one GIF link, both families, both directions (no local endpoint pinned: any local address)"

echo "=== a stranger gets nothing"
if INET ping -c2 -W2 10.98.0.1 >/dev/null 2>&1; then nl_fail "an unknown remote reached the router through an IPIP tunnel"; fi
rm_has "ip saddr $STRANGER" && nl_fail "a rule names the stranger's address"
nl_ok "protocol 4 from $STRANGER (no tunnel for it): no answer, no rule"

echo "=== status and page"
nl_api GET /svc/tunnels
python3 - "$NL_OUT" <<'PY' || nl_fail "live status does not describe the tunnels"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["configured"] == 3 and st["present"] == 3, st
by = {t["name"]: t for t in st["tunnels"]}
for n in ("site", "he", "gif1"):
    assert by[n]["present"] and by[n]["up"] and by[n]["in_sync"], by[n]
assert by["site"]["link"] == "tn-site" and by["site"]["type"] == "ipip", by["site"]
assert by["site"]["rx_bytes"] > 0 and by["site"]["tx_bytes"] > 0, by["site"]
assert "10.99.0.1/30" in by["site"]["addresses"], by["site"]
assert len(by["gif1"]["addresses"]) == 2, by["gif1"]
PY
nl_ok "status: three tunnels present, up, in sync with the stored configuration, counters moving"
nl_web GET /svc/tunnels
[ "$NL_CODE" = 200 ] && grep -F 'svc-settings-form' "$NL_OUT" >/dev/null || nl_fail "tunnels page: $NL_CODE"
nl_web GET /api/features
grep -F '"tunnels"' "$NL_OUT" >/dev/null || nl_fail "/api/features does not list tunnels"
nl_ok "the page and the feature list answer"

echo "=== changes: MTU keeps the link, TTL re-creates it, foreign links are left alone"
R ip link add foo0 type ipip remote 192.0.2.9 local "$NL_RTR_WAN"
R ip link add tn-stray type ipip remote 192.0.2.10
SITE=$(tid site)
before=$(ifidx tn-site)
nl_api_ok "MTU edit" PUT /svc/tunnels/tunnels/$SITE '{"mtu":1400}'
lk tn-site | grep -E "mtu 1400" >/dev/null || nl_fail "MTU not applied"
[ "$(ifidx tn-site)" = "$before" ] || nl_fail "an MTU edit re-created the link"
R ping -c1 -W2 10.99.0.2 >/dev/null || nl_fail "tunnel down after the MTU edit"
nl_ok "MTU 1400 applied in place (same link, same ifindex)"
has_link foo0 || nl_fail "a link Patronus does not own was removed"
has_link tn-stray && nl_fail "a stray tn-* link was left behind"
nl_ok "a foreign ipip link is untouched, a stray tn-* link is removed"
nl_api_ok "TTL edit" PUT /svc/tunnels/tunnels/$SITE '{"ttl":32}'
lk tn-site | grep -E "ttl 32" >/dev/null || nl_fail "TTL not applied"
[ "$(ifidx tn-site)" != "$before" ] || nl_fail "a TTL edit did not re-create the link"
R ip -4 addr show dev tn-site | grep "inet 10.99.0.1/30" >/dev/null || nl_fail "re-created link lost its address"
R ip -4 route show 10.77.0.0/24 | grep "dev tn-site" >/dev/null || nl_fail "re-created link lost its route"
nl_api_ok "TTL back" PUT /svc/tunnels/tunnels/$SITE '{"ttl":64,"mtu":1480}'
R ping -c2 -W2 10.99.0.2 >/dev/null || nl_fail "tunnel down after the re-creation"
nl_ok "TTL edit re-creates the link and puts back its address and route; traffic flows again"
# applying twice changes nothing
a=$(ifidx tn-site); h=$(ifidx tn-he)
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "second apply"; }
[ "$(ifidx tn-site)" = "$a" ] && [ "$(ifidx tn-he)" = "$h" ] || nl_fail "a repeated apply re-created links"
nl_ok "a repeated apply is a no-op (same links)"

echo "=== disable removes link, route and rules"
HE=$(tid he)
nl_api_ok "disable 6in4" PUT /svc/tunnels/tunnels/$HE '{"enabled":false}'
has_link tn-he && nl_fail "tn-he still exists although disabled"
R ip -6 route show default | grep tn-he >/dev/null && nl_fail "the default IPv6 route over the disabled tunnel is still there"
rm_has "meta l4proto 41 accept" && nl_fail "protocol 41 is still accepted"
R ping -c1 -W2 10.99.0.2 >/dev/null || nl_fail "disabling one tunnel broke another"
nl_ok "disabled: link, default route and protocol-41 rule gone; the IPIP tunnel is unaffected"
nl_api_ok "enable 6in4 again" PUT /svc/tunnels/tunnels/$HE '{"enabled":true}'
R ping -6 -c2 -W2 2001:db8:ffff::53 >/dev/null || nl_fail "6in4 did not come back"
nl_ok "enabled again: the tunnel and its default route are back"

echo "=== reboot: patronus apply brings everything back"
nl_web_stop
nl_kill_daemons
nl_up; far_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
for l in tn-site tn-he tn-gif1; do has_link $l || nl_fail "$l not created by the boot apply"; done
INET ping -c2 -W2 10.99.0.1 >/dev/null || nl_fail "IPIP does not work after the reboot"
INET ping -6 -c2 -W2 2001:db8:6::1 >/dev/null || nl_fail "6in4 does not work after the reboot"
R ping -6 -c2 -W2 2001:db8:ffff::53 >/dev/null || nl_fail "default IPv6 route over the tunnel missing after the reboot"
R ping -c2 -W2 10.97.0.2 >/dev/null || nl_fail "GIF does not work after the reboot"
nl_web_start "$DB"; nl_login
C ping -c2 -W2 10.77.0.1 >/dev/null || nl_fail "the route behind the far end is missing after the reboot"
[ "$(syn_mss tn-site)" = 1440 ] || nl_fail "MSS clamp missing after the reboot"
nl_ok "after a reboot: three tunnels, addresses, routes, firewall rules and the MSS clamp are back from the store alone"

echo "=== delete everything"
for n in site he gif1; do nl_api_ok "delete $n" DELETE /svc/tunnels/tunnels/$(tid $n); done
nl_api GET /svc/tunnels
for r in $(nl_json "$NL_OUT" "' '.join(str(x['id']) for x in d['collections']['routes'])"); do nl_api_ok "delete route $r" DELETE /svc/tunnels/routes/$r; done
[ -z "$(R ip -br link show | grep '^tn-' || true)" ] || nl_fail "tn-* links left after deleting every tunnel"
has_link foo0 || nl_fail "the foreign link went too"
R nft list table inet patronus_tunnel >/dev/null 2>&1 && nl_fail "tunnel table left"
rm_has "tunnel site" && nl_fail "tunnel rules left"
R ip -4 route show proto 248 | grep . >/dev/null && nl_fail "routes of ours left"
nl_ok "everything removed; the foreign link stays"
nl_web_stop
R ip link del foo0 2>/dev/null || true
echo "ALL TUNNEL CHECKS PASSED"
