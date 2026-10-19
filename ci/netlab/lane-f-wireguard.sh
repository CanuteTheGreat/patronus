#!/usr/bin/env bash
# Lane F: WireGuard from the web UI API, proven in the kernel and with real
# traffic. A road-warrior client on the internet side (nl-inet) uses the
# client config Patronus generated (download from the API), reaches the
# router's tunnel address and a LAN host through the tunnel -- and nothing
# on the LAN without the tunnel. Then a reboot (fresh namespaces + `patronus
# apply`) brings the same tunnel (same keys) back, and deleting it in the UI
# removes the link and closes the port.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-f-wg.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== tunnel + peer through the API"
nl_api POST /vpn/wireguard/tunnels '{"addresses":"10.99.0.1/24","endpoint":"203.0.113.2","client_allowed_ips":"10.99.0.0/24, 192.168.50.0/24","description":"road warriors"}'
[ "$NL_CODE" = 201 ] || nl_fail "add tunnel: $NL_CODE $(cat "$NL_OUT")"
SERVER_PUB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_key"])' "$NL_OUT")
nl_api POST /vpn/wireguard/peers '{"name":"laptop","interface":"wg0","preshared_key":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add peer: $NL_CODE $(cat "$NL_OUT")"
PEER_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
grep -q '"allowed_ips":"10.99.0.2/32"' "$NL_OUT" || nl_fail "peer did not get the next free address: $(cat "$NL_OUT")"
# a site-to-site style peer: its networks get a route through the tunnel
SITE_PUB=$(wg genkey | wg pubkey)
nl_api POST /vpn/wireguard/peers "{\"name\":\"site-c\",\"interface\":\"wg0\",\"public_key\":\"$SITE_PUB\",\"allowed_ips\":\"10.99.0.20/32, 10.77.0.0/24\"}"
[ "$NL_CODE" = 201 ] || nl_fail "add site peer: $NL_CODE $(cat "$NL_OUT")"
# what peers may reach is up to the firewall: tunnel -> LAN, tunnel -> router ping
nl_api POST /firewall/rules '{"name":"wg-to-lan","chain":"forward","action":"accept","interface":"wg0","protocol":"any","source":"10.99.0.0/24","destination":"192.168.50.0/24","port":"","description":"wg-to-lan","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add wg-to-lan rule: $NL_CODE $(cat "$NL_OUT")"

echo "=== kernel state"
has() { grep -qF -- "$2" <<<"$1" || nl_fail "$3: got $1"; }
has "$(R ip -d link show wg0)" wireguard "wg0 is not a wireguard link"
has "$(R ip -br addr show wg0)" 10.99.0.1/24 "wg0 lacks 10.99.0.1/24"
[ "$(R wg show wg0 public-key)" = "$SERVER_PUB" ] || nl_fail "wg0 key differs from the API's"
[ "$(R wg show wg0 listen-port)" = 51820 ] || nl_fail "wg0 not on 51820"
has "$(R wg show wg0 allowed-ips)" "10.99.0.2/32" "laptop peer not in the kernel"
PSKS=$(R wg show wg0 preshared-keys)
grep -qv '(none)' <<<"$PSKS" || nl_fail "PSK not set: $PSKS"
has "$(R ip route show proto 249)" "10.77.0.0/24 dev wg0" "no route to the site peer's network"
nl_assert_nft_has 'udp dport 51820 accept comment "WireGuard wg0"' 'iifname "wg0" ip saddr 10.99.0.0/24 ip daddr 192.168.50.0/24 accept'
nl_ok "wg0 up with key/port/peers/PSK from the store, route 10.77.0.0/24 (proto 249), port open"

echo "=== client config download -> a real client on the internet side"
client_up() {
  nl_api GET "/vpn/wireguard/config/$PEER_ID"
  [ "$NL_CODE" = 200 ] || nl_fail "client config: $NL_CODE $(cat "$NL_OUT")"
  cp "$NL_OUT" /t/laptop.conf
  grep -q "Endpoint = 203.0.113.2:51820" /t/laptop.conf || nl_fail "config endpoint: $(cat /t/laptop.conf)"
  grep -q "PublicKey = $SERVER_PUB" /t/laptop.conf || nl_fail "config server key"
  # wg-quick keys (Address/DNS) are applied by hand: wg setconf takes the rest
  grep -vE '^(Address|DNS) =' /t/laptop.conf > /t/laptop.setconf
  INET ip link add wgc type wireguard
  INET wg setconf wgc /t/laptop.setconf
  INET ip addr add 10.99.0.2/32 dev wgc
  INET ip link set wgc up
  INET ip route add 10.99.0.0/24 dev wgc
  INET ip route add 192.168.50.0/24 dev wgc
}
client_up
INET ping -c1 -W3 10.99.0.1 >/dev/null || { R wg show; nl_fail "client cannot ping the router through the tunnel"; }
nl_ok "client pings 10.99.0.1 through the tunnel"
nl_expect_tcp "client -> LAN host through the tunnel (source = tunnel address, not NATed)" INET $NL_CLIENT 9000
grep -q 10.99.0.2 "$NL_OUT" || nl_fail "LAN host saw $(cat "$NL_OUT"), want 10.99.0.2"
HS=$(R wg show wg0 latest-handshakes)
awk '$2 > 0 {f=1} END {exit !f}' <<<"$HS" || nl_fail "no handshake recorded: $HS"
nl_api GET /vpn/wireguard/peers
grep -q '"status":"Connected"' "$NL_OUT" || nl_fail "live peers do not show Connected: $(cat "$NL_OUT")"
nl_web GET /vpn
grep -q 'data-peer="laptop"' "$NL_OUT" || nl_fail "VPN page lacks the peer"
grep -q '<span class="ok">Connected' "$NL_OUT" || nl_fail "VPN page does not show the peer connected"
nl_ok "API and VPN page show laptop Connected"
INET ip link del wgc
nl_expect_no_tcp "internet host without the tunnel -> LAN host" INET $NL_CLIENT 9000

echo "=== reboot: the same tunnel comes back from the store"
nl_web_stop
nl_boot "$DB"
[ "$(R wg show wg0 public-key)" = "$SERVER_PUB" ] || nl_fail "after reboot wg0 has another key"
has "$(R ip route show proto 249)" "10.77.0.0/24 dev wg0" "site route not back after reboot"
nl_web_start "$DB"; nl_login
client_up
INET ping -c1 -W3 10.99.0.1 >/dev/null || nl_fail "after reboot: no ping through the tunnel"
nl_expect_tcp "after reboot: client -> LAN host through the tunnel" INET $NL_CLIENT 9000
nl_apply "$DB" --phase interfaces || { cat "$NL_OUT"; nl_fail "re-apply"; }
INET ping -c1 -W3 10.99.0.1 >/dev/null || nl_fail "re-apply broke the tunnel"
nl_ok "re-apply is idempotent (tunnel stays up)"

echo "=== a foreign WireGuard link is never touched; deleting the tunnel removes ours"
R ip link add wgforeign type wireguard
nl_api DELETE /vpn/wireguard/tunnels/wg0
[ "$NL_CODE" = 200 ] || nl_fail "delete tunnel: $NL_CODE $(cat "$NL_OUT")"
if R ip link show wg0 >/dev/null 2>&1; then nl_fail "wg0 still exists after delete"; fi
R ip link show wgforeign >/dev/null 2>&1 || nl_fail "the foreign link was removed"
nl_assert_nft_lacks 'udp dport 51820'
nl_api GET /vpn
grep -q '"tunnels":\[\]' "$NL_OUT" || nl_fail "store still has tunnels: $(cat "$NL_OUT")"
nl_web_stop
nl_ok "tunnel deleted: link gone, port closed, foreign link kept"
nl_down
