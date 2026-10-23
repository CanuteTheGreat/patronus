#!/usr/bin/env bash
# Lane N: OpenVPN server + client profile export in the shipped binary. A
# client is added in the UI/API, its .ovpn profile (certificate, key and
# tls-crypt key inline) is downloaded, and a real OpenVPN client on the
# "internet" host connects to the router's WAN address, gets a tunnel address
# and reaches the server and the LAN; disabling the client ends and blocks it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-openvpn.db
rm -f "$DB" "$NL_T/nl-jar" "$NL_T"/alice.ovpn
export DEBIAN_FRONTEND=noninteractive
command -v openvpn >/dev/null || apt-get install -y -qq openvpn >/dev/null
command -v openvpn >/dev/null && command -v openssl >/dev/null || nl_fail "openvpn/openssl not installed"
[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200 2>/dev/null || true; }
pkill -x openvpn 2>/dev/null || true

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api POST /svc/openvpn/clients '{"name":"alice"}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "add client: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /svc/openvpn/export/alice; true
C curl -sk -b "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' "$NL_UI/api/svc/openvpn/export/alice" >"$NL_T/code"
[ "$(cat "$NL_T/code")" = 400 ] || nl_fail "export without a public host should be 400, got $(cat "$NL_T/code"): $(cat "$NL_OUT")"

nl_api PUT /svc/openvpn "{\"enabled\":true,\"public_host\":\"$NL_RTR_WAN\",\"lan_route\":\"192.168.50.0/24\"}"
[ "$NL_CODE" = 200 ] || nl_fail "enable: $NL_CODE $(cat "$NL_OUT")"
nl_wait 30 R pgrep -x openvpn || nl_fail "openvpn server did not start"
nl_assert_nft_has "OpenVPN server"
nl_ok "server running, port opened on the WAN side"

C curl -sk -b "$NL_T/nl-jar" -o "$NL_T/alice.ovpn" -w '%{http_code}' "$NL_UI/api/svc/openvpn/export/alice" >"$NL_T/code"
[ "$(cat "$NL_T/code")" = 200 ] || nl_fail "export: $(cat "$NL_T/code")"
for tag in '<ca>' '<cert>' '<key>' '<tls-crypt>' "remote $NL_RTR_WAN 1194"; do grep -qF "$tag" "$NL_T/alice.ovpn" || nl_fail "profile lacks $tag"; done
nl_ok "alice.ovpn exported with certificate, key and tls-crypt inline"
[ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM openvpn_pki WHERE name LIKE 'client:alice:%'")" = 2 ] || nl_fail "client keys are not in the store"

start_client() {
  INET ip link del tun0 2>/dev/null || true
  nl_bg INET openvpn --config "$NL_T/alice.ovpn" --dev tun0 --log /tmp/ovpn-alice.log
}
start_client
nl_wait 60 sh -c 'ip netns exec nl-inet ping -c1 -W1 10.8.0.1' || { tail -30 /tmp/ovpn-alice.log; R sh -c 'ip a; pgrep -a openvpn'; nl_fail "the OpenVPN client never reached the server tunnel address"; }
nl_ok "client connected over the WAN and pings the server at 10.8.0.1"
INET ping -c2 -W2 $NL_CLIENT >/dev/null || nl_fail "the VPN client cannot reach the LAN host"
nl_ok "VPN client reaches the LAN host $NL_CLIENT through the tunnel"

echo "=== disabling the client ends and blocks it"
ID=$(sqlite3 "$DB" "SELECT id FROM openvpn_clients WHERE name='alice'")
nl_api PUT /svc/openvpn/clients/$ID '{"enabled":false}'
[ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE $(cat "$NL_OUT")"
sleep 3
nl_wait 30 sh -c '! ip netns exec nl-inet ping -c1 -W1 10.8.0.1' || nl_fail "a disabled client still reaches the server"
sleep 12
INET ping -c1 -W2 10.8.0.1 >/dev/null 2>&1 && nl_fail "a disabled client got back in"
nl_ok "disabled client: session ended, reconnects refused"
echo "PASS lane-n-openvpn"
