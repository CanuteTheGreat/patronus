#!/usr/bin/env bash
# Customer journey: the web UI shows the box's REAL state, never fixtures.
# The admin brings up a WireGuard tunnel to a LAN client by hand (wg), adds
# a route, creates a configuration backup in the web UI; the VPN page/API,
# the dashboard counter, the routing table and the backup list must show
# exactly that -- and nothing that is not on the box (the old fixtures:
# three "Active" peers with made-up keys, an IPsec tunnel to 203.0.113.100,
# a default route via 192.168.1.254, 2024 backups, "0 MB" backups, services
# up for "15d 8h").
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DIR=/t/honest
DB=$DIR/config.db
rm -rf "$DIR"; mkdir -p "$DIR"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"
nl_login

json() { python3 -c "import json,sys; d=json.load(open('$NL_OUT')); $1"; }
no_fixtures() {
  for f in RZv3iVQPxjKqBVLPEMJJX site-to-site-hq 203.0.113.100 192.168.1.254 patronus-backup-2024 \
           '"0 MB"' '15d 8h' '2024-01-1' vpn.example.com 'Intel Core i7'; do
    if grep -qF -- "$f" "$NL_OUT"; then nl_fail "$1 shows fixture text '$f'"; fi
  done
}

echo "=== a fresh box: no tunnels, no backups"
nl_api GET /status
[ "$NL_CODE" = 200 ] || nl_fail "status $NL_CODE"
json 'assert d["vpn_connections"] == 0, d'
nl_ok "status: vpn_connections = 0 on a box without tunnels"
nl_api GET /system/backups
[ "$NL_CODE" = 200 ] && json 'assert d == [], d' || nl_fail "backups on a fresh box: $NL_CODE $(cat "$NL_OUT")"
nl_ok "backups: empty list on a fresh box"
for p in / /vpn /system /monitoring /network; do
  nl_web GET "$p"; [ "$NL_CODE" = 200 ] || nl_fail "page $p: $NL_CODE"; no_fixtures "page $p"
done
nl_ok "dashboard, VPN, system, monitoring and network pages render without fixture rows"

echo "=== WireGuard tunnel router <-> LAN client, configured with wg"
command -v wg >/dev/null || nl_fail "wireguard-tools missing in the netlab image"
umask 077
wg genkey > "$DIR/r.key"; wg pubkey < "$DIR/r.key" > "$DIR/r.pub"
wg genkey > "$DIR/c.key"; wg pubkey < "$DIR/c.key" > "$DIR/c.pub"
RPUB=$(cat "$DIR/r.pub"); CPUB=$(cat "$DIR/c.pub")
R ip link add wg0 type wireguard || nl_fail "no WireGuard kernel support on the CI host"
R wg set wg0 listen-port 51820 private-key "$DIR/r.key" \
    peer "$CPUB" allowed-ips 10.99.0.2/32 endpoint $NL_CLIENT:51821
R ip addr add 10.99.0.1/24 dev wg0; R ip link set wg0 up
C ip link add wg1 type wireguard
C wg set wg1 listen-port 51821 private-key "$DIR/c.key" peer "$RPUB" allowed-ips 10.99.0.1/32
C ip addr add 10.99.0.2/24 dev wg1; C ip link set wg1 up

nl_api GET /vpn/wireguard/peers
[ "$NL_CODE" = 200 ] || nl_fail "wg peers: $NL_CODE $(cat "$NL_OUT")"
json "assert len(d) == 1, d; p = d[0]; assert p['public_key'] == '$CPUB', p; assert p['interface'] == 'wg0'; assert p['allowed_ips'] == '10.99.0.2/32', p; assert not p['connected'] and p['last_handshake'] is None, p"
nl_ok "API lists exactly the kernel's one peer ($CPUB), no handshake yet"
nl_api GET /status
json 'assert d["vpn_connections"] == 0, d'
nl_ok "status: a peer without a handshake is not a connection"

R ping -c 3 -W 2 10.99.0.2 >/dev/null 2>&1 || true   # triggers the handshake
for _ in $(seq 1 20); do
  hs=$(R wg show wg0 latest-handshakes | awk '{print $2}')
  [ "${hs:-0}" -gt 0 ] && break; sleep 0.5
done
[ "${hs:-0}" -gt 0 ] || nl_fail "the tunnel never completed a handshake"
nl_ok "kernel: wg0 handshake at $hs"
nl_api GET /vpn/wireguard/peers
json "p = d[0]; assert p['connected'] and p['status'] == 'Connected' and p['last_handshake'], p; assert p['endpoint'] == '$NL_CLIENT:51821', p"
nl_ok "API: the peer is Connected, endpoint $NL_CLIENT:51821, handshake $(json 'print(d[0]["last_handshake"])')"
nl_api GET /status
json 'assert d["vpn_connections"] == 1, d'
nl_ok "status: vpn_connections = 1 (the real tunnel)"
nl_web GET /vpn
grep -qF "$CPUB" "$NL_OUT" || nl_fail "VPN page does not show the peer"
no_fixtures "VPN page"
nl_ok "VPN page shows the live peer and nothing else"
nl_api POST /vpn/wireguard/peers '{"name":"x","public_key":"'"$RPUB"'","allowed_ips":"10.99.0.9/32","endpoint":null,"persistent_keepalive":null,"enabled":true}'
# wg0 was made by hand (not by Patronus): a peer can only go on a tunnel
# Patronus manages, and the hand-made one is never touched (lane F)
[ "$NL_CODE" = 400 ] || nl_fail "add peer without a Patronus tunnel should be 400, got $NL_CODE"
[ "$(R wg show wg0 peers | wc -l)" = 1 ] || nl_fail "the refused add changed the kernel"
nl_ok "adding a peer without a Patronus-managed tunnel is refused (400), the hand-made wg0 is unchanged"

echo "=== routing table"
R ip route add 10.77.0.0/24 via $NL_CLIENT
nl_api GET /network/routes
[ "$NL_CODE" = 200 ] || nl_fail "routes: $NL_CODE $(cat "$NL_OUT")"
no_fixtures "routes API"
KERNEL4=$(R ip -json -4 route show table main | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
json "v4 = [r for r in d if ':' not in r['destination']]; assert len(v4) == $KERNEL4, (len(v4), d); \
dflt = [r for r in v4 if r['destination'].startswith('0.0.0.0/0')]; assert dflt and dflt[0]['gateway'] == '203.0.113.1' and dflt[0]['interface'] == '$NL_WAN_IF', dflt; \
r = [r for r in v4 if r['destination'] == '10.77.0.0/24']; assert r and r[0]['gateway'] == '$NL_CLIENT', d; \
assert any(r['destination'] == '10.99.0.0/24' and r['interface'] == 'wg0' for r in v4), d"
nl_ok "routes API = the kernel's $KERNEL4 IPv4 routes (default via 203.0.113.1, 10.77.0.0/24, wg0 subnet)"

echo "=== configuration backup from the web UI"
nl_api POST /system/backups
[ "$NL_CODE" = 201 ] || nl_fail "create backup: $NL_CODE $(cat "$NL_OUT")"
NAME=$(json 'print(d["name"])'); SIZE=$(json 'print(d["size_bytes"])')
[ -f "$DIR/backups/$NAME" ] || nl_fail "no backup file $DIR/backups/$NAME"
[ "$(stat -c %s "$DIR/backups/$NAME")" = "$SIZE" ] || nl_fail "size $SIZE != file size"
[ "$SIZE" -gt 1000 ] || nl_fail "backup suspiciously small ($SIZE bytes)"
nl_ok "backup $NAME written: $SIZE bytes on disk = size reported"
R "$P" --db "$DIR/restore.db" config import "$DIR/backups/$NAME" --no-apply >"$NL_OUT" 2>&1 \
  || { cat "$NL_OUT"; nl_fail "the backup does not import"; }
[ "$(sqlite3 "$DIR/restore.db" 'SELECT count(*) FROM firewall_rules')" = "$(sqlite3 "$DB" 'SELECT count(*) FROM firewall_rules')" ] \
  || nl_fail "the imported backup has a different rule count"
nl_ok "the backup is a real export: \`patronus config import\` restores the same firewall rules"
nl_api GET /system/backups
json "assert len(d) == 1 and d[0]['name'] == '$NAME' and d[0]['size_bytes'] == $SIZE, d"
nl_web GET /system
grep -qF "$NAME" "$NL_OUT" || nl_fail "System page does not list the backup"
no_fixtures "System page"
nl_ok "System page lists the real backup file"
nl_web GET "/api/system/backups/$NAME"
cmp -s "$NL_OUT" "$DIR/backups/$NAME" || nl_fail "download differs from the file"
nl_ok "download returns the file byte for byte"
nl_api DELETE "/system/backups/$NAME"
[ "$NL_CODE" = 200 ] && [ ! -e "$DIR/backups/$NAME" ] || nl_fail "delete backup: $NL_CODE"
nl_ok "delete removes the file"

echo "=== services and updates"
nl_api GET /system/services
[ "$NL_CODE" = 200 ] || nl_fail "services: $NL_CODE"
no_fixtures "services API"
nl_ok "services API: $(json 'print(len(d))') installed Patronus-related services, live state"
nl_api GET /system/updates
[ "$NL_CODE" = 200 ] || nl_fail "updates should answer 200, got $NL_CODE"
grep -q '"pending":\[\]' "$NL_OUT" || nl_fail "an unchecked box must have nothing pending: $(cat "$NL_OUT")"
nl_ok "updates: nothing pending before a check, no invented update"

nl_web_stop
R ip link del wg0; C ip link del wg1
nl_down
