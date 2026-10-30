#!/usr/bin/env bash
# Lane M: GitOps resources beyond firewall rules, from a git repository through
# `patronus gitops sync` (what the patronus-gitops service runs):
#   Alias (host list + URL table), WireGuardTunnel (+ peers), IpsecTunnel,
#   IpsecRoadWarrior (+ users), Group and User (web accounts).
# Each lands in the config store, is applied to the kernel / strongSwan, is
# usable (traffic blocked by the alias rule, `wg show`, charon connections, a
# login with the declared account), follows a later commit (change, removal of
# a peer/user) and disappears when its file is deleted; boot rebuilds it all
# from the store alone.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DIR=/t/gitops-res
DB=$DIR/config.db
UP=$DIR/upstream
rm -rf "$DIR"; mkdir -p "$DIR"
command -v git >/dev/null || { apt-get install -y -qq git >/dev/null; }
FEEDS=$DIR/www; mkdir -p "$FEEDS"
printf '# blocked hosts\n%s\n' "$NL_BLOCKED" > "$FEEDS/list.txt"

nl_write_installer_toml
cat >>"$NL_TOML" <<EOF

[gitops]
repo_url = "$UP"
branch = "main"
local_path = "$DIR/clone"
config_path = "config"
poll_interval_secs = 5
auto_apply = true
EOF

# the init script the IPsec applier starts/stops charon with
cat > /etc/init.d/strongswan <<'EOF'
#!/bin/sh
P=/tmp/charon-rtr.pid
up() { [ -s $P ] && kill -0 "$(cat $P)" 2>/dev/null; }
case "$1" in
  start) up || { setsid /usr/sbin/charon-systemd </dev/null >/t/charon-rtr.log 2>&1 & echo $! > $P; sleep 1; } ;;
  stop) up && kill "$(cat $P)"; rm -f $P; sleep 1 ;;
  restart) $0 stop; $0 start ;;
  status) up && echo started || echo stopped ;;
esac
exit 0
EOF
chmod +x /etc/init.d/strongswan
kill_charon() { [ -s /tmp/charon-rtr.pid ] && { kill "$(cat /tmp/charon-rtr.pid)" 2>/dev/null || true; }; sleep 0.5; rm -f /tmp/charon-rtr.pid /run/charon.vici; }
boot() { kill_charon; nl_boot "$DB"; }

g() { git -C "$UP" -c user.name=QA -c user.email=qa@errant.solutions "$@"; }
sync() { R "$P" --db "$DB" gitops sync --apply --bootstrap "$NL_TOML" --state-dir "$DIR/state" >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "gitops sync failed"; }; }
sql() { sqlite3 "$DB" "$1"; }
api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }

OPS_PW='ops-user-password-1'
OPS_HASH=$(printf '%s\n' "$OPS_PW" | "$P" users hash-password)
case "$OPS_HASH" in '$argon2'*) ;; *) nl_fail "patronus users hash-password printed: $OPS_HASH";; esac
nl_ok "patronus users hash-password makes the argon2 hash for a User resource"
WGPUB=$(wg genkey | wg pubkey)

write_repo() { # PEER-LIST-EXTRA USER2
  cat >"$UP/config/resources.yaml" <<EOF
- apiVersion: patronus.firewall/v1
  kind: Alias
  metadata: { name: office }
  spec: { type: host, entries: [$NL_WWW], description: "the web server" }
- apiVersion: patronus.firewall/v1
  kind: Alias
  metadata: { name: fromurl }
  spec: { type: urltable, url: "http://$NL_WWW:8099/list.txt", refresh_secs: 3600, max_entries: 1000 }
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata: { name: block-office }
  spec:
    action: deny
    interface: "@lan"
    source: { address: "any" }
    destination: { address: "\$office", ports: [80] }
    protocol: tcp
    enabled: true
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata: { name: block-url }
  spec:
    action: deny
    interface: "@lan"
    source: { address: "any" }
    destination: { address: "\$fromurl", ports: [9000] }
    protocol: tcp
    enabled: true
- apiVersion: patronus.firewall/v1
  kind: WireGuardTunnel
  metadata: { name: wgtest }
  spec:
    listen_port: 51899
    addresses: "10.77.0.1/24"
    endpoint: "203.0.113.2"
    peers:
      - { name: laptop, allowed_ips: "10.77.0.2/32" }
$1
- apiVersion: patronus.firewall/v1
  kind: IpsecTunnel
  metadata: { name: site-b }
  spec:
    remote_address: "198.51.100.77"
    psk: "gitops-site-b-shared-secret-01"
    local_ts: "192.168.50.0/24"
    remote_ts: "10.2.0.0/24"
    start_action: none
    description: "site B"
- apiVersion: patronus.firewall/v1
  kind: IpsecRoadWarrior
  metadata: { name: phones }
  spec:
    auth: eap
    server_id: vpn.test
    pool: "10.99.70.0/24"
    dns: "192.168.50.1"
    local_ts: "192.168.50.0/24"
    users:
      - { username: alice, password: "alice-gitops-password" }
- apiVersion: patronus.firewall/v1
  kind: Group
  metadata: { name: vpn-admins }
  spec: { description: "VPN only", privileges: { vpn: write, dashboard: read } }
- apiVersion: patronus.firewall/v1
  kind: User
  metadata: { name: opsuser }
  spec: { role: operator, password_hash: "$OPS_HASH", enabled: true, groups: [vpn-admins] }
$2
EOF
}

git init -q -b main "$UP"
mkdir -p "$UP/config"
SITE_PEER="      - { name: site, public_key: \"$WGPUB\", allowed_ips: \"10.78.0.0/24\", endpoint: \"198.51.100.88:51820\", persistent_keepalive: 25 }"
write_repo "$SITE_PEER" ""
g add -A && g commit -qm "resources"

echo "=== boot, then one GitOps pass"
boot
ip netns exec nl-inet python3 -m http.server 8099 --bind $NL_WWW --directory "$FEEDS" >/t/feedsrv.log 2>&1 &
NL_PIDS+=($!)
for _ in $(seq 1 50); do INET curl -s -m 2 -o /dev/null "http://$NL_WWW:8099/" && break; sleep 0.2; done
nl_expect_tcp "baseline: LAN -> $NL_BLOCKED:9000 reachable" C $NL_BLOCKED 9000
nl_expect_http "baseline: LAN -> www:80 reachable" "http://$NL_WWW/" "sees $NL_RTR_WAN"
sync
grep -q "applied" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "sync did not report an apply"; }
nl_ok "gitops sync applied: $(grep -m1 -o 'applied ([0-9]* change(s))' "$NL_OUT")"

echo "--- aliases and the rules that name them"
[ "$(sql "SELECT entries FROM firewall_aliases WHERE name='office'")" = "[\"$NL_WWW\"]" ] || nl_fail "alias office: $(sql "SELECT * FROM firewall_aliases")"
grep -q "alias fromurl: ok: 1 entries" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "the URL table was not fetched after the sync"; }
nl_assert_nft_has "set alias_office_v4" "set alias_fromurl_v4" "ip daddr @alias_office_v4 tcp dport 80" "ip daddr @alias_fromurl_v4 tcp dport 9000"
nl_expect_http_blocked "LAN -> www:80 blocked by the rule on the host alias" "http://$NL_WWW/"
nl_expect_no_tcp "LAN -> $NL_BLOCKED:9000 blocked by the rule on the URL table" C $NL_BLOCKED 9000
nl_expect_tcp "LAN -> www:9000 (not listed) still reachable" C $NL_WWW 9000
[ "$(sql "SELECT kind FROM firewall_alias_sources WHERE alias='fromurl'")" = url ] || nl_fail "no source row for fromurl"

echo "--- WireGuard"
WG=$(R wg show wgtest 2>&1) || { echo "$WG"; nl_fail "no WireGuard interface wgtest"; }
grep -q "listening port: 51899" <<<"$WG" && grep -q "$WGPUB" <<<"$WG" || { echo "$WG"; nl_fail "wg show lacks the port or the declared peer"; }
[ "$(grep -c '^peer:' <<<"$WG")" = 2 ] || { echo "$WG"; nl_fail "expected 2 peers"; }
R ip -4 addr show dev wgtest | grep 10.77.0.1/24 >/dev/null || nl_fail "no tunnel address"
nl_assert_nft_has "udp dport 51899 accept"
LAPTOPKEY=$(sql "SELECT public_key FROM wg_peers WHERE name='laptop'")
[ -n "$LAPTOPKEY" ] && [ "$(sql "SELECT count(*) FROM wg_peers WHERE private_key IS NOT NULL")" = 1 ] || nl_fail "the road-warrior peer has no generated key pair"
nl_ok "wgtest is up (port 51899, 10.77.0.1/24) with the declared peer and a laptop peer whose key pair Patronus generated"

echo "--- IPsec"
SW=$(swanctl --list-conns 2>&1) || { echo "$SW"; tail -20 /t/charon-rtr.log; nl_fail "swanctl --list-conns"; }
grep -q "patronus-site-b" <<<"$SW" && grep -q "patronus-rw-phones" <<<"$SW" || { echo "$SW"; nl_fail "charon lacks the tunnel or the road-warrior profile"; }
grep -q 'id = alice' /etc/swanctl/conf.d/patronus.conf && grep -q 'addrs = 10.99.70.0/24' /etc/swanctl/conf.d/patronus.conf || nl_fail "road-warrior config incomplete"
[ -f /etc/swanctl/private/patronus-rw-phones.pem ] || nl_fail "no server key for the road-warrior profile"
nl_assert_nft_has "meta ipsec exists ip saddr 10.99.70.0/24 ip daddr 192.168.50.0/24" 'IPsec site-b'
nl_ok "charon has patronus-site-b and patronus-rw-phones (alice, pool 10.99.70.0/24, server certificate issued)"

echo "--- accounts"
[ "$(sql "SELECT role FROM web_users WHERE username='opsuser'")" = operator ] || nl_fail "no operator account"
[ "$(sql "SELECT g.name FROM rbac_members m JOIN web_users u ON u.id=m.user_id JOIN rbac_groups g ON g.id=m.group_id WHERE u.username='opsuser'")" = vpn-admins ] || nl_fail "opsuser is not in vpn-admins"
nl_web_start "$DB"
rm -f "$NL_T/nl-jar"
nl_api POST /auth/login "{\"username\":\"opsuser\",\"password\":\"wrong-password-1\"}"
[ "$NL_CODE" = 401 ] || nl_fail "wrong password for the declared user: $NL_CODE"
nl_api POST /auth/login "{\"username\":\"opsuser\",\"password\":\"$OPS_PW\"}"
[ "$NL_CODE" = 200 ] || nl_fail "login of the declared user: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /vpn
[ "$NL_CODE" = 200 ] || nl_fail "the group's vpn:write was not honoured: $NL_CODE"
nl_api GET /firewall/rules
[ "$NL_CODE" = 403 ] || nl_fail "the group does not grant firewall, got $NL_CODE"
nl_ok "opsuser (declared with a hash) logs in with the password; the group lets it into /vpn and not /firewall"
rm -f "$NL_T/nl-jar"

echo "=== a later commit: drop a peer, change an alias and the group, add a user, remove alice"
rm -f "$UP/config/resources.yaml"
write_repo "" "- apiVersion: patronus.firewall/v1
  kind: User
  metadata: { name: viewer }
  spec: { role: readonly, password_hash: \"$OPS_HASH\" }"
sed -i "s|entries: \[$NL_WWW\]|entries: [$NL_WWW, 192.0.2.77]|; s|vpn: write, dashboard: read|vpn: read|; s|      - { username: alice, password: \"alice-gitops-password\" }|      - { username: carol, password: \"carol-gitops-password\" }|" "$UP/config/resources.yaml"
g add -A && g commit -qm "change"
sync
WG=$(R wg show wgtest 2>&1)
[ "$(grep -c '^peer:' <<<"$WG")" = 1 ] && ! grep -q "$WGPUB" <<<"$WG" || { echo "$WG"; nl_fail "the removed peer is still in the kernel"; }
nl_ok "the peer removed from git is gone from wg show"
setdump() { R nft list set inet patronus "$1"; }
setdump alias_office_v4 | grep 192.0.2.77 >/dev/null || nl_fail "alias change not in the set"
grep -q 'id = carol' /etc/swanctl/conf.d/patronus.conf && ! grep -q 'id = alice' /etc/swanctl/conf.d/patronus.conf || nl_fail "road-warrior users not reconciled"
[ "$(sql "SELECT count(*) FROM web_users WHERE username='viewer'")" = 1 ] || nl_fail "new user not created"
grep -q '"vpn":"read"' <(sql "SELECT privileges FROM rbac_groups WHERE name='vpn-admins'") || nl_fail "group privileges not updated"
nl_ok "alias set, road-warrior users, accounts and group privileges all follow the commit"

echo "=== reboot: everything comes back from the store"
nl_web_stop
boot
R wg show wgtest >/dev/null 2>&1 || nl_fail "after reboot: no wgtest"
SW=$(swanctl --list-conns 2>&1)
grep -q "patronus-rw-phones" <<<"$SW" && grep -q "patronus-site-b" <<<"$SW" || { echo "$SW"; nl_fail "after reboot charon lacks the profiles"; }
nl_assert_nft_has "set alias_office_v4" "ip daddr @alias_office_v4 tcp dport 80"
nl_expect_http_blocked "after reboot: LAN -> www:80 still blocked" "http://$NL_WWW/"
nl_ok "after a reboot the declared resources are in the kernel / charon again, without the repository"

echo "=== deleting the files removes the resources"
rm -f "$UP/config/resources.yaml"; echo "# nothing" > "$UP/config/README.md"
g add -A && g commit -qm "remove everything"
sync
if R wg show wgtest >/dev/null 2>&1; then nl_fail "wgtest still exists"; fi
SW=$(swanctl --list-conns 2>&1 || true)
grep -q "patronus-" <<<"$SW" && { echo "$SW"; nl_fail "IPsec connections left"; }
for t in firewall_aliases firewall_alias_sources wg_interfaces wg_peers ipsec_tunnels ipsec_rw_profiles ipsec_rw_users; do
  [ "$(sql "SELECT count(*) FROM $t")" = 0 ] || nl_fail "$t still has rows: $(sql "SELECT * FROM $t" | head -3)"
done
[ "$(sql "SELECT count(*) FROM firewall_rules WHERE origin='gitops'")" = 0 ] || nl_fail "gitops rules left"
[ "$(sql "SELECT count(*) FROM web_users WHERE username IN ('opsuser','viewer')")" = 0 ] || nl_fail "declared users left"
[ "$(sql "SELECT count(*) FROM rbac_groups")" = 0 ] || nl_fail "group left"
[ "$(sql "SELECT count(*) FROM web_users WHERE username='admin'")" = 1 ] || nl_fail "the admin account was touched"
nl_assert_nft_lacks "alias_office" "udp dport 51899"
nl_expect_http "LAN -> www:80 works again" "http://$NL_WWW/" "sees $NL_RTR_WAN"
nl_ok "deleting the file removed the tunnel, interface, aliases, rules, profiles, users and group; the admin account is untouched"

echo "=== a broken resource is refused and changes nothing"
cat >"$UP/config/bad.yaml" <<EOF
- apiVersion: patronus.firewall/v1
  kind: IpsecTunnel
  metadata: { name: nokey }
  spec: { remote_address: "198.51.100.5", local_ts: "192.168.50.0/24", remote_ts: "10.9.0.0/24" }
EOF
g add -A && g commit -qm "tunnel without a key"
if R "$P" --db "$DB" gitops sync --apply --bootstrap "$NL_TOML" --state-dir "$DIR/state" >"$NL_OUT" 2>&1; then cat "$NL_OUT"; nl_fail "a tunnel without a PSK was accepted"; fi
grep -q "needs psk" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "the error does not say what is wrong"; }
[ "$(sql "SELECT count(*) FROM ipsec_tunnels")" = 0 ] || nl_fail "half-applied"
nl_ok "an IpsecTunnel without a key is refused with the reason and nothing is stored"
kill_charon
nl_down
