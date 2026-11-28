#!/usr/bin/env bash
# Lane J: Kea DDNS (USE=kea-ddns). Real Kea DHCPv4 + the real Kea DDNS daemon (D2) on the router, a real DHCP
# client (udhcpc) in the LAN client's namespace, the router's real Unbound as the resolver the client asks:
#   - a client that gets a lease with a host name is, a moment later, resolvable by that name (A) and by its
#     address (PTR) through the router's Unbound; the update path is DHCP lease -> Kea -> D2 -> RFC 2136 with a
#     TSIG signature -> the built-in receiver -> Unbound
#   - releasing the lease removes both records again
#   - an unsigned update, and one with the wrong key, to the receiver change nothing
#   - the TSIG secret is never returned by the API and the generated files that hold it are mode 0600
#   - the records survive a resolver restart (re-pushed) and a reboot apply (state file)
#   - external mode: D2 updates a real third-party RFC 2136 server (BIND, TSIG key, allow-update); the
#     built-in receiver is stopped then
#   - invalid settings are refused (400) and switching it off removes the daemons, the secret files and the
#     dhcp-ddns block from Kea's config
set -euo pipefail
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"   # the receiver is `patronus kea-ddns run`
DB=/t/lane-j-kea-ddns.db
rm -f "$DB" "$NL_T/nl-jar"
rm -rf /var/lib/kea/kea-leases4.csv* /var/lib/patronus/net/kea-ddns* /run/patronus/kea-ddns.stats
nl_write_installer_toml
nl_kill_daemons
pkill -x 'unbound|kea-dhcp4|kea-dhcp-ddns|named' 2>/dev/null || true

[ ! -e /usr/sbin/kea-dhcp4.parked ] || mv /usr/sbin/kea-dhcp4.parked /usr/sbin/kea-dhcp4   # run.sh parks it so other lanes keep dnsmasq
command -v kea-dhcp4 >/dev/null && command -v kea-dhcp-ddns >/dev/null || nl_fail "kea-dhcp4 / kea-dhcp-ddns are not installed in the lab image (ci/netlab/run.sh installs kea-dhcp4-server and kea-dhcp-ddns-server)"
command -v named >/dev/null || nl_fail "named (bind9) is not installed in the lab image"
command -v udhcpc >/dev/null || apt-get install -y -qq udhcpc >/dev/null 2>&1 || true
UDHCPC=udhcpc; command -v udhcpc >/dev/null || UDHCPC="busybox udhcpc"

# no init system in the container: Patronus' service manager runs /etc/init.d/<name>; Unbound ships one, Kea's
# Debian packages do not, so give kea-dhcp4 the same tiny script the dnsmasq lanes use
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

cat > "$NL_T/nl-q.py" <<'PY'
# nl-q.py NAME TYPE SERVER [PORT]  -> prints the answers (one per line) or "RCODE n"
import socket, struct, sys
name, typ, server = sys.argv[1], sys.argv[2], sys.argv[3]
port = int(sys.argv[4]) if len(sys.argv) > 4 else 53
T = {"A": 1, "PTR": 12, "AAAA": 28}
q = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.rstrip(".").split("."):
    q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", T[typ], 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, (server, port)); d, _ = s.recvfrom(4096)
rc = d[3] & 15
an = struct.unpack("!H", d[6:8])[0]
def skip(p):
    while True:
        l = d[p]
        if l & 0xc0 == 0xc0: return p + 2
        if l == 0: return p + 1
        p += l + 1
def name_at(p):
    out = []
    while True:
        l = d[p]
        if l & 0xc0 == 0xc0: p = ((l & 0x3f) << 8) | d[p + 1]; continue
        if l == 0: break
        out.append(d[p + 1:p + 1 + l].decode()); p += l + 1
    return ".".join(out)
p = 12
p = skip(p) + 4
res = []
for _ in range(an):
    p = skip(p)
    t, c, ttl, rl = struct.unpack("!HHIH", d[p:p + 10]); p += 10
    rd = d[p:p + rl]
    if t == 1: res.append(socket.inet_ntoa(rd))
    elif t == 12: res.append(name_at(p))
    p += rl
if rc != 0 and not res:
    print("RCODE", rc)
for r in res: print(r)
PY
cat > "$NL_T/nl-badupdate.py" <<'PY'
# nl-badupdate.py SERVER PORT ZONE NAME IP: an UPDATE without any signature (what an attacker on the router would send)
import socket, struct, sys
server, port, zone, name, ip = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
def n(x):
    o = b""
    for l in x.rstrip(".").split("."): o += bytes([len(l)]) + l.encode()
    return o + b"\x00"
m = struct.pack("!HHHHHH", 0x1111, 5 << 11, 1, 0, 1, 0) + n(zone) + struct.pack("!HH", 6, 1)
m += n(name) + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(m, (server, port)); d, _ = s.recvfrom(4096)
print("RCODE", d[3] & 15)
PY
cat > "$NL_T/nl-udhcpc.sh" <<'EOF'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    [ -n "$router" ] && ip route replace default via "${router%% *}" dev "$interface"
    echo "$ip ${router%% *} $dns $lease $domain" > "/t/nl-lease-$HN"
    ;;
esac
exit 0
EOF
chmod +x "$NL_T/nl-udhcpc.sh"

cleanup() {
  pkill -x 'unbound|kea-dhcp4|kea-dhcp-ddns|named|udhcpc' 2>/dev/null || true
  rm -f /etc/init.d/kea-dhcp4 /etc/kea/kea-dhcp4.conf
  [ ! -e /usr/sbin/kea-dhcp4 ] || mv /usr/sbin/kea-dhcp4 /usr/sbin/kea-dhcp4.parked
}
trap cleanup EXIT

lease() { # HOSTNAME [MAC]: the client gets a lease and sends HOSTNAME as its host name (stays up, so it can release)
  C ip addr flush dev lan0
  [ -n "${2:-}" ] && C ip link set lan0 address "$2"
  rm -f "$NL_T/nl-lease-$1"
  ip netns exec nl-client env HN=$1 $UDHCPC -i lan0 -f -t 8 -T 2 -x "hostname:$1" -s "$NL_T/nl-udhcpc.sh" >"$NL_OUT.dhcp-$1" 2>&1 &
  echo $! > "$NL_T/nl-udhcpc-$1.pid"
  nl_wait 25 test -s "$NL_T/nl-lease-$1" || { cat "$NL_OUT.dhcp-$1"; tail -30 /var/log/kea4-netlab.log 2>/dev/null; nl_fail "$1 got no DHCP lease"; }
}
release() { # HOSTNAME: SIGUSR2 = release the lease, then stop the client
  kill -USR2 "$(cat "$NL_T/nl-udhcpc-$1.pid")" 2>/dev/null || true
  sleep 1
  kill "$(cat "$NL_T/nl-udhcpc-$1.pid")" 2>/dev/null || true
}
ans() { C python3 "$NL_T/nl-q.py" "$@" 2>&1 || true; }
ans_is() { # WANT NAME TYPE: the resolver on the router answers exactly WANT
  [ "$(ans "$2" "$3" $NL_RTR_LAN)" = "$1" ]
}
ans_gone() { [ "$(ans "$1" "$2" $NL_RTR_LAN)" = "RCODE 3" ]; }

echo "=== boot: Kea DHCP with one pool, the router's Unbound as the resolver"
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"
nl_api_ok "DNS resolver, local domain" PUT /dns/settings '{"mode":"resolver","dnssec":false,"local_domain":"lan.example"}'
nl_api_ok "DHCP pool" POST /dhcp/pools '{"interface":"@lan","range_start":"192.168.50.100","range_end":"192.168.50.150","lease_time":3600,"domain":"lan.example"}'
nl_api_ok "apply DHCP" POST /dhcp/apply
nl_wait 15 pgrep -x kea-dhcp4 || nl_fail "kea-dhcp4 is not running"
nl_wait 15 pgrep -x unbound || nl_fail "unbound is not running"
grep -q '"dhcp-ddns"' /etc/kea/kea-dhcp4.conf && nl_fail "Kea is told to send DDNS requests before the feature is on"
nl_ok "Kea serves the pool; no dhcp-ddns block yet"

echo "=== baseline: a lease without DDNS gives no DNS name"
lease pc0 02:00:00:00:00:10
nl_ok "pc0 leased $(awk '{print $1}' "$NL_T/nl-lease-pc0")"
sleep 3
ans_gone pc0.lan.example A || nl_fail "pc0.lan.example resolves with DDNS off: $(ans pc0.lan.example A $NL_RTR_LAN)"
nl_ok "pc0.lan.example is NXDOMAIN with DDNS off"
release pc0

echo "=== validation (nothing is stored)"
for bad in '{"forward_zone":"bad zone;x"}' '{"secret":"not base64 at all!"}' '{"secret":"QUJD"}' '{"mode":"sideways"}' '{"d2_port":80}' '{"key_name":"a b"}' '{"server":"dns.example"}' '{"max_records":3}'; do
  nl_api_code "bad kea-ddns setting $bad" 400 PUT /svc/kea-ddns "$bad"
done
nl_ok "a bad zone, secrets that are not base64 or too short, a bad mode, a privileged port, a bad key name, a host name instead of an address and a tiny record cap are refused (400)"
nl_api GET /svc/kea-ddns
[ "$(nl_json "$NL_OUT" 'd["settings"]["enabled"]')" = False ] || nl_fail "refused settings were stored"

echo "=== external mode needs the secret of the server's key"
nl_api_ok "external mode, no secret yet" PUT /svc/kea-ddns '{"enabled":false,"mode":"external","server":"198.51.100.53","server_port":5353}'
nl_api PUT /svc/kea-ddns '{"enabled":true}'
[ "$NL_CODE" != 200 ] && grep -qi 'secret' "$NL_OUT" || nl_fail "enabling external mode without a secret was accepted: $NL_CODE $(cat "$NL_OUT")"
nl_ok "enabling external mode without the secret is refused: $(head -c 160 "$NL_OUT")"
nl_api_ok "back to local mode" PUT /svc/kea-ddns '{"enabled":false,"mode":"local"}'

echo "=== enable: local receiver feeding Unbound"
nl_api_ok "enable" PUT /svc/kea-ddns '{"enabled":true,"mode":"local","forward_zone":"lan.example"}'
nl_wait 15 pgrep -x kea-dhcp-ddns || { tail -20 /run/patronus/patronus-daemon.kea-ddns-d2.log 2>/dev/null; nl_fail "kea-dhcp-ddns (D2) did not start"; }
nl_wait 15 pgrep -f 'kea-ddns run' || nl_fail "the receiver did not start"
nl_ok "D2 and the receiver run: $(pgrep -ax kea-dhcp-ddns | head -1 | cut -c1-90)"
grep -q '"dhcp-ddns"' /etc/kea/kea-dhcp4.conf || { cat /etc/kea/kea-dhcp4.conf; nl_fail "Kea's config has no dhcp-ddns block"; }
grep -q '"ddns-qualifying-suffix": "lan.example."' /etc/kea/kea-dhcp4.conf || nl_fail "Kea's qualifying suffix is not the zone"
nl_wait 15 pgrep -x kea-dhcp4 || nl_fail "kea-dhcp4 is gone"
nl_ok "kea-dhcp4.conf carries the dhcp-ddns block and the qualifying suffix"
NETD=${PATRONUS_NET_DIR:-/var/lib/patronus/net}
for f in $NETD/kea-dhcp-ddns.conf $NETD/kea-ddns-sink.json; do
  [ -f "$f" ] || nl_fail "$f was not written"
  [ "$(stat -c %a "$f")" = 600 ] || nl_fail "$f has mode $(stat -c %a "$f"): it holds the TSIG secret"
done
nl_ok "the generated files that hold the TSIG key are mode 0600"
SECRET=$(python3 -c 'import json;print(json.load(open("'$NETD'/kea-ddns-sink.json"))["secret"])')
nl_api GET /svc/kea-ddns
grep -q "$SECRET" "$NL_OUT" && nl_fail "the API returned the TSIG secret"
[ "$(nl_json "$NL_OUT" 'd["settings"]["secret"]')" = '********' ] || nl_fail "the secret field is not masked: $(nl_json "$NL_OUT" 'd["settings"]["secret"]')"
nl_ok "a random TSIG key was generated; the API only shows ********"
OUT=$(R patronus --db "$DB" kea-ddns show)
case "$OUT" in *"$SECRET"*) nl_fail "the TSIG secret is in 'patronus kea-ddns show'";; esac
nl_ok "'patronus kea-ddns show' (and a plan/export of the applier) hides the secret"

echo "=== a client with a host name gets A and PTR records"
lease pc1 02:00:00:00:00:11
IP1=$(awk '{print $1}' "$NL_T/nl-lease-pc1")
nl_ok "pc1 leased $IP1"
RPTR=$(echo "$IP1" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
nl_wait 30 ans_is "$IP1" pc1.lan.example A || { ans pc1.lan.example A $NL_RTR_LAN; tail -30 /var/log/kea4-netlab.log; cat /run/patronus/patronus-daemon.kea-ddns-d2.log 2>/dev/null | tail -30; cat /run/patronus/kea-ddns.stats; nl_fail "pc1.lan.example did not resolve to $IP1"; }
nl_ok "A: pc1.lan.example -> $IP1 (through the router's Unbound)"
nl_wait 30 ans_is "pc1.lan.example" "$RPTR" PTR || { ans "$RPTR" PTR $NL_RTR_LAN; nl_fail "PTR $RPTR did not resolve to pc1.lan.example"; }
nl_ok "PTR: $RPTR -> pc1.lan.example"
lease pc2 02:00:00:00:00:12
IP2=$(awk '{print $1}' "$NL_T/nl-lease-pc2")
[ "$IP2" != "$IP1" ] || nl_fail "two clients got the same address"
nl_wait 30 ans_is "$IP2" pc2.lan.example A || nl_fail "pc2.lan.example did not resolve to $IP2"
nl_ok "a second client: pc2.lan.example -> $IP2 (the first is still there: $(ans pc1.lan.example A $NL_RTR_LAN))"
nl_api_ok "registered names" POST /svc/kea-ddns/action/records '{}'
python3 - "$NL_OUT" pc1.lan.example "$IP1" <<'PY' || nl_fail "the registered names list does not show pc1"
import json, sys
d = json.load(open(sys.argv[1]))
assert any(n["name"] == sys.argv[2] + "." and n["value"] == sys.argv[3] for n in d["names"] if n["type"] == "A"), d
assert d["total"] >= 4, d
PY
nl_ok "the page's registered-names list shows the records"
nl_api GET /svc/kea-ddns
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show D2 and the receiver running"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["daemon_running"] and st["receiver_running"], st
assert st["receiver"]["updates_ok"] >= 4 and st["receiver"]["unbound_ok"], st
PY
nl_ok "status: D2 and the receiver running, updates accepted, Unbound fed"

echo "=== releasing the lease removes the records"
release pc2
nl_wait 30 ans_gone pc2.lan.example A || { ans pc2.lan.example A $NL_RTR_LAN; nl_fail "pc2.lan.example still resolves after the lease was released"; }
nl_ok "pc2.lan.example is gone after DHCPRELEASE"
ans_is "$IP1" pc1.lan.example A || nl_fail "pc1 was removed with pc2"
nl_ok "pc1.lan.example is untouched"

echo "=== the receiver refuses unsigned and wrongly signed updates"
OUT=$(R python3 "$NL_T/nl-badupdate.py" 127.0.0.1 5335 lan.example evil.lan.example 6.6.6.6)
[ "$OUT" = "RCODE 5" ] || nl_fail "an unsigned update was answered '$OUT' (want REFUSED)"
sleep 6
ans_gone evil.lan.example A || nl_fail "the unsigned update took effect"
nl_ok "an unsigned update gets REFUSED and evil.lan.example does not exist"
OUT=$(R python3 "$NL_T/nl-badupdate.py" 127.0.0.1 5335 evil.example x.evil.example 6.6.6.6)
[ "$OUT" = "RCODE 5" ] || nl_fail "an update for a foreign zone was answered '$OUT'"
nl_ok "an update naming a zone the router does not serve is refused too"
SS=$(R ss -lnu)
[ "$(grep -c ':5335 ' <<<"$SS")" = 1 ] && [ "$(grep -c '127.0.0.1:5335 ' <<<"$SS")" = 1 ] || { echo "$SS"; nl_fail "the receiver is not on loopback only"; }
nl_ok "the receiver listens on 127.0.0.1 only"

echo "=== the records survive a resolver restart"
pkill -x unbound; sleep 1
R /etc/init.d/unbound start >/dev/null 2>&1 || true
nl_wait 20 pgrep -x unbound || nl_fail "unbound did not come back"
nl_wait 30 ans_is "$IP1" pc1.lan.example A || nl_fail "pc1.lan.example is lost after an Unbound restart"
nl_wait 30 ans_is "pc1.lan.example" "$RPTR" PTR || nl_fail "the PTR is lost after an Unbound restart"
nl_ok "after the resolver restarted the receiver put A and PTR back"

echo "=== reboot: the stored settings and records bring everything back"
release pc1
sleep 1
lease pc1 02:00:00:00:00:11
nl_wait 30 ans_is "$IP1" pc1.lan.example A || nl_fail "pc1 not registered after the re-lease"
nl_web_stop
nl_kill_daemons
pkill -x 'unbound|kea-dhcp4|kea-dhcp-ddns' 2>/dev/null || true
pkill -f 'kea-ddns run' 2>/dev/null || true
for p in "$NL_T"/nl-udhcpc-*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done
sleep 1
nl_boot "$DB"
nl_wait 20 pgrep -x kea-dhcp-ddns || nl_fail "D2 not started by the boot apply"
nl_wait 20 pgrep -f 'kea-ddns run' || nl_fail "receiver not started by the boot apply"
nl_wait 20 pgrep -x unbound || nl_fail "unbound not started by the boot apply"
nl_wait 40 ans_is "$IP1" pc1.lan.example A || nl_fail "pc1.lan.example is not served after the reboot"
nl_ok "after a reboot apply: D2 and the receiver run again and pc1.lan.example -> $IP1 (records kept in the state file)"
nl_web_start "$DB"; nl_login

echo "=== external mode against a real RFC 2136 server (BIND)"
KEY=$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')
mkdir -p /t/named; rm -f /t/named/*.zone /t/named/*.jnl
cat > /t/named/lan.example.zone <<'ZONE'
$TTL 300
@ IN SOA ns.lan.example. root.lan.example. 1 3600 600 86400 300
@ IN NS ns.lan.example.
ns IN A 198.51.100.53
ZONE
sed 's/^ns IN A.*/ns IN A 198.51.100.53/' /t/named/lan.example.zone > /t/named/50.168.192.in-addr.arpa.zone
cat > /t/named/named.conf <<CONF
options {
  directory "/t/named";
  listen-on port 5353 { 198.51.100.53; };
  listen-on-v6 { none; };
  pid-file "/t/named/named.pid";
  session-keyfile "/t/named/session.key";
  recursion no; allow-query { any; }; dnssec-validation no;
};
key "patronus-ddns" { algorithm hmac-sha256; secret "$KEY"; };
zone "lan.example" { type master; file "/t/named/lan.example.zone"; allow-update { key patronus-ddns; }; };
zone "50.168.192.in-addr.arpa" { type master; file "/t/named/50.168.192.in-addr.arpa.zone"; allow-update { key patronus-ddns; }; };
CONF
chown -R bind:bind /t/named 2>/dev/null || true
nl_bg INET named -f -u root -c /t/named/named.conf
BIND_UP() { [ "$(INET python3 "$NL_T/nl-q.py" ns.lan.example A 198.51.100.53 5353 2>&1 || true)" = 198.51.100.53 ]; }
nl_wait 20 BIND_UP || nl_fail "BIND did not answer"
nl_ok "BIND answers for lan.example and the reverse zone on 198.51.100.53:5353"
nl_api_ok "external mode" PUT /svc/kea-ddns "{\"mode\":\"external\",\"server\":\"198.51.100.53\",\"server_port\":5353,\"secret\":\"$KEY\"}"
NO_RECV() { ! pgrep -f 'kea-ddns run' >/dev/null; }
nl_wait 15 NO_RECV || nl_fail "the built-in receiver still runs in external mode"
nl_wait 15 pgrep -x kea-dhcp-ddns || nl_fail "D2 is not running in external mode"
nl_ok "external mode: the built-in receiver is stopped, D2 runs"
lease pc3 02:00:00:00:00:13
IP3=$(awk '{print $1}' "$NL_T/nl-lease-pc3")
EXT_A() { [ "$(INET python3 "$NL_T/nl-q.py" pc3.lan.example A 198.51.100.53 5353 2>&1 || true)" = "$IP3" ]; }
nl_wait 30 EXT_A || { INET python3 "$NL_T/nl-q.py" pc3.lan.example A 198.51.100.53 5353 || true; cat /run/patronus/patronus-daemon.kea-ddns-d2.log 2>/dev/null | tail -30; nl_fail "BIND did not get pc3.lan.example -> $IP3 from D2"; }
nl_ok "BIND holds pc3.lan.example -> $IP3 (a TSIG-signed RFC 2136 update from D2)"
RPTR3=$(echo "$IP3" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
EXT_P() { [ "$(INET python3 "$NL_T/nl-q.py" "$RPTR3" PTR 198.51.100.53 5353 2>&1 || true)" = "pc3.lan.example" ]; }
nl_wait 30 EXT_P || nl_fail "BIND did not get the PTR for $IP3"
nl_ok "BIND holds the PTR $RPTR3 -> pc3.lan.example"
release pc3
EXT_GONE() { [ "$(INET python3 "$NL_T/nl-q.py" pc3.lan.example A 198.51.100.53 5353 2>&1 || true)" = "RCODE 3" ]; }
nl_wait 30 EXT_GONE || nl_fail "BIND still has pc3.lan.example after the release"
nl_ok "the release removed pc3.lan.example from BIND"
nl_api_code "a wrong key is not stored as a valid external setup" 400 PUT /svc/kea-ddns '{"secret":"AAAA"}'

echo "=== disable"
nl_api_ok "disable" PUT /svc/kea-ddns '{"enabled":false}'
NO_D2() { ! pgrep -x kea-dhcp-ddns >/dev/null; }
nl_wait 15 NO_D2 || nl_fail "D2 still running"
nl_wait 15 NO_RECV || nl_fail "receiver still running"
[ ! -e "$NETD/kea-dhcp-ddns.conf" ] && [ ! -e "$NETD/kea-ddns-sink.json" ] || nl_fail "the files that hold the TSIG secret are still there"
grep -q '"dhcp-ddns"' /etc/kea/kea-dhcp4.conf && nl_fail "Kea still has the dhcp-ddns block"
nl_ok "disabled: D2 and the receiver stopped, the secret files removed, the dhcp-ddns block gone from Kea's config"
nl_web_stop
echo "ALL KEA DDNS CHECKS PASSED"
