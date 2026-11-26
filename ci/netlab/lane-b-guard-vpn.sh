#!/usr/bin/env bash
# Lane B: brute-force protection for the VPN servers (patronus_firewall::guard sources `openvpn` and
# `strongswan`, docs/BRUTE-FORCE.md) with the real daemons and real clients over the "internet":
#
#   OpenVPN (the server Patronus runs, output in the supervisor's log file):
#   - a legitimate client connects and nothing is counted against it;
#   - tls-crypt failures (a client without the key; spoofable from a victim's address) are logged by
#     the server but NOT counted;
#   - a client with a certificate from another CA (VERIFY ERROR) is banned after the threshold:
#     the address is in the kernel set, its packets to the VPN port are dropped by the guard table,
#     so even the legitimate profile cannot connect from that address until the unban;
#   IPsec road warriors (strongSwan, IKEv2 EAP-MSCHAPv2, a second charon as the client):
#   - wrong passwords from the client's address are attributed to it through the IKE_SA's own
#     `received packet` line and ban it after the threshold; the right password does not get in while
#     banned and does after the unban; a successful login is not counted.
set -euo pipefail
set -E
trap 'echo "lane-b-guard-vpn: failed at line $LINENO" >&2' ERR
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-guard-vpn.db
rm -f "$DB" "$NL_T/nl-jar" "$NL_T"/alice.ovpn
export DEBIAN_FRONTEND=noninteractive
command -v openvpn >/dev/null && command -v openssl >/dev/null || { echo "SKIP lane-b-guard-vpn: openvpn/openssl not installed"; exit 0; }
command -v charon-systemd >/dev/null || [ -x /usr/sbin/charon-systemd ] || { echo "SKIP lane-b-guard-vpn: strongSwan not installed"; exit 0; }
[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200 2>/dev/null || true; }
pkill -x openvpn 2>/dev/null || true
export PATRONUS_GUARD_TICK_SECS=1
RWD=/t/rw
rm -rf "$RWD"; mkdir -p "$RWD/swanctl/x509ca" "$RWD/swanctl/pkcs12"
CLI_ADDR=$NL_WWW        # the OpenVPN client's address (the "internet" host)
RW_ADDR=198.18.0.2      # the road warrior's address

cleanup() {
  set +e
  pkill -x openvpn 2>/dev/null
  nl_web_stop
}
trap cleanup EXIT

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }
guard_table() { R nft list table inet patronus_guard 2>/dev/null || true; }
in_set() { # SET ELEMENT
  guard_table > /t/guard-table.txt
  python3 - "$1" "$2" /t/guard-table.txt <<'EOF'
import re, sys
text = open(sys.argv[3]).read()
m = re.search(r"set %s \{(.*?)\n\t\}" % re.escape(sys.argv[1]), text, re.S)
sys.exit(0 if m and re.search(r"(^|[\s{,])%s([\s,}]|$)" % re.escape(sys.argv[2]), m.group(1)) else 1)
EOF
}
dropped() { guard_table | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | awk '{s+=$1} END {print s+0}'; }
wait_in_set() { # SET ELEMENT DESC
  for _ in $(seq 1 40); do in_set "$1" "$2" && { nl_ok "$3"; return 0; }; sleep 0.5; done
  guard_table; tail -20 "$NL_T/nl-web.log"; nl_fail "$3: $2 not in $1"
}
not_in_set() { in_set "$1" "$2" && nl_fail "$3: $2 is in $1"; return 0; }
ban_source() { # ADDRESS: the source of the active ban
  R "$P" --db "$DB" guard status --json > /t/guard-st.json
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(",".join(b["source"] for b in d["active"] if b["address"]==sys.argv[2]))' /t/guard-st.json "$1"
}

echo "=== 1. OpenVPN"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login

# the guard first: only the OpenVPN source, three refused logins ban
api_ok PUT /guard/settings '{"enabled":true,"sources":["openvpn"],"max_failures":3,"find_secs":300,"ban_secs":600,"ban_max_secs":3600,"journal":"off","log_files":[]}'
api_ok GET /guard
[ "$(jget 'd["settings"]["openvpn_log"]')" = auto ] || nl_fail "openvpn_log default: $(cat "$NL_OUT")"
nl_api PUT /guard/settings '{"openvpn_log":"relative.log"}'
[ "$NL_CODE" = 400 ] || nl_fail "relative OpenVPN log path accepted ($NL_CODE)"
nl_api PUT /guard/settings '{"log_tags":["bad tag"]}'
[ "$NL_CODE" = 400 ] || nl_fail "bad syslog tag accepted ($NL_CODE)"
nl_ok "the VPN sources are typed settings: bad values are refused with 400"

api_ok POST /svc/openvpn/clients '{"name":"alice"}'
api_ok PUT /svc/openvpn "{\"enabled\":true,\"public_host\":\"$NL_RTR_WAN\",\"lan_route\":\"192.168.50.0/24\"}"
nl_wait 30 R pgrep -x openvpn || nl_fail "openvpn server did not start"
OVLOG=/run/patronus/patronus-daemon.openvpn-server.log
nl_wait 20 test -s "$OVLOG" || nl_fail "the supervisor's OpenVPN log $OVLOG does not exist"
api_ok GET /guard
case "$(jget 'd["status"]["inputs"]["log_files"]')" in *"patronus-daemon.openvpn-server.log"*) ;; *) nl_fail "guard does not follow the OpenVPN log: $(cat "$NL_OUT")";; esac
nl_ok "OpenVPN server running; the guard follows the supervisor's log file of the server"

C curl -sk -b "$NL_T/nl-jar" -o "$NL_T/alice.ovpn" -w '%{http_code}' "$NL_UI/api/svc/openvpn/export/alice" >"$NL_T/code"
[ "$(cat "$NL_T/code")" = 200 ] || nl_fail "export: $(cat "$NL_T/code")"

start_client() { # CONF DEV LOG
  INET ip link del "$2" 2>/dev/null || true
  nl_bg INET openvpn --config "$1" --dev "$2" --log "$3"
}
# the clients run from /t/*.ovpn; the server's own config lives in the state directory
stop_clients() { pkill -f '[o]penvpn --config /t/' 2>/dev/null || true; sleep 1; }

start_client "$NL_T/alice.ovpn" tun0 /tmp/ovpn-alice.log
nl_wait 60 sh -c 'ip netns exec nl-inet ping -c1 -W1 10.8.0.1' || { tail -30 /tmp/ovpn-alice.log; nl_fail "the legitimate client never connected"; }
nl_ok "a legitimate client connects over the WAN"
sleep 3
not_in_set ban4 $CLI_ADDR "legitimate client"
api_ok GET /guard
[ "$(jget 'len(d["failures"])')" = 0 ] || nl_fail "a successful login was counted: $(cat "$NL_OUT")"
nl_ok "a successful login counts as nothing"
stop_clients
INET ip link del tun0 2>/dev/null || true

# tls-crypt failures: a client with a wrong tls-crypt key. The server logs them, the guard must not count them
python3 - "$NL_T/alice.ovpn" "$NL_T/nocrypt.ovpn" <<'EOF'
import re, sys
t = open(sys.argv[1]).read()
key = "-----BEGIN OpenVPN Static key V1-----\n" + "\n".join(["00112233445566778899aabbccddeeff"] * 16) + "\n-----END OpenVPN Static key V1-----\n"
t = re.sub(r"<tls-crypt>.*?</tls-crypt>", lambda m: "<tls-crypt>\n" + key + "</tls-crypt>", t, flags=re.S)
open(sys.argv[2], "w").write(t)
EOF
INET timeout 16 openvpn --config "$NL_T/nocrypt.ovpn" --dev tun8 --log /tmp/ovpn-nocrypt.log >/dev/null 2>&1 || true
N=$(grep -c 'tls-crypt unwrapping failed' "$OVLOG" || true)
[ "$N" -ge 4 ] || { tail -20 "$OVLOG"; echo "--- client"; tail -20 /tmp/ovpn-nocrypt.log; nl_fail "the server logged only $N tls-crypt failures: the check proves nothing"; }
sleep 3
not_in_set ban4 $CLI_ADDR "tls-crypt failures"
nl_ok "$N tls-crypt failures in the server log (forgeable from any address): not counted, nobody banned"

# a certificate from another CA: VERIFY ERROR
mkdir -p "$NL_T/evil"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$NL_T/evil/ca.key" -out "$NL_T/evil/ca.crt" -subj /CN=evil-ca -days 2 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$NL_T/evil/c.key" -out "$NL_T/evil/c.csr" -subj /CN=alice 2>/dev/null
printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > "$NL_T/evil/ext"
openssl x509 -req -in "$NL_T/evil/c.csr" -CA "$NL_T/evil/ca.crt" -CAkey "$NL_T/evil/ca.key" -CAcreateserial -out "$NL_T/evil/c.crt" -days 2 -extfile "$NL_T/evil/ext" 2>/dev/null
python3 - "$NL_T/alice.ovpn" "$NL_T/evil.ovpn" "$NL_T/evil/c.crt" "$NL_T/evil/c.key" <<'EOF'
import re, sys
t = open(sys.argv[1]).read()
cert, key = open(sys.argv[3]).read(), open(sys.argv[4]).read()
t = re.sub(r"<cert>.*?</cert>", lambda m: "<cert>\n" + cert + "</cert>", t, flags=re.S)
t = re.sub(r"<key>.*?</key>", lambda m: "<key>\n" + key + "</key>", t, flags=re.S)
open(sys.argv[2], "w").write(t)
EOF
for i in 1 2 3 4 5 6; do
  INET timeout 8 openvpn --config "$NL_T/evil.ovpn" --dev tun9 --log /tmp/ovpn-evil.log >/dev/null 2>&1 || true
  # each connection attempt may repeat; stop at the first sign of a ban
  in_set ban4 $CLI_ADDR && break
done
grep -q 'VERIFY ERROR' "$OVLOG" || { tail -20 "$OVLOG"; nl_fail "the server never logged a VERIFY ERROR"; }
echo "server log: $(grep -c 'VERIFY ERROR' "$OVLOG") refused certificates"
nl_api GET /guard; echo "guard sees: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["failures"], d["active"], d["status"]["inputs"])' "$NL_OUT")"
wait_in_set ban4 $CLI_ADDR "refused certificates -> the client's address is in the kernel ban set"
[ "$(ban_source $CLI_ADDR)" = openvpn ] || nl_fail "the ban's source: $(ban_source $CLI_ADDR)"
nl_ok "the ban is recorded as source openvpn"
before=$(dropped)
start_client "$NL_T/alice.ovpn" tun0 /tmp/ovpn-alice2.log
sleep 14
INET ping -c1 -W2 10.8.0.1 >/dev/null 2>&1 && nl_fail "a banned address still connected to the VPN"
[ "$(dropped)" -gt "$before" ] || nl_fail "the drop counter did not grow ($before -> $(dropped))"
nl_ok "banned address: even the legitimate profile cannot connect (drop counter $before -> $(dropped))"
stop_clients
R "$P" --db "$DB" guard unban $CLI_ADDR >/dev/null
not_in_set ban4 $CLI_ADDR "after unban"
start_client "$NL_T/alice.ovpn" tun0 /tmp/ovpn-alice3.log
nl_wait 60 sh -c 'ip netns exec nl-inet ping -c1 -W1 10.8.0.1' || { tail -20 /tmp/ovpn-alice3.log; nl_fail "no VPN after the unban"; }
nl_ok "unban: the legitimate client connects again"
stop_clients
INET ip link del tun0 2>/dev/null || true

echo "=== 2. IPsec road warriors"
nl_web_stop
PLUG=$(find /usr/lib /usr/lib64 /usr/libexec \( -name 'libstrongswan-eap-mschapv2.so' \) 2>/dev/null | head -1 || true)
[ -n "$PLUG" ] || { echo "SKIP lane-b-guard-vpn: no eap-mschapv2 plugin: the IPsec half is not proven here"; echo "lane-b-guard-vpn: OpenVPN checks passed"; exit 0; }

# the router's charon logs to stderr -> /t/charon-rtr.log at the daemon's default level
mkdir -p /etc/strongswan.d
cat > /etc/strongswan.d/zz-patronus-lab-log.conf <<'EOF'
charon-systemd {
  filelog {
    stderr {
      default = 1
      ike_name = yes
      flush_line = yes
    }
  }
}
EOF
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
cat > "$RWD/strongswan.conf" <<'EOF'
include /etc/strongswan.conf
charon-systemd {
    plugins {
        vici {
            socket = unix:///run/charon-client.vici
        }
    }
}
EOF
RW() { ip netns exec nl-rw "$@"; }
RWS() {
  ip netns exec nl-rw unshare -m --propagation private sh -c \
    'mount --bind /t/rw/swanctl /etc/swanctl && exec swanctl "$@" --uri unix:///run/charon-client.vici' sh "$@"
}
add_rw_ns() {
  ip netns del nl-rw 2>/dev/null || true
  ip netns add nl-rw; ip -n nl-rw link set lo up
  ip link add rwisp netns nl-isp type veth peer name rw0 netns nl-rw
  ISP ip addr add 198.18.0.1/24 dev rwisp; ISP ip link set rwisp up
  ip -n nl-rw addr add $RW_ADDR/24 dev rw0; ip -n nl-rw link set rw0 up
  ip -n nl-rw route add default via 198.18.0.1
  ip netns exec nl-rw env STRONGSWAN_CONF=$RWD/strongswan.conf /usr/sbin/charon-systemd </dev/null >/t/charon-rw.log 2>&1 &
  NL_PIDS+=($!)
  for _ in $(seq 1 40); do RWS --stats >/dev/null 2>&1 && return 0; sleep 0.25; done
  cat /t/charon-rw.log; nl_fail "the client's charon did not start"
}
[ -s /tmp/charon-rtr.pid ] && { kill "$(cat /tmp/charon-rtr.pid)" 2>/dev/null || true; }
sleep 0.5; rm -f /tmp/charon-rtr.pid /run/charon.vici
nl_up; add_rw_ns
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_ok "boot: patronus apply (the guard keeps its settings)"
nl_web_start "$DB"; nl_login
api_ok PUT /guard/settings '{"enabled":true,"sources":["strongswan"],"max_failures":3,"find_secs":300,"ban_secs":600,"ban_max_secs":3600,"journal":"off","log_files":["/t/charon-rtr.log"]}'
api_ok POST /vpn/ipsec/roadwarrior/profiles '{"name":"eap","auth":"eap","server_id":"eap.vpn.test","pool":"10.99.50.0/24","dns":"192.168.50.1","local_ts":"192.168.50.0/24"}'
PID=$(jget 'd["id"]')
api_ok POST /vpn/ipsec/roadwarrior/profiles/$PID/users '{"username":"alice"}'
PW=$(jget 'd["generated_password"]')
api_ok GET /vpn/ipsec/roadwarrior/ca
cp "$NL_OUT" "$RWD/swanctl/x509ca/patronus-ca.pem"
for _ in $(seq 1 30); do O=$(swanctl --list-conns 2>/dev/null || true); case "$O" in *patronus-rw-eap*) break;; esac; sleep 0.5; done

SECRET() { printf 'secrets {\n  eap-alice { id = alice\n    secret = "%s" }\n}\n' "$1"; }
rw_conf() { # PASSWORD
  cat > "$RWD/swanctl/swanctl.conf" <<EOF
connections {
  rw {
    version = 2
    remote_addrs = 203.0.113.2
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha256-ecp256
    local {
      auth = eap-mschapv2
      eap_id = alice
    }
    remote {
      auth = pubkey
      id = eap.vpn.test
    }
    children {
      lan {
        remote_ts = 192.168.50.0/24
        esp_proposals = aes256gcm16-ecp256
        start_action = none
      }
    }
  }
}
$(SECRET "$1")
EOF
  RWS --load-all --noprompt >/dev/null 2>&1 || { cat "$RWD/swanctl/swanctl.conf"; nl_fail "client: cannot load its swanctl config"; }
}
rw_try() { RWS --initiate --child lan --timeout 8 >"$NL_OUT" 2>&1 || true; RWS --terminate --ike rw >/dev/null 2>&1 || true; }
established() { local o; o=$(RWS --list-sas 2>/dev/null || true); grep -q ESTABLISHED <<<"$o"; }

rw_conf "$PW"; RWS --initiate --child lan >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; tail -20 /t/charon-rtr.log; nl_fail "the road warrior with the right password could not connect"; }
established || nl_fail "no established SA with the right password"
nl_ok "the road warrior connects with the right password"
sleep 3
not_in_set ban4 $RW_ADDR "successful IPsec login"
api_ok GET /guard
[ "$(jget 'len(d["failures"])')" = 0 ] || nl_fail "a successful IKE login was counted: $(cat "$NL_OUT")"
nl_ok "a successful IKE login counts as nothing"
RWS --terminate --ike rw >/dev/null 2>&1 || true; sleep 1

rw_conf "wrong-password-1"
rw_try; sleep 2
not_in_set ban4 $RW_ADDR "after one wrong password"
rw_try; sleep 2
not_in_set ban4 $RW_ADDR "after two wrong passwords"
rw_try
grep -q 'EAP-MS-CHAPv2 verification failed' /t/charon-rtr.log || { tail -30 /t/charon-rtr.log; nl_fail "charon logged no refused EAP password"; }
wait_in_set ban4 $RW_ADDR "3 wrong passwords -> the road warrior's address is in the kernel ban set"
[ "$(ban_source $RW_ADDR)" = strongswan ] || nl_fail "the ban's source: $(ban_source $RW_ADDR)"
nl_ok "the ban is recorded as source strongswan"
rw_conf "$PW"
before=$(dropped)
RWS --initiate --child lan --timeout 8 >"$NL_OUT" 2>&1 && established && nl_fail "a banned address connected with the right password"
[ "$(dropped)" -gt "$before" ] || nl_fail "IKE packets of the banned address were not dropped ($before -> $(dropped))"
nl_ok "banned: even the right password cannot connect, IKE packets are dropped ($before -> $(dropped))"
R "$P" --db "$DB" guard unban $RW_ADDR >/dev/null
not_in_set ban4 $RW_ADDR "after unban"
RWS --terminate --ike rw >/dev/null 2>&1 || true; sleep 1
RWS --initiate --child lan >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "no connection after the unban"; }
established || nl_fail "no SA after the unban"
nl_ok "unban: the road warrior connects again"
echo "lane-b-guard-vpn: all checks passed"
