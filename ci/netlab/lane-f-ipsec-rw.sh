#!/usr/bin/env bash
# Lane F: IPsec road warriors (IKEv2 remote access), proven with a real
# strongSwan client in its own namespace connecting over the "internet":
#
#   rw client 198.18.0.2 --- isp --- router WAN 203.0.113.2 --- LAN 192.168.50.0/24
#
# - an EAP-MSCHAPv2 profile: the client authenticates with a password,
#   gets a virtual IP from the pool and reaches a LAN host through the
#   tunnel (the LAN host sees the pool address, no NAT); a wrong password
#   and a disabled user are refused;
# - a client-certificate profile: Patronus issues the user's certificate
#   (exported as PKCS#12), the client connects with it; deleting the user
#   removes the pinned certificate and the next connection is refused;
# - the setup files (iOS/macOS .mobileconfig, Android .sswan, Windows
#   PowerShell) are well-formed and carry what the platforms need;
# - everything comes back after a reboot and goes away when deleted.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-f-rw.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
RWD=/t/rw
rm -rf "$RWD"; mkdir -p "$RWD/swanctl/x509ca" "$RWD/swanctl/pkcs12"

api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

# the init script the IPsec applier starts/stops charon with (SysV path)
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
# swanctl for the client's charon, with the client's own /etc/swanctl
RWS() {
  ip netns exec nl-rw unshare -m --propagation private sh -c \
    'mount --bind /t/rw/swanctl /etc/swanctl && exec swanctl "$@" --uri unix:///run/charon-client.vici' sh "$@"
}
add_rw_ns() {
  ip netns del nl-rw 2>/dev/null || true
  ip netns add nl-rw; ip -n nl-rw link set lo up
  ip link add rwisp netns nl-isp type veth peer name rw0 netns nl-rw
  ISP ip addr add 198.18.0.1/24 dev rwisp; ISP ip link set rwisp up
  ip -n nl-rw addr add 198.18.0.2/24 dev rw0; ip -n nl-rw link set rw0 up
  ip -n nl-rw route add default via 198.18.0.1
  ip netns exec nl-rw env STRONGSWAN_CONF=$RWD/strongswan.conf /usr/sbin/charon-systemd </dev/null >/t/charon-rw.log 2>&1 &
  NL_PIDS+=($!)
  for _ in $(seq 1 40); do RWS --stats >/dev/null 2>&1 && return 0; sleep 0.25; done
  cat /t/charon-rw.log; nl_fail "the client's charon did not start"
}
boot() {
  # the router's charon goes with the reboot (nl_down kills the client's: it is in NL_PIDS)
  [ -s /tmp/charon-rtr.pid ] && { kill "$(cat /tmp/charon-rtr.pid)" 2>/dev/null || true; }
  sleep 0.5; rm -f /tmp/charon-rtr.pid /run/charon.vici
  nl_up; add_rw_ns
  nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
  nl_ok "boot: patronus apply"
}
rw_conf() { # NAME REMOTE_ID AUTH-BLOCK CHILD-TS
  cat > "$RWD/swanctl/swanctl.conf" <<EOF
connections {
  $1 {
    version = 2
    remote_addrs = 203.0.113.2
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha256-ecp256
    local {
$3
    }
    remote {
      auth = pubkey
      id = $2
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
$4
EOF
}
rw_up() { # CONN: load the config, connect; prints the swanctl output on failure
  RWS --load-all --noprompt >/dev/null 2>&1 || { cat "$RWD/swanctl/swanctl.conf"; nl_fail "client: cannot load its swanctl config"; }
  RWS --initiate --child lan >"$NL_OUT" 2>&1
}
established() { local o; o=$(RWS --list-sas 2>/dev/null || true); grep -q ESTABLISHED <<<"$o"; }
has_conn() { local o; o=$(swanctl --list-conns 2>/dev/null || true); grep -q "$1" <<<"$o"; }
rw_down() { RWS --terminate --ike "$1" >/dev/null 2>&1 || true; sleep 0.5; }

# Ubuntu 24.04 (the act image) ships strongSwan without eap-mschapv2/md4: the
# EAP *connection* steps need it (Debian/Gentoo have it); everything else
# (config, firewall, exports, certificate profile) is proven either way.
MSCHAP=0
ls /usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so /usr/lib/*/ipsec/plugins/libstrongswan-eap-mschapv2.so >/dev/null 2>&1 && MSCHAP=1
[ "$MSCHAP" = 1 ] || echo "NOTE: no eap-mschapv2 plugin in this strongSwan: live EAP connection steps are skipped"

boot
nl_web_start "$DB"; nl_login
api_ok GET /vpn/ipsec/roadwarrior
[ "$(jget 'len(d["profiles"])')" = 0 ] || nl_fail "fresh box has road-warrior profiles"
nl_web GET /vpn
grep -q 'id="rw-card"' "$NL_OUT" || nl_fail "the VPN page has no road-warrior card"
nl_ok "the VPN page has the road-warrior card (no profiles yet)"

echo "=== validation"
for body in \
  '{"name":"x y","server_id":"eap.vpn.test","pool":"10.99.50.0/24"}' \
  '{"name":"x","auth":"psk","server_id":"eap.vpn.test","pool":"10.99.50.0/24"}' \
  '{"name":"x","server_id":"bad host!","pool":"10.99.50.0/24"}' \
  '{"name":"x","server_id":"eap.vpn.test","pool":"10.99.50.0/31"}' \
  '{"name":"x","server_id":"eap.vpn.test","pool":"10.99.50.0/24","dns":"not-an-address"}' \
  '{"name":"x","server_id":"eap.vpn.test"}'; do
  nl_api POST /vpn/ipsec/roadwarrior/profiles "$body"
  [ "$NL_CODE" = 400 ] || nl_fail "accepted $body: $NL_CODE $(cat "$NL_OUT")"
done
nl_ok "bad names, auth types, server names, pools and DNS servers are refused (400)"

echo "=== 1. EAP-MSCHAPv2 profile"
api_ok POST /vpn/ipsec/roadwarrior/profiles '{"name":"eap","auth":"eap","server_id":"eap.vpn.test","pool":"10.99.50.0/24","dns":"192.168.50.1","local_ts":"192.168.50.0/24"}'
PID=$(jget 'd["id"]')
api_ok POST /vpn/ipsec/roadwarrior/profiles/$PID/users '{"username":"alice"}'
PW=$(jget 'd["generated_password"]')
[ "${#PW}" = 20 ] || nl_fail "no generated password: $(cat "$NL_OUT")"
nl_ok "user alice added; a 20-character password was generated and shown once"
UID_A=$(jget 'd["id"]')
CONF=$(cat /etc/swanctl/conf.d/patronus.conf)
for want in 'patronus-rw-eap {' 'pools = patronus-rw-eap' 'auth = eap-mschapv2' 'id = eap.vpn.test' 'addrs = 10.99.50.0/24' 'dns = 192.168.50.1' 'id = alice' 'local_ts = 192.168.50.0/24'; do
  grep -qF -- "$want" <<<"$CONF" || { echo "$CONF"; nl_fail "swanctl config lacks: $want"; }
done
[ "$(stat -c %a /etc/swanctl/conf.d/patronus.conf)" = 600 ] || nl_fail "swanctl conf mode"
[ "$(stat -c %a /etc/swanctl/private/patronus-rw-eap.pem)" = 600 ] || nl_fail "server key mode $(stat -c %a /etc/swanctl/private/patronus-rw-eap.pem)"
nl_ok "swanctl config + server certificate/key written (key 0600)"
nl_assert_nft_has 'udp dport { 500, 4500 } accept' 'meta ipsec exists ip saddr 10.99.50.0/24 ip daddr 192.168.50.0/24 accept' 'ip daddr 10.99.50.0/24 accept comment "IPsec road warriors eap: no NAT"'
has_conn patronus-rw-eap || nl_fail "charon has no patronus-rw-eap connection"
nl_ok "charon loaded the connection; firewall: IKE/ESP, pool -> LAN forwarding, no NAT for answers"
nl_api GET /vpn/ipsec/roadwarrior/ca
head -1 "$NL_OUT" | grep 'BEGIN CERTIFICATE' >/dev/null || nl_fail "CA download: $(head -c 100 "$NL_OUT")"
cp "$NL_OUT" "$RWD/swanctl/x509ca/patronus-ca.pem"
openssl verify -CAfile "$RWD/swanctl/x509ca/patronus-ca.pem" /etc/swanctl/x509/patronus-rw-eap.pem >/dev/null || nl_fail "server certificate does not verify against the CA"
nl_ok "the CA downloads and the server certificate verifies against it"

SECRET() { printf 'secrets {\n  eap-alice { id = alice\n    secret = "%s" }\n}\n' "$1"; }
if [ "$MSCHAP" = 1 ]; then
rw_conf rw eap.vpn.test "      auth = eap-mschapv2
      eap_id = alice" "$(SECRET "wrong-password-1")"
rw_up || true
if established; then nl_fail "connected with a wrong password"; fi
nl_ok "a wrong password is refused"
rw_conf rw eap.vpn.test "      auth = eap-mschapv2
      eap_id = alice" "$(SECRET "$PW")"
rw_up || { cat "$NL_OUT"; tail -20 /t/charon-rtr.log; nl_fail "the road warrior could not connect"; }
SAS=$(RWS --list-sas)
grep -q ESTABLISHED <<<"$SAS" || { echo "$SAS"; nl_fail "no established SA"; }
VIP=$(grep -oE '10\.99\.50\.[0-9]+' <<<"$SAS" | head -1)
[ -n "$VIP" ] || { echo "$SAS"; nl_fail "no virtual IP from the pool"; }
nl_ok "alice connected with her password and got $VIP from the pool"
OUT=$(RW python3 "$NL_T/nl-conn.py" $NL_CLIENT 9000) || { RW ip route show table all | head -20; nl_fail "client -> LAN host through the tunnel: $OUT"; }
[ "$OUT" = "$VIP" ] || nl_fail "the LAN host saw $OUT, want the pool address $VIP"
nl_ok "the road warrior reaches the LAN host through the tunnel; the host sees $VIP (no NAT)"
RW ping -c1 -W3 $NL_CLIENT >/dev/null || nl_fail "ping through the tunnel"
nl_ok "ping through the tunnel works"
# `swanctl --list-pools`: name, base, "online / offline / size"
POOLS=$(swanctl --list-pools 2>/dev/null || true); grep patronus-rw-eap <<<"$POOLS" | grep -E ' 1 / 0 / ' >/dev/null || { swanctl --list-pools; nl_fail "router shows no online lease"; }
nl_ok "the router's pool shows the lease: $(swanctl --list-pools 2>/dev/null | grep patronus-rw-eap | tr -s ' ')"
RW python3 "$NL_T/nl-conn.py" $NL_WWW 80 >/dev/null 2>&1 && nl_fail "a profile limited to the LAN let the client reach the internet host" || true
nl_ok "traffic outside the profile's networks does not go through the tunnel"
fi

echo "--- a disabled user is refused"
rw_down rw
api_ok PUT /vpn/ipsec/roadwarrior/users/$UID_A '{"enabled":false}'
! grep -q 'id = alice' /etc/swanctl/conf.d/patronus.conf || nl_fail "a disabled user's secret is still loaded"
if [ "$MSCHAP" = 1 ]; then
  rw_up || true
  if established; then nl_fail "a disabled user connected"; fi
  nl_ok "a disabled user cannot connect"
fi
api_ok PUT /vpn/ipsec/roadwarrior/users/$UID_A '{"enabled":true}'
grep -q 'id = alice' /etc/swanctl/conf.d/patronus.conf || nl_fail "a re-enabled user's secret is not loaded again"
if [ "$MSCHAP" = 1 ]; then
  rw_up || { cat "$NL_OUT"; nl_fail "re-enabled user cannot connect"; }
  nl_ok "re-enabling the user lets her connect again"
fi
rw_down rw

echo "=== 2. setup files for the phones and Windows"
nl_api GET /vpn/ipsec/roadwarrior/export/$UID_A/mobileconfig
[ "$NL_CODE" = 200 ] || nl_fail "mobileconfig: $NL_CODE $(cat "$NL_OUT")"
python3 - "$NL_OUT" <<'PY' || nl_fail ".mobileconfig is not a valid property list with the VPN + CA payloads"
import plistlib, sys
d = plistlib.load(open(sys.argv[1], "rb"))
pl = {p["PayloadType"]: p for p in d["PayloadContent"]}
v = pl["com.apple.vpn.managed"]
assert v["VPNType"] == "IKEv2", v
i = v["IKEv2"]
assert i["RemoteAddress"] == "eap.vpn.test" and i["AuthName"] == "alice" and i["ExtendedAuthEnabled"] == 1, i
assert i["IKESecurityAssociationParameters"]["DiffieHellmanGroup"] == 19
assert pl["com.apple.security.root"]["PayloadContent"].startswith(b"0"), "CA is not DER"
assert "com.apple.security.pkcs12" not in pl
PY
nl_ok ".mobileconfig for alice parses as a plist: IKEv2, server eap.vpn.test, EAP user alice, the CA as a root payload"
nl_api GET /vpn/ipsec/roadwarrior/export/$UID_A/sswan
python3 - "$NL_OUT" <<'PY' || nl_fail ".sswan is wrong"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["type"] == "ikev2-eap" and d["local"]["eap_id"] == "alice" and d["remote"]["addr"] == "eap.vpn.test", d
assert d["split-tunneling"]["subnets"] == "192.168.50.0/24", d
assert len(d["remote"]["cert"]) > 100
PY
nl_ok "Android .sswan profile: ikev2-eap, user alice, the CA certificate, split tunnelling to the LAN"
nl_api GET /vpn/ipsec/roadwarrior/export/$UID_A/ps1
for want in "Add-VpnConnection -Name 'eap' -ServerAddress 'eap.vpn.test' -TunnelType Ikev2" 'MSChapv2' 'Import-Certificate' 'Set-VpnConnectionIPsecConfiguration' "Add-VpnConnectionRoute -ConnectionName 'eap' -DestinationPrefix '192.168.50.0/24'"; do
  grep -qF -- "$want" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "PowerShell script lacks: $want"; }
done
grep -q "$PW" "$NL_OUT" && nl_fail "the PowerShell script contains the password"
nl_ok "Windows PowerShell script: trusts the CA, Add-VpnConnection IKEv2/MSChapv2, IPsec parameters, LAN route; no password inside"
nl_api GET /vpn/ipsec/roadwarrior/export/$UID_A/p12
[ "$NL_CODE" = 400 ] || nl_fail "a p12 for an EAP user: $NL_CODE"
nl_api GET /vpn/ipsec/roadwarrior/export/$UID_A/bogus
[ "$NL_CODE" = 400 ] || nl_fail "unknown format: $NL_CODE"
nl_ok "an unknown format and a .p12 for a password user are refused (400)"

echo "=== 3. client-certificate profile"
api_ok POST /vpn/ipsec/roadwarrior/profiles '{"name":"cert","auth":"cert","server_id":"cert.vpn.test","pool":"10.99.60.0/24","local_ts":"192.168.50.0/24"}'
CPID=$(jget 'd["id"]')
nl_api POST /vpn/ipsec/roadwarrior/profiles/$CPID/users '{"username":"bob","password":"not-allowed-here"}'
[ "$NL_CODE" = 400 ] || nl_fail "a password for a certificate user was accepted"
api_ok POST /vpn/ipsec/roadwarrior/profiles/$CPID/users '{"username":"bob"}'
UID_B=$(jget 'd["id"]')
[ -f /etc/swanctl/x509/patronus-rw-cert-bob.pem ] || { ls /etc/swanctl/x509; nl_fail "bob's certificate is not pinned"; }
grep -qF 'certs = patronus-rw-cert-bob.pem' /etc/swanctl/conf.d/patronus.conf || nl_fail "bob's certificate is not in the connection"
openssl verify -CAfile "$RWD/swanctl/x509ca/patronus-ca.pem" /etc/swanctl/x509/patronus-rw-cert-bob.pem >/dev/null || nl_fail "bob's certificate does not verify against the CA"
nl_ok "bob got a client certificate from the CA, pinned in the connection"
nl_api GET /vpn/ipsec/roadwarrior/export/$UID_B/p12
[ "$NL_CODE" = 400 ] || nl_fail "p12 without a password: $NL_CODE"
nl_api GET "/vpn/ipsec/roadwarrior/export/$UID_B/p12?password=short"
[ "$NL_CODE" = 400 ] || nl_fail "p12 with a short password: $NL_CODE"
nl_api GET "/vpn/ipsec/roadwarrior/export/$UID_B/p12?password=p12-pass-word-1"
[ "$NL_CODE" = 200 ] || nl_fail "p12: $NL_CODE"
cp "$NL_OUT" "$RWD/swanctl/pkcs12/bob.p12"
openssl pkcs12 -info -noout -passin pass:p12-pass-word-1 -in "$RWD/swanctl/pkcs12/bob.p12" >/dev/null 2>&1 || nl_fail "bob.p12 does not open with its password"
nl_ok "bob's PKCS#12 opens with the password he was given"
nl_api GET "/vpn/ipsec/roadwarrior/export/$UID_B/mobileconfig?password=p12-pass-word-1"
python3 - "$NL_OUT" <<'PY' || nl_fail "certificate .mobileconfig is wrong"
import plistlib, sys
d = plistlib.load(open(sys.argv[1], "rb"))
pl = {p["PayloadType"]: p for p in d["PayloadContent"]}
i = pl["com.apple.vpn.managed"]["IKEv2"]
assert i["AuthenticationMethod"] == "Certificate" and i["PayloadCertificateUUID"] == pl["com.apple.security.pkcs12"]["PayloadUUID"]
assert pl["com.apple.security.pkcs12"]["Password"] == "p12-pass-word-1" and pl["com.apple.security.pkcs12"]["PayloadContent"]
PY
nl_ok "certificate .mobileconfig links the VPN payload to bob's PKCS#12 payload"
nl_api GET "/vpn/ipsec/roadwarrior/export/$UID_B/sswan?password=p12-pass-word-1"
[ "$(jget 'd["type"]')" = ikev2-cert ] && [ "$(jget 'len(d["local"]["p12"]) > 100')" = True ] || nl_fail ".sswan for a certificate user: $(head -c 300 "$NL_OUT")"
nl_api GET "/vpn/ipsec/roadwarrior/export/$UID_B/ps1?password=p12-pass-word-1"
grep -q 'MachineCertificate' "$NL_OUT" && grep -q 'Import-PfxCertificate' "$NL_OUT" || nl_fail "certificate PowerShell script"
nl_ok "Android and Windows files for a certificate user carry the PKCS#12 and the right authentication"

SECRETS_B='secrets {
  pkcs12-bob { file = bob.p12
    secret = "p12-pass-word-1" }
}'
rw_conf rwc cert.vpn.test "      auth = pubkey
      id = CN=bob" "$SECRETS_B"
rw_up || { cat "$NL_OUT"; tail -20 /t/charon-rtr.log; tail -20 /t/charon-rw.log; nl_fail "bob could not connect with his certificate"; }
SAS=$(RWS --list-sas)
grep -q ESTABLISHED <<<"$SAS" && grep -qE '10\.99\.60\.[0-9]+' <<<"$SAS" || { echo "$SAS"; nl_fail "no SA / virtual IP for bob"; }
VIPB=$(grep -oE '10\.99\.60\.[0-9]+' <<<"$SAS" | head -1)
OUT=$(RW python3 "$NL_T/nl-conn.py" $NL_CLIENT 9000) || nl_fail "bob -> LAN host: $OUT"
[ "$OUT" = "$VIPB" ] || nl_fail "the LAN host saw $OUT, want $VIPB"
nl_ok "bob connected with his certificate (virtual IP $VIPB) and reaches the LAN host"
rw_down rwc
echo "--- deleting the user revokes the certificate"
api_ok DELETE /vpn/ipsec/roadwarrior/users/$UID_B
[ ! -f /etc/swanctl/x509/patronus-rw-cert-bob.pem ] || nl_fail "bob's pinned certificate is still on disk"
rw_up || true
if established; then nl_fail "bob connected after his user was deleted"; fi
nl_ok "after bob's user is deleted his certificate is refused"

echo "=== 4. reboot: everything comes back from the store"
RWS --terminate --ike rw >/dev/null 2>&1 || true
nl_web_stop
boot
has_conn patronus-rw-eap || nl_fail "after reboot charon lacks the EAP profile"
# bob was deleted: a certificate profile without users has no connection
has_conn patronus-rw-cert && nl_fail "a certificate profile without users still has a connection"
nl_assert_nft_has 'meta ipsec exists ip saddr 10.99.50.0/24'
if [ "$MSCHAP" = 1 ]; then
rw_conf rw eap.vpn.test "      auth = eap-mschapv2
      eap_id = alice" "$(SECRET "$PW")"
cp /dev/null "$RWD/swanctl/x509ca/patronus-ca.pem"
fi
nl_web_start "$DB"; nl_login
if [ "$MSCHAP" = 1 ]; then
nl_api GET /vpn/ipsec/roadwarrior/ca; cp "$NL_OUT" "$RWD/swanctl/x509ca/patronus-ca.pem"
rw_up || { cat "$NL_OUT"; nl_fail "alice cannot connect after the reboot (same CA, same password)"; }
nl_ok "after a reboot both profiles are loaded and alice connects with the same CA and password"
rw_down rw
fi

echo "=== 5. deleting the profiles removes everything"
api_ok DELETE /vpn/ipsec/roadwarrior/profiles/$PID
api_ok DELETE /vpn/ipsec/roadwarrior/profiles/$CPID
api_ok GET /vpn/ipsec/roadwarrior
[ "$(jget 'len(d["profiles"])')" = 0 ] || nl_fail "profiles left"
if grep -q 'patronus-rw' /etc/swanctl/conf.d/patronus.conf; then cat /etc/swanctl/conf.d/patronus.conf; nl_fail "profiles left in the swanctl config"; fi
[ -z "$(ls /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/x509ca 2>/dev/null | grep patronus-rw || true)" ] || nl_fail "certificates left in /etc/swanctl"
nl_assert_nft_lacks 'IPsec road warriors' 'dport { 500, 4500 }'
nl_ok "profiles deleted: swanctl config, certificates and firewall rules are gone"
nl_web_stop
[ -s /tmp/charon-rtr.pid ] && { kill "$(cat /tmp/charon-rtr.pid)" 2>/dev/null || true; }
nl_down
ip netns del nl-rw 2>/dev/null || true
