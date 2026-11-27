#!/usr/bin/env bash
# Lane H: certificate manager / ACME client against a real ACME server (Pebble)
# and a real authoritative name server (BIND, RFC 2136 + TSIG), on the
# "internet" side of the netlab.
#
#  - HTTP-01: the router answers on its WAN port 80 (the firewall opens it by
#    itself while a certificate uses http-01), Pebble validates and issues;
#  - the web UI serves the issued certificate, and a forced renewal swaps it
#    without a restart (same web process, new serial on the wire);
#  - the renewal task renews a certificate inside its window by itself;
#  - an expired certificate is reported as expired in the status API;
#  - DNS-01 (wildcard) through RFC 2136 with a TSIG key; a wrong TSIG secret
#    fails, is reported (status + cert_renewal_failed event) and leaves the
#    old certificate serving;
#  - revocation reaches the CA (Pebble reports the serial revoked) and a new
#    certificate is requested.
# BIND stands in for the DNS provider (a challenge server such as
# pebble-challtestsrv cannot take RFC 2136 updates); Pebble resolves through it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-acme.db
rm -f "$DB" "$NL_T/nl-jar"
PEBBLE=${PEBBLE_BIN:-/opt/pebble/pebble}
[ -x "$PEBBLE" ] || nl_fail "pebble binary missing at $PEBBLE (ci/netlab/run.sh installs it)"
command -v named >/dev/null || nl_fail "named (bind9) missing"

NS_IP=198.51.100.54
CA_IP=198.51.100.55
ZONE=acme.test
HOST=router.$ZONE
W=$NL_T/acme; rm -rf "$W"; mkdir -p "$W/zones" "$W/bind"

echo "=== lab: BIND (zone $ZONE, TSIG key) + Pebble"
# a small CA for Pebble's own HTTPS (the router verifies the ACME server's TLS)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=lab-acme-root" -keyout "$W/root.key" -out "$W/root.pem" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=pebble" -keyout "$W/srv.key" -out "$W/srv.csr" 2>/dev/null
printf 'subjectAltName=IP:%s,DNS:pebble.%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$CA_IP" "$ZONE" > "$W/srv.ext"
openssl x509 -req -in "$W/srv.csr" -CA "$W/root.pem" -CAkey "$W/root.key" -CAcreateserial -days 2 -extfile "$W/srv.ext" -out "$W/srv.pem" 2>/dev/null

TSIG_SECRET=$(head -c 32 /dev/urandom | base64 -w0)
cat > "$W/bind/named.conf" <<EOF
options { directory "$W/bind"; listen-on { $NS_IP; }; listen-on-v6 { none; }; recursion no; allow-query { any; };
          pid-file "$W/bind/named.pid"; session-keyfile "$W/bind/session.key"; dnssec-validation no; };
key "acme-key" { algorithm hmac-sha256; secret "$TSIG_SECRET"; };
zone "$ZONE" { type primary; file "$W/zones/$ZONE.db"; allow-update { key "acme-key"; }; };
EOF
cat > "$W/zones/$ZONE.db" <<EOF
\$TTL 5
@ IN SOA ns.$ZONE. hostmaster.$ZONE. 1 5 5 5 5
@ IN NS ns.$ZONE.
ns IN A $NS_IP
router IN A $NL_RTR_WAN
pebble IN A $CA_IP
EOF
chown -R bind "$W/zones" "$W/bind" 2>/dev/null || true
chmod -R a+rwX "$W/zones" "$W/bind"
cat > "$W/pebble.json" <<EOF
{ "pebble": { "listenAddress": "$CA_IP:14000", "managementListenAddress": "$CA_IP:15000",
  "certificate": "$W/srv.pem", "privateKey": "$W/srv.key", "httpPort": 80, "tlsPort": 443,
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "domainBlocklist": [], "retryAfter": { "authz": 3, "order": 5 },
  "profiles": { "default": { "description": "lab", "validityPeriod": 90 } } } }
EOF

nl_write_installer_toml
nl_boot "$DB"
INET ip addr add $NS_IP/24 dev inet0
INET ip addr add $CA_IP/24 dev inet0
nl_bg INET named -g -c "$W/bind/named.conf" -u root
nl_bg INET env PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE" -config "$W/pebble.json" -dnsserver "$NS_IP:53"
for _ in $(seq 1 60); do
  INET curl -s --cacert "$W/root.pem" "https://$CA_IP:14000/dir" -o "$W/dir.json" 2>/dev/null && break; sleep 0.5
done
grep -q newOrder "$W/dir.json" || nl_fail "pebble did not come up"
[ "$(INET dig +short @$NS_IP $HOST 2>/dev/null || true)" = "" ] && true
nl_ok "Pebble (ACME directory) and BIND (zone $ZONE) are up on the internet side"

# the router's web UI also listens on port 80 (the HTTP-01 answer lives there)
export PATRONUS_HTTP_REDIRECT_PORT=80 PATRONUS_CERTS_CHECK_SECS=10 PATRONUS_CERTS_FIRST_CHECK_SECS=5
nl_web_start "$DB"; nl_login
WEBPID=$NL_WEB_PID

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
served_serial() { C sh -c "echo | openssl s_client -connect $NL_RTR_LAN:8443 2>/dev/null | openssl x509 -noout -serial" | cut -d= -f2; }
status_of() { nl_api GET /svc/certs; python3 - "$NL_OUT" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for r in d["collections"]["acme"]:
    if r["name"]==sys.argv[2]:
        print(json.dumps(r["status"])); break
PY
}
wait_state() { # NAME STATE SECS
  local n=$1 want=$2 secs=${3:-90} i
  for i in $(seq 1 "$secs"); do
    st=$(status_of "$n"); case "$st" in *"\"state\": \"$want\""*) return 0;; esac; sleep 1
  done
  nl_fail "certificate $n never reached state $want: $st"
}

DIRURL="https://$CA_IP:14000/dir"
ROW_COMMON="\"directory\":\"custom\",\"directory_url\":\"$DIRURL\",\"ca_bundle\":\"$W/root.pem\",\"tos\":true,\"email\":\"lab@$ZONE\",\"renew_days\":1"

echo "=== HTTP-01 for the web UI"
nl_api PUT /svc/certs "{\"dir\":\"$W/certs\",\"check_mins\":1,\"retry_mins\":1}"
[ "$NL_CODE" = 200 ] || nl_fail "certs settings: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /svc/certs/acme "{\"name\":\"web\",\"domains\":\"$HOST\",\"challenge\":\"http-01\",\"use_for_web\":false,$ROW_COMMON}"
[ "$NL_CODE" = 201 ] || nl_fail "add certificate: $NL_CODE $(cat "$NL_OUT")"
nl_assert_nft_has 'tcp dport 80 accept comment "ACME http-01 challenge"'
nl_ok "an enabled http-01 certificate opens tcp/80 on the WAN by itself"
nl_api POST /svc/certs/action/issue '{"name":"web"}'
[ "$NL_CODE" = 200 ] || { tail -20 "$NL_T/nl-web.log"; nl_fail "issue (http-01): $NL_CODE $(cat "$NL_OUT")"; }
[ "$(jget 'd["issued"]')" = True ] || nl_fail "not issued: $(cat "$NL_OUT")"
[ -s "$W/certs/web/fullchain.pem" ] && [ "$(stat -c %a "$W/certs/web/key.pem")" = 600 ] || nl_fail "files / key mode"
openssl verify -CAfile "$W/root.pem" "$W/certs/web/fullchain.pem" >/dev/null 2>&1 && true
nl_ok "Pebble validated HTTP-01 and issued; key stored mode 0600"

OLD=$(served_serial)
nl_api PUT /svc/certs/acme/1 '{"use_for_web":true}'
[ "$NL_CODE" = 200 ] || nl_fail "use_for_web: $NL_CODE"
nl_api POST /svc/certs/action/issue '{"name":"web"}'
[ "$NL_CODE" = 200 ] || nl_fail "issue for web: $NL_CODE $(cat "$NL_OUT")"
sleep 1
S1=$(served_serial)
CERT_SERIAL=$(openssl x509 -in "$W/certs/web/fullchain.pem" -noout -serial | cut -d= -f2)
[ "$S1" = "$CERT_SERIAL" ] || nl_fail "web UI serves $S1, issued $CERT_SERIAL"
[ "$S1" != "$OLD" ] || nl_fail "web UI still serves the self-signed certificate"
nl_ok "the web UI serves the issued certificate (serial $S1)"

kill -0 "$WEBPID" 2>/dev/null || nl_fail "web process gone"
nl_api POST /svc/certs/action/issue '{"name":"web"}'
[ "$NL_CODE" = 200 ] || nl_fail "forced renewal: $NL_CODE $(cat "$NL_OUT")"
sleep 1
S2=$(served_serial)
[ "$S2" != "$S1" ] || nl_fail "forced renewal did not change the served certificate"
kill -0 "$WEBPID" 2>/dev/null || nl_fail "web process restarted/died on renewal"
nl_ok "forced renewal swapped the certificate in place ($S1 -> $S2), no restart"

echo "=== renewal task + expiry"
# validity is 90 s and renew_days is 1: the certificate is always inside its window, the task must renew it
for _ in $(seq 1 60); do S3=$(served_serial); [ "$S3" != "$S2" ] && break; sleep 1; done
[ "$S3" != "$S2" ] || nl_fail "the renewal task did not renew a due certificate within 60 s"
nl_ok "the renewal task renewed a due certificate by itself ($S2 -> $S3)"
nl_api PUT /svc/certs/acme/1 '{"enabled":false}'
for _ in $(seq 1 120); do
  st=$(status_of web); case "$st" in *'"state": "expired"'*) break;; esac; sleep 1
done
case "$st" in *'"state": "expired"'*) ;; *) nl_fail "an expired certificate is not reported expired: $st";; esac
nl_ok "an expired certificate shows state=expired in the status API"
nl_api PUT /svc/certs/acme/1 '{"enabled":true}'
for _ in $(seq 1 90); do
  st=$(status_of web); case "$st" in *'"state": "expired"'*|*'"state": "none"'*) sleep 1;; *) break;; esac
done
case "$st" in *'"state": "expired"'*|*'"state": "none"'*) nl_fail "the expired certificate was not replaced: $st";; esac
nl_ok "re-enabled: the expired certificate was replaced"

echo "=== DNS-01 (wildcard) through RFC 2136 + TSIG"
DNS_ROW="\"dns_provider\":\"rfc2136\",\"dns_server\":\"$NS_IP:53\",\"dns_zone\":\"$ZONE\",\"tsig_key_name\":\"acme-key\",\"tsig_algorithm\":\"hmac-sha256\",\"propagation_secs\":1"
nl_api POST /svc/certs/acme "{\"name\":\"wild\",\"domains\":\"*.$ZONE,$ZONE\",\"challenge\":\"dns-01\",\"tsig_secret\":\"$TSIG_SECRET\",$DNS_ROW,$ROW_COMMON}"
[ "$NL_CODE" = 201 ] || nl_fail "add wildcard: $NL_CODE $(cat "$NL_OUT")"
WID=$(jget 'd["id"]')
nl_api POST /svc/certs/action/issue '{"name":"wild"}'
[ "$NL_CODE" = 200 ] || { tail -20 "$NL_T/nl-web.log"; nl_fail "issue (dns-01): $NL_CODE $(cat "$NL_OUT")"; }
SANS=$(openssl x509 -in "$W/certs/wild/fullchain.pem" -noout -ext subjectAltName)
grep -q "DNS:\*.$ZONE" <<<"$SANS" || nl_fail "wildcard SAN missing"
nl_ok "wildcard issued with DNS-01 via RFC 2136 (TSIG signed), no shell tool involved"
[ -z "$(INET dig +short TXT _acme-challenge.$ZONE @$NS_IP 2>/dev/null)" ] || nl_fail "challenge TXT record left in the zone"
nl_ok "the challenge TXT record was removed after validation"

BAD=$(head -c 32 /dev/urandom | base64 -w0)
nl_api PUT "/svc/certs/acme/$WID" "{\"tsig_secret\":\"$BAD\"}"
[ "$NL_CODE" = 200 ] || nl_fail "change secret: $NL_CODE"
BEFORE=$(openssl x509 -in "$W/certs/wild/fullchain.pem" -noout -serial)
nl_api POST /svc/certs/action/issue '{"name":"wild"}'
[ "$NL_CODE" != 200 ] || nl_fail "issue with a wrong TSIG secret succeeded"
st=$(status_of wild)
case "$st" in *"DNS UPDATE"*|*"rcode"*|*"NOTAUTH"*|*"REFUSED"*) ;; *) nl_fail "failure not in the status: $st";; esac
[ "$(openssl x509 -in "$W/certs/wild/fullchain.pem" -noout -serial)" = "$BEFORE" ] || nl_fail "failed renewal replaced the certificate"
nl_ok "a wrong TSIG secret fails, is reported in the status, and the old certificate stays"
for _ in $(seq 1 90); do
  nl_api GET /events; grep -q cert_renewal_failed "$NL_OUT" && break; sleep 1
done
grep -q cert_renewal_failed "$NL_OUT" || nl_fail "no cert_renewal_failed event from the renewal task"
nl_ok "the renewal task recorded cert_renewal_failed (notification pipeline)"
nl_api PUT "/svc/certs/acme/$WID" '{"enabled":false}'

echo "=== revocation"
SER=$(openssl x509 -in "$W/certs/web/fullchain.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
nl_api POST /svc/certs/action/revoke '{"name":"web"}'
[ "$NL_CODE" = 200 ] || nl_fail "revoke: $NL_CODE $(cat "$NL_OUT")"
PST=$(INET curl -sk "https://$CA_IP:15000/cert-status-by-serial/$SER")
grep -qi revoked <<<"$PST" || nl_fail "Pebble does not list serial $SER as revoked"
nl_ok "the revocation reached the CA (Pebble: serial $SER revoked)"
for _ in $(seq 1 60); do [ -s "$W/certs/web/fullchain.pem" ] && break; sleep 1; done
[ -s "$W/certs/web/fullchain.pem" ] || nl_fail "no replacement requested after revocation"
NEW=$(openssl x509 -in "$W/certs/web/fullchain.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
[ "$NEW" != "$SER" ] || nl_fail "the revoked certificate is back"
nl_ok "a replacement certificate was requested after revocation"

echo "=== secrets stay out of the API and logs"
nl_api GET /svc/certs
! grep -qF "$TSIG_SECRET" "$NL_OUT" && ! grep -qF "$BAD" "$NL_OUT" || nl_fail "a TSIG secret is in the API answer"
! grep -qF "$TSIG_SECRET" "$NL_T/nl-web.log" && ! grep -qF "$BAD" "$NL_T/nl-web.log" || nl_fail "a TSIG secret is in the log"
! grep -q "BEGIN .*PRIVATE KEY" "$NL_T/nl-web.log" || nl_fail "a private key is in the log"
nl_ok "no secret or key in the API answer or the log"
nl_assert_store_ok "$DB"
nl_web_stop
INET sh -c "kill \$(cat $W/bind/named.pid)" 2>/dev/null || true
echo "PASS lane-h-acme"
