#!/usr/bin/env bash
# Lane N: the dashboard's HTTPS. The first start generates a self-signed certificate
# (cert.pem + key.pem, key mode 0600, names localhost / patronus / patronus.local) and the
# LAN really is served that certificate; a browser-style client that trusts it and uses a
# listed name gets the login page, one that does not trust it is refused; plain HTTP on the
# HTTPS port gets no dashboard; the session cookie is Secure; TLS 1.2 and 1.3 work; a
# restart reuses the same certificate (the pinned fingerprint does not change under the
# admin); and a certificate the operator drops into the directory is served instead.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-tls.db
TLS=$NL_T/nl-tls
rm -f "$DB" "$NL_T/nl-jar"
rm -rf "$TLS"
command -v openssl >/dev/null || nl_fail "openssl not installed"
nl_write_installer_toml
nl_boot "$DB"

# fingerprint of the certificate the LAN is actually served (SNI name given)
served_fp() { # SNI
  C sh -c "openssl s_client -connect $NL_RTR_LAN:8443 -servername $1 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" | sed 's/^.*=//'
}
file_fp() { openssl x509 -in "$TLS/cert.pem" -noout -fingerprint -sha256 | sed 's/^.*=//'; }
# GET https://NAME:8443/login from the LAN client, trusting only CERT, name pinned to the router
trusted_login_code() { # NAME CERT
  C curl -s -m 10 --cacert "$2" --resolve "$1:8443:$NL_RTR_LAN" -o "$NL_OUT" -w '%{http_code}' "https://$1:8443/login" || true
}

echo "=== first start generates the certificate"
nl_web_start "$DB"
[ -s "$TLS/cert.pem" ] && [ -s "$TLS/key.pem" ] || { ls -la "$TLS" || true; nl_fail "no cert.pem/key.pem generated under $TLS"; }
[ "$(stat -c %a "$TLS/key.pem")" = 600 ] || nl_fail "key.pem mode is $(stat -c %a "$TLS/key.pem"), want 600"
SAN=$(openssl x509 -in "$TLS/cert.pem" -noout -ext subjectAltName)
for n in localhost patronus patronus.local; do
  case "$SAN" in *"DNS:$n"*) ;; *) nl_fail "certificate lacks the name $n: $SAN" ;; esac
done
nl_ok "cert.pem + key.pem generated, key mode 0600, names localhost / patronus / patronus.local"

FP1=$(file_fp)
[ "$(served_fp patronus)" = "$FP1" ] || nl_fail "the LAN is served a different certificate than the one on disk"
nl_ok "the LAN client is served exactly the generated certificate ($FP1)"

echo "=== trust and refusal"
[ "$(trusted_login_code patronus "$TLS/cert.pem")" = 200 ] || nl_fail "login page over verified TLS for the name 'patronus' did not answer 200"
grep -qF 'id="login-form"' "$NL_OUT" || nl_fail "verified TLS answered, but not with the login page"
nl_ok "a client trusting the certificate gets the login page for https://patronus:8443 (name verified)"
[ "$(trusted_login_code wrong.example.test "$TLS/cert.pem")" != 200 ] || nl_fail "a name the certificate does not carry was accepted"
nl_ok "a name the certificate does not carry is refused"
rc=0; C curl -s -m 10 -o /dev/null "$NL_UI/login" || rc=$?
[ "$rc" = 60 ] || nl_fail "curl without -k and without trusting the certificate exited $rc, want 60 (untrusted self-signed)"
nl_ok "a client that does not trust the self-signed certificate is refused (curl exit 60)"

echo "=== plain HTTP on the HTTPS port, protocol versions, Secure cookie"
code=$(C curl -s -m 5 -o "$NL_OUT" -w '%{http_code}' "http://$NL_RTR_LAN:8443/login" || true)
if [ "$code" = 200 ] || grep -qF 'login-form' "$NL_OUT" 2>/dev/null; then nl_fail "plain HTTP on 8443 served the dashboard ($code)"; fi
nl_ok "plain HTTP on the HTTPS port does not serve the dashboard (answer '$code')"
for v in tls1_2 tls1_3; do
  C sh -c "openssl s_client -connect $NL_RTR_LAN:8443 -$v </dev/null 2>&1" > "$NL_OUT" || true
  grep -q 'BEGIN CERTIFICATE' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no $v handshake"; }
done
nl_ok "TLS 1.2 and TLS 1.3 handshakes both succeed"
C curl -sk -m 10 -D "$NL_T/nl-hdr" -o /dev/null -H 'content-type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$NL_PASS\"}" "$NL_UI/api/auth/login"
grep -i '^set-cookie:' "$NL_T/nl-hdr" > "$NL_OUT" || { cat "$NL_T/nl-hdr"; nl_fail "login set no cookie"; }
while read -r line; do
  case "$(echo "$line" | tr 'A-Z' 'a-z')" in *"; secure"*|*";secure"*) ;; *) nl_fail "cookie without Secure: $line" ;; esac
done < "$NL_OUT"
nl_ok "every cookie the login sets carries Secure"

echo "=== a restart keeps the certificate"
nl_web_stop
nl_web_start "$DB"
[ "$(file_fp)" = "$FP1" ] || nl_fail "restart regenerated the certificate"
[ "$(served_fp patronus)" = "$FP1" ] || nl_fail "after the restart a different certificate is served"
nl_ok "after a restart the same certificate is still served (fingerprint unchanged)"

echo "=== the operator's own certificate wins"
nl_web_stop
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj /CN=fw.corp.test -addext subjectAltName=DNS:fw.corp.test \
  -keyout "$TLS/key.pem" -out "$TLS/cert.pem" >/dev/null 2>&1 || nl_fail "could not make the operator certificate"
chmod 600 "$TLS/key.pem"
FP2=$(file_fp)
[ "$FP2" != "$FP1" ] || nl_fail "test setup: the operator certificate equals the generated one"
nl_web_start "$DB"
[ "$(served_fp fw.corp.test)" = "$FP2" ] || nl_fail "the operator's certificate is not the one served"
[ "$(file_fp)" = "$FP2" ] || nl_fail "the operator's certificate was overwritten"
[ "$(trusted_login_code fw.corp.test "$TLS/cert.pem")" = 200 ] || nl_fail "login page over the operator's certificate did not answer 200"
nl_ok "a certificate dropped into the TLS directory is served for fw.corp.test and never overwritten"
nl_web_stop
echo "ALL DASHBOARD TLS CHECKS PASSED"
