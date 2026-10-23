#!/usr/bin/env bash
# Lane N: LDAP login for the web UI against a real OpenLDAP (slapd) on the
# "internet" host. A directory user logs in from the LAN with the directory
# password and gets the server's default role (operator when a member of the
# operator group); a wrong or empty password, an unknown user, a filter
# injection attempt and a LOCAL account's name with the directory password are
# all refused; the search account's password never leaves the store; deleting
# the server ends directory logins.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-ldap.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
if ! command -v slapd >/dev/null; then
  printf 'slapd slapd/password1 password Ldap-Admin-Pw-1\nslapd slapd/password2 password Ldap-Admin-Pw-1\nslapd slapd/domain string example.net\nslapd shared/organization string Example\nslapd slapd/no_configuration boolean false\n' | debconf-set-selections
  apt-get install -y -qq slapd ldap-utils >/dev/null 2>&1 || nl_fail "slapd could not be installed"
fi
command -v ldapadd >/dev/null || nl_fail "ldap-utils missing"
BASE=dc=example,dc=net
ADMIN="cn=admin,$BASE"; APW=Ldap-Admin-Pw-1
nl_write_installer_toml
nl_boot "$DB"
mkdir -p /run/slapd; chown openldap:openldap /run/slapd 2>/dev/null || true
nl_bg INET slapd -h "ldap://$NL_WWW:389/" -u openldap -g openldap -F /etc/ldap/slapd.d
nl_wait 20 ip netns exec nl-inet ldapsearch -x -H ldap://$NL_WWW -b "$BASE" -s base dn || nl_fail "slapd did not answer"
H1=$(slappasswd -s Alice-Dir-Pw-1); H2=$(slappasswd -s Olive-Dir-Pw-1); H3=$(slappasswd -s Ldap-Admin-Spoof-1)
ip netns exec nl-inet ldapadd -x -H ldap://$NL_WWW -D "$ADMIN" -w "$APW" >/dev/null <<LDIF || nl_fail "loading the directory"
dn: ou=people,$BASE
objectClass: organizationalUnit
ou: people

dn: ou=groups,$BASE
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,$BASE
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: A
userPassword: $H1

dn: uid=olive,ou=people,$BASE
objectClass: inetOrgPerson
uid: olive
cn: Olive
sn: O
userPassword: $H2

dn: uid=admin,ou=people,$BASE
objectClass: inetOrgPerson
uid: admin
cn: Admin Spoof
sn: S
userPassword: $H3

dn: cn=netops,ou=groups,$BASE
objectClass: groupOfNames
cn: netops
member: uid=olive,ou=people,$BASE
LDIF
nl_ok "OpenLDAP is serving $BASE (alice, olive in netops, an 'admin' entry with another password)"

nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api POST /system/auth-servers '{"kind":"ldap","name":"dir","host":"'$NL_WWW'","base_dn":"'$BASE'","user_filter":"uid=*"}'
[ "$NL_CODE" = 400 ] || nl_fail "a filter without {u} must be refused, got $NL_CODE"
nl_api POST /system/auth-servers '{"kind":"ldap","name":"dir","host":"'$NL_WWW'"}'
[ "$NL_CODE" = 400 ] || nl_fail "an LDAP server without a base DN must be refused, got $NL_CODE"
nl_api POST /system/auth-servers '{"kind":"ldap","name":"dir","host":"'$NL_WWW'","base_dn":"'$BASE'","bind_dn":"'$ADMIN'"}'
[ "$NL_CODE" = 400 ] || nl_fail "a bind DN without its password must be refused, got $NL_CODE"
nl_api POST /system/auth-servers '{"kind":"ldap","name":"dir","host":"'$NL_WWW'","base_dn":"'$BASE'","bind_dn":"'$ADMIN'","bind_password":"'$APW'","operator_group":"cn=netops,ou=groups,'$BASE'","default_role":"readonly"}'
[ "$NL_CODE" = 201 ] || nl_fail "add LDAP server: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /system/auth-servers
grep -q "$APW" "$NL_OUT" && nl_fail "the search account's password is in the API answer"
[ "$(jget 'd[0]["kind"]')" = ldap ] || nl_fail "list: $(cat "$NL_OUT")"
nl_ok "LDAP server saved (bad filters/missing base DN refused, password not returned)"

J=$NL_T/nl-jar-ldap
login() { rm -f "$J"; C curl -sk -b "$J" -c "$J" -o "$NL_OUT" -w '%{http_code}' -X POST -H 'content-type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" "$NL_UI/api/auth/login"; }
[ "$(login alice Alice-Dir-Pw-1)" = 200 ] || nl_fail "alice (directory) could not log in: $(cat "$NL_OUT")"
[ "$(jget 'd["role"].lower()')" = readonly ] || nl_fail "alice should be read-only: $(cat "$NL_OUT")"
nl_ok "alice logs in with her directory password as read-only"
[ "$(login olive Olive-Dir-Pw-1)" = 200 ] || nl_fail "olive could not log in: $(cat "$NL_OUT")"
[ "$(jget 'd["role"].lower()')" = operator ] || nl_fail "olive is in netops and should be operator: $(cat "$NL_OUT")"
nl_ok "olive (member of netops) logs in as operator"

for bad in "alice Wrong-Pw-12345" "alice " "nobody Alice-Dir-Pw-1" "alice)(uid=* x" "*  Alice-Dir-Pw-1" "alice* Alice-Dir-Pw-1"; do
  set -- $bad
  got=$(login "$1" "${2:-}")
  [ "$got" = 401 ] || [ "$got" = 400 ] || nl_fail "login '$1' with '${2:-}' answered $got, must be refused"
  # a good login in between keeps the brute-force throttle (5 failures) from tripping
  [ "$(login alice Alice-Dir-Pw-1)" = 200 ] || nl_fail "alice cannot log in again after '$1'"
done
nl_ok "wrong/empty password, unknown user and filter-injection names are refused"
got=$(login admin Ldap-Admin-Spoof-1)
[ "$got" = 401 ] || nl_fail "the LOCAL admin account must not accept the directory's password (got $got)"
nl_ok "a local account never falls back to the directory"

[ "$(sqlite3 "$DB" "SELECT role FROM web_users WHERE username='olive'")" = operator ] || nl_fail "olive's account is not stored as operator"
[ "$(sqlite3 "$DB" "SELECT substr(password_hash,1,10) FROM web_users WHERE username='alice'")" = '!external:' ] || nl_fail "alice should be a password-less external account"

echo "=== directory gone"
SID=$(sqlite3 "$DB" "SELECT id FROM auth_servers WHERE kind='ldap'")
nl_api DELETE /system/auth-servers/$SID; [ "$NL_CODE" = 200 ] || nl_fail "delete server $NL_CODE"
[ "$(login alice Alice-Dir-Pw-1)" = 401 ] || nl_fail "alice can still log in after the server was removed"
nl_ok "with the server removed, directory logins end"
echo "PASS lane-n-ldap"
