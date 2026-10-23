#!/usr/bin/env bash
# Lane N: groups and privileges (RBAC) in the shipped binary, from the LAN.
# An operator account put in a group may read the firewall and write routing
# only; everything else answers 403 (API and pages); the membership survives a
# restart of patronus-web (it is in the store); deleting the group gives the
# operator role back.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-rbac.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api POST /system/users '{"username":"neto","password":"Neto-Passw0rd-123","role":"operator"}'
[ "$NL_CODE" = 201 ] || nl_fail "create account: $NL_CODE $(cat "$NL_OUT")"; UID_=$(jget 'd["id"]')
nl_api POST /system/groups '{"name":"netops","privileges":{"firewall":"read","routing":"write"}}'
[ "$NL_CODE" = 201 ] || nl_fail "create group: $NL_CODE $(cat "$NL_OUT")"; GID=$(jget 'd["id"]')
nl_api PUT /system/users/$UID_/group "{\"group_id\":$GID}"
[ "$NL_CODE" = 200 ] || nl_fail "membership: $NL_CODE $(cat "$NL_OUT")"
nl_ok "group netops created, account neto is a member"

# the grouped account, in a cookie jar of its own
J=$NL_T/nl-jar-neto; rm -f "$J"
code() { C curl -sk -b "$J" -c "$J" -o "$NL_OUT" -w '%{http_code}' -X "$1" -H 'content-type: application/json' ${3:+-d "$3"} "$NL_UI$2"; }
[ "$(code POST /api/auth/login '{"username":"neto","password":"Neto-Passw0rd-123"}')" = 200 ] || nl_fail "neto login"
want() { local got; got=$(code "$2" "$3" "${4:-}"); [ "$got" = "$1" ] || nl_fail "$2 $3 -> $got, want $1 ($(cat "$NL_OUT"))"; nl_ok "$2 $3 -> $got"; }
want 200 GET /api/firewall/rules
want 403 POST /api/firewall/aliases '{}'
want 403 GET /api/vpn/wireguard
want 403 GET /api/system/backups
want 403 GET /vpn
want 200 GET /routing
want 403 POST /api/system/groups '{"name":"evil"}'

echo "=== survives a restart of the web UI"
nl_web_stop; nl_web_start "$DB"
[ "$(code POST /api/auth/login '{"username":"neto","password":"Neto-Passw0rd-123"}')" = 200 ] || nl_fail "neto login after restart"
want 403 GET /api/vpn/wireguard
[ "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM rbac_members')" = 1 ] || nl_fail "membership is not in the store"

echo "=== deleting the group gives the role back"
nl_login
nl_api DELETE /system/groups/$GID; [ "$NL_CODE" = 200 ] || nl_fail "delete group $NL_CODE"
[ "$(code POST /api/auth/login '{"username":"neto","password":"Neto-Passw0rd-123"}')" = 200 ] || nl_fail "neto login"
got=$(code GET /api/vpn/wireguard); [ "$got" != 403 ] || nl_fail "still 403 after the group is gone"
nl_ok "operator role applies again (GET /api/vpn/wireguard -> $got)"
echo "PASS lane-n-rbac"
