#!/usr/bin/env bash
# Lane J: RFC 2136 dynamic DNS client (USE=rfc2136), against a REAL authoritative
# server: BIND `named` in the INET namespace, zone example.net, updates only
# accepted with a TSIG key (HMAC-SHA256). The router publishes its WAN address.
#   - an unsigned update from the router's own network is REFUSED (proves auth)
#   - validation: bad names/keys/zone/secret are refused (400) and nothing starts
#   - enable: A (+AAAA with family=both) appear in the zone with the right TTL
#   - the WAN address changes: the zone follows within a few check intervals
#   - a client with a wrong TSIG secret fails visibly (status) and writes nothing
#   - TCP transport works
#   - secrets: never in the API, the rendered view, `patronus rfc2136 show`,
#     any process command line, the web log; the engine file is mode 0600; no
#     key file is left behind
#   - survives a reboot apply; disabling stops it
set -euo pipefail
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"   # `patronus rfc2136 run` is the engine
DB=/t/lane-j-rfc2136.db
rm -f "$DB"
nl_write_installer_toml
nl_kill_daemons
ND=$NL_T/named
NS_IP=198.51.100.54
KEY=$(head -c 32 /dev/urandom | base64 -w0)
BADKEY=$(head -c 32 /dev/urandom | base64 -w0)
KEY512=$(head -c 64 /dev/urandom | base64 -w0)

. "$NL_T/fixtures/rfc2136-named.sh"
diag() {
  set +e
  echo "--- diag: engine status"; cat /var/lib/patronus/net/run/rfc2136.stats /run/patronus/rfc2136.stats 2>/dev/null
  echo "--- diag: engine processes"; ps -eo pid,stat,args | grep '[r]fc2136'
  echo "--- diag: nsupdate -d for client 2"
  python3 - /var/lib/patronus/net/rfc2136.json "$NL_T" <<'PY'
import json, sys
c = [x for x in json.load(open(sys.argv[1]))["clients"] if x["hostname"].startswith("v6.")][0]
open(sys.argv[2] + "/dbg.key", "w").write('key "%s" { algorithm %s; secret "%s"; };\n' % (c["key_name"], c["key_algo"], c["key_secret"]))
open(sys.argv[2] + "/dbg.txt", "w").write("server %s %s\nzone %s.\nupdate delete %s. A\nupdate add %s. 300 A 203.0.113.9\nsend\n" % (c["server"], c["port"], c["zone"], c["hostname"], c["hostname"]))
print(c["key_algo"], c["tcp"], c["port"], c["server"])
PY
  R nsupdate -d -k "$NL_T/dbg.key" -v "$NL_T/dbg.txt" 2>&1 | tail -30
  R nsupdate -d -k "$NL_T/dbg.key" "$NL_T/dbg.txt" 2>&1 | tail -8
  echo "--- diag: named log"; tail -15 "$ND"/*.log 2>/dev/null
  echo "--- diag: web log"; tail -10 "$NL_T/nl-web.log" 2>/dev/null
  echo "--- diag: zone"; INET dig +noall +answer @"$NS_IP" example.net AXFR 2>&1 | head -20
}
trap 'rc=$?; named_stop; [ $rc = 0 ] || diag' EXIT

# swap the WAN address; promote_secondaries keeps the new one when the old primary goes
wan_renumber() { # NEW OLD
  R sh -c 'echo 1 > /proc/sys/net/ipv4/conf/rtr-wan/promote_secondaries'
  R ip addr add "$1/24" dev rtr-wan
  R ip addr del "$2/24" dev rtr-wan
}

nl_up
named_start
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login

echo "=== the server really requires TSIG"
printf 'server %s 53\nzone example.net.\nupdate add evil.example.net. 60 A 192.0.2.99\nsend\n' "$NS_IP" > "$NL_T/unsigned.txt"
if R nsupdate -t 5 "$NL_T/unsigned.txt" >"$NL_T/unsigned.out" 2>&1; then nl_fail "named took an UNSIGNED update"; fi
[ -z "$(dnsq evil.example.net A)" ] || nl_fail "unsigned update changed the zone"
nl_ok "an unsigned RFC 2136 update from the router is refused; the zone is unchanged"

echo "=== validation"
mk() { # HOST ZONE KEYNAME SECRET [extra json]
  printf '{"hostname":"%s","zone":"%s","server":"%s","key_name":"%s","key_secret":"%s","iface":"@wan"%s}' "$1" "$2" "$NS_IP" "$3" "$4" "${5:+,$5}"
}
nl_api_code "bad host (space)" 400 POST /svc/rfc2136/clients "$(mk 'a b.example.net' example.net ddns-key "$KEY")"
nl_api_code "newline in server" 400 POST /svc/rfc2136/clients '{"hostname":"r.example.net","zone":"example.net","server":"1.2.3.4\nupdate delete x A","key_name":"k","key_secret":"c2VjcmV0c2VjcmV0","iface":"@wan"}'
nl_api_code "quote in key name" 400 POST /svc/rfc2136/clients "$(mk r.example.net example.net 'k"1' "$KEY")"
nl_api_code "md5 algorithm" 400 POST /svc/rfc2136/clients "$(mk r.example.net example.net ddns-key "$KEY" '"key_algo":"hmac-md5"')"
nl_api_code "bad port" 400 POST /svc/rfc2136/clients "$(mk r.example.net example.net ddns-key "$KEY" '"port":70000')"
nl_api_code "bad family" 400 POST /svc/rfc2136/clients "$(mk r.example.net example.net ddns-key "$KEY" '"family":"ipx"')"
nl_api_code "bad interface" 400 POST /svc/rfc2136/clients "{\"hostname\":\"r.example.net\",\"zone\":\"example.net\",\"server\":\"$NS_IP\",\"key_name\":\"ddns-key\",\"key_secret\":\"$KEY\",\"iface\":\"@wan;x\"}"
nl_api_code "enable with no client" 400 PUT /svc/rfc2136 '{"enabled":true}'
nl_api_ok "host outside the zone is stored (checked at apply)" POST /svc/rfc2136/clients "$(mk r.example.org example.net ddns-key "$KEY")"
nl_api_code "enable: host outside its zone" 400 PUT /svc/rfc2136 '{"enabled":true}'
nl_api GET /svc/rfc2136; BADID=$(nl_json "$NL_OUT" 'd["collections"]["clients"][0]["id"]')
nl_api_ok "fix the host name" PUT /svc/rfc2136/clients/$BADID "$(mk r.example.net example.net ddns-key not-base64-secret!)"
nl_api_code "enable: secret is not base64" 400 PUT /svc/rfc2136 '{"enabled":true}'
if pgrep -f '[r]fc2136 run' >/dev/null 2>&1; then nl_fail "the client started although the change was refused"; fi
nl_api_ok "good secret" PUT /svc/rfc2136/clients/$BADID "$(mk r.example.net example.net ddns-key "$KEY" '"ttl":120,"description":"router"')"
nl_ok "bad names, keys, algorithms, ports, families, zones and secrets are refused (400); nothing started"

echo "=== enable: the A record appears with the right TTL"
nl_api_ok "interval 5 s" PUT /svc/rfc2136 '{"enabled":true,"interval":5,"refresh":0,"timeout":10}'
nl_wait 10 pgrep -f '[r]fc2136 run' || { tail -20 "$NL_T/nl-web.log"; nl_fail "engine did not start"; }
want_dns r.example.net A "$NL_RTR_WAN" "A r.example.net = the WAN address $NL_RTR_WAN"
ttl=$(INET dig +noall +answer +time=2 +tries=1 @"$NS_IP" r.example.net A | awk '{print $2}')
[ "$ttl" -le 120 ] && [ "$ttl" -gt 0 ] || nl_fail "TTL is $ttl, want 120"
nl_ok "TTL from the client row (120)"
[ -z "$(dnsq r.example.net AAAA)" ] || nl_fail "family=ipv4 published an AAAA"

echo "=== secrets"
CONF=/var/lib/patronus/net/rfc2136.json
[ "$(stat -c %a "$CONF")" = 600 ] || nl_fail "engine config is mode $(stat -c %a "$CONF"), want 600"
nl_api GET /svc/rfc2136
! grep -F "$KEY" "$NL_OUT" >/dev/null || nl_fail "the API returned the TSIG secret"
grep -F '********' "$NL_OUT" >/dev/null || nl_fail "the API does not mask the secret"
patronus rfc2136 show --db "$DB" > "$NL_T/show.txt" 2>&1 || patronus --db "$DB" rfc2136 show > "$NL_T/show.txt" 2>&1 || true
! grep -F "$KEY" "$NL_T/show.txt" >/dev/null || nl_fail "patronus rfc2136 show printed the secret"
for p in /proc/[0-9]*/cmdline; do
  if tr '\0' ' ' < "$p" 2>/dev/null | grep -F "$KEY" >/dev/null; then nl_fail "TSIG secret on a command line ($p)"; fi
done
! grep -F "$KEY" "$NL_T/nl-web.log" >/dev/null || nl_fail "the web log holds the secret"
stats_file() { ls /var/lib/patronus/net/run/rfc2136.stats /run/patronus/rfc2136.stats 2>/dev/null | head -1 || true; }
nl_wait 20 test -n "$(stats_file)" || nl_fail "the engine wrote no status file"
STATS=$(stats_file); RUNDIR=$(dirname "$STATS")
ls "$RUNDIR" > "$NL_T/rundir.txt"
! grep rfc2136-key "$NL_T/rundir.txt" >/dev/null || nl_fail "a key file was left in $RUNDIR"
nl_ok "secret: masked in the API/show, mode 0600 engine file, never on a command line or in the log, no key file left behind"

echo "=== the address changes: the zone follows"
wan_renumber 203.0.113.9 $NL_RTR_WAN
want_dns r.example.net A "203.0.113.9" "renumbered WAN: A follows to 203.0.113.9"

echo "=== AAAA + TCP + SHA-512 on a second client"
R ip -6 addr add 2001:db8:2136::2/64 dev rtr-wan nodad
nl_api_ok "client 2" POST /svc/rfc2136/clients "$(mk v6.example.net example.net ddns-key512 "$KEY512" '"key_algo":"hmac-sha512","family":"both","tcp":true')"
want_dns v6.example.net A "203.0.113.9" "client 2 (hmac-sha512, TCP): A published"
want_dns v6.example.net AAAA "2001:db8:2136::2" "client 2: AAAA published (family both)"

echo "=== a wrong TSIG secret fails visibly and writes nothing"
nl_api_ok "client 3 (wrong secret)" POST /svc/rfc2136/clients "$(mk bad.example.net example.net ddns-key "$BADKEY")"
bad_failed() {
  python3 - "$STATS" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))['clients']
b = [v for v in c.values() if v['hostname'] == 'bad.example.net'][0]
sys.exit(0 if b['last_error'] and not b['ok'] and b['failures'] >= 1 else 1)
PY
}
nl_wait 60 bad_failed || { cat "$STATS"; nl_fail "the failing client is not reported in the status"; }
[ -z "$(dnsq bad.example.net A)" ] || nl_fail "an update signed with the wrong secret changed the zone"
[ "$(dnsq r.example.net A)" = 203.0.113.9 ] || nl_fail "the good client was disturbed by the failing one"
nl_api GET /svc/rfc2136
python3 - "$NL_OUT" <<'PY' || nl_fail "page status does not show the clients"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert st["clients"] == 3, st
PY
nl_ok "wrong secret: error in the status, nothing written, the other clients carry on"

echo "=== reboot: patronus apply brings it back"
nl_web_stop
nl_kill_daemons
pkill -f '[r]fc2136 run' || true
nl_wait 10 sh -c '! pgrep -f "[r]fc2136 run"' || nl_fail "engine survived the simulated reboot"
named_stop
nl_up
named_start
wan_renumber 203.0.113.5 $NL_RTR_WAN   # a different address after the "reboot"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_wait 10 pgrep -f '[r]fc2136 run' || nl_fail "engine not started by the boot apply"
want_dns r.example.net A "203.0.113.5" "after reboot the zone follows the new address"

echo "=== disable: engine stops"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/rfc2136 '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -f "[r]fc2136 run"' || nl_fail "engine still running"
wan_renumber 203.0.113.77 203.0.113.5
sleep 8
[ "$(dnsq r.example.net A)" = 203.0.113.5 ] || nl_fail "an update was sent after disabling"
nl_ok "disabled: engine stopped, no further updates"
nl_web_stop
echo "ALL RFC2136 CHECKS PASSED"
