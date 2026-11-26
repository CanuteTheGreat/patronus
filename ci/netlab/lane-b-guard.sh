#!/usr/bin/env bash
# Lane B: brute-force protection (patronus_firewall::guard, docs/BRUTE-FORCE.md) on the real binaries,
# with real OpenSSH logins, the real web login API, nftables and real traffic.
#
# Proves:
#   - on for a new install (seeded at first boot): the inet patronus_guard table exists after `patronus apply`;
#   - settings through the API: the table keeps both ban sets;
#   - a LAN address is never banned while "never ban my own networks" is on, however often it fails;
#   - with it off, real failed SSH password logins (sshd writing its own log) ban the client after
#     the threshold: the address is in the kernel set, the drop counter grows, the client can no
#     longer reach the router at all; `patronus guard unban` gives access back at once;
#   - failed web UI logins are counted the same way (the web UI reports them) and ban too;
#   - repeat offenders get a longer ban (offence 2 = twice the first ban);
#   - a manual IPv6 ban covers the /64; invalid settings are refused with 400;
#   - bans survive a reboot (patronus apply rebuilds the table from the store);
#   - turning the protection off removes the table.
set -euo pipefail
set -E
trap 'echo "lane-b-guard: failed at line $LINENO" >&2' ERR
. "$(dirname "$0")/lib.sh"

command -v sshd >/dev/null && command -v ssh >/dev/null || { echo "SKIP lane-b-guard: openssh not installed"; exit 0; }
DB=/t/lane-b-guard.db
rm -f "$DB" "$NL_T/nl-jar"
LOG=/t/guard-sshd.log
K=/t/guard-keys; rm -rf "$K"; mkdir -p "$K" /run/sshd
SSHD=$(command -v sshd)
export PATRONUS_GUARD_TICK_SECS=1
nl_write_installer_toml

cleanup() {
  set +e
  [ -f /run/guard-sshd.pid ] && kill "$(cat /run/guard-sshd.pid)" 2>/dev/null
  nl_web_stop
}
trap cleanup EXIT

guard_table() { R nft list table inet patronus_guard 2>/dev/null || true; }
in_set() { # SET ELEMENT: the element is in the live set
  guard_table > /t/guard-table.txt
  python3 - "$1" "$2" /t/guard-table.txt <<'EOF'
import re, sys
text = open(sys.argv[3]).read()
m = re.search(r"set %s \{(.*?)\n\t\}" % re.escape(sys.argv[1]), text, re.S)
sys.exit(0 if m and re.search(r"(^|[\s{,])%s([\s,}]|$)" % re.escape(sys.argv[2]), m.group(1)) else 1)
EOF
}
dropped() { # drop counter packets of the guard rules
  guard_table | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | awk '{s+=$1} END {print s+0}'
}
wait_in_set() { # SET ELEMENT DESC
  for _ in $(seq 1 30); do in_set "$1" "$2" && { nl_ok "$3"; return 0; }; sleep 0.5; done
  guard_table; tail -20 "$NL_T/nl-web.log"; nl_fail "$3: $2 not in $1"
}
ssh_fail() { # N: N failed password logins from the LAN client (one guess per connection)
  printf '#!/bin/sh\necho wrong-password\n' > /t/guard-askpass; chmod +x /t/guard-askpass
  for _ in $(seq 1 "$1"); do
    C env SSH_ASKPASS=/t/guard-askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 ssh -n \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=4 \
      nosuchuser@$NL_RTR_LAN true </dev/null >/dev/null 2>&1 || true
  done
}
web_fail() { # N failed web logins from the LAN client (own cookie jar)
  for _ in $(seq 1 "$1"); do
    C curl -sk -m 5 -o /dev/null -H 'content-type: application/json' \
      -d '{"username":"admin","password":"not-the-password"}' "$NL_UI/api/auth/login" || true
  done
}

# --- boot: a new install has it on --------------------------------------------------------------------
nl_boot "$DB"
grep -q 'set ban4' <<<"$(guard_table)" || nl_fail "new install: no inet patronus_guard table after the first boot"
[ "$(sqlite3 "$DB" "SELECT value FROM system_config WHERE key='guard.enabled'")" = 1 ] || nl_fail "guard.enabled not seeded"
nl_ok "new install: brute-force protection is on after the first boot (table inet patronus_guard)"

# a real sshd in the router namespace, writing its own log (the stand-in on :22 makes room)
pkill -f '[n]l-tcp.py 0.0.0.0 22$' || true
ssh-keygen -q -t ed25519 -N '' -f "$K/host"
: > "$LOG"
R "$SSHD" -E "$LOG" -h "$K/host" -p 22 -o ListenAddress=$NL_RTR_LAN -o PasswordAuthentication=yes \
  -o KbdInteractiveAuthentication=no -o UsePAM=no -o PidFile=/run/guard-sshd.pid -o MaxStartups=100
for _ in $(seq 1 40); do C sh -c "exec 3<>/dev/tcp/$NL_RTR_LAN/22" 2>/dev/null && break; sleep 0.25; done

nl_web_start "$DB"
nl_login

# --- on, with LAN exemption (the default) ---------------------------------------------------------------
nl_api PUT /guard/settings "{\"enabled\":true,\"max_failures\":3,\"find_secs\":300,\"ban_secs\":120,\"ban_max_secs\":3600,\"log_files\":[\"$LOG\"],\"journal\":\"off\"}"
[ "$NL_CODE" = 200 ] || nl_fail "enable: $NL_CODE $(cat "$NL_OUT")"
T=$(guard_table)
grep -q 'set ban4' <<<"$T" && grep -q 'set ban6' <<<"$T" || nl_fail "no ban sets: $T"
nl_ok "settings through the API: table inet patronus_guard with ban4 and ban6"
nl_api PUT /guard/settings '{"max_failures":0}'
[ "$NL_CODE" = 400 ] || nl_fail "max_failures 0 accepted ($NL_CODE)"
nl_api PUT /guard/settings '{"allowlist":["10.0.0.0/33"]}'
[ "$NL_CODE" = 400 ] || nl_fail "bad allow-list accepted ($NL_CODE)"
nl_ok "invalid settings are refused with 400"

ssh_fail 4
grep -q 'Failed password for invalid user nosuchuser from 192.168.50.10' "$LOG" || { cat "$LOG"; nl_fail "sshd logged no failed password"; }
sleep 3
in_set ban4 $NL_CLIENT && nl_fail "LAN client banned although LAN addresses are exempt"
nl_api GET /guard
[ "$(nl_json "$NL_OUT" 'len(d["active"])')" = 0 ] || nl_fail "active bans with exempt LAN: $(cat "$NL_OUT")"
nl_ok "4 failed SSH logins from the LAN: never banned while my own networks are exempt"

# --- LAN exemption off: real SSH failures ban -----------------------------------------------------------
nl_api PUT /guard/settings '{"exempt_lan":false}'
[ "$NL_CODE" = 200 ] || nl_fail "exempt_lan off: $NL_CODE"
ssh_fail 2
sleep 2
in_set ban4 $NL_CLIENT && nl_fail "banned below the threshold"
ssh_fail 1
wait_in_set ban4 $NL_CLIENT "3 failed SSH logins -> the client's address is in the kernel ban set"
before=$(dropped)
C curl -sk -m 3 -o /dev/null "$NL_UI/login" && nl_fail "banned client still reaches the web UI"
C ping -c1 -W2 $NL_RTR_LAN >/dev/null 2>&1 && nl_fail "banned client still pings the router"
[ "$(dropped)" -gt "$before" ] || nl_fail "drop counter did not grow ($before -> $(dropped))"
nl_ok "banned client reaches nothing on the router, the drop counter grows ($before -> $(dropped))"
OUT=$(R "$P" --db "$DB" guard status)
grep -q "$NL_CLIENT" <<<"$OUT" && grep -q 'failed SSH logins' <<<"$OUT" || nl_fail "guard status: $OUT"
nl_ok "patronus guard status names the ban and why"
R "$P" --db "$DB" guard unban $NL_CLIENT >/dev/null
in_set ban4 $NL_CLIENT && nl_fail "still in the set after unban"
C curl -sk -m 5 -o /dev/null "$NL_UI/login" || nl_fail "web UI unreachable after unban"
nl_ok "patronus guard unban: access is back at once"

# --- repeat offender: the second ban is twice as long ----------------------------------------------------
ssh_fail 3
wait_in_set ban4 $NL_CLIENT "a second round of failures bans again"
R "$P" --db "$DB" guard status --json > /t/guard-st.json
python3 - /t/guard-st.json <<'EOF' || nl_fail "second ban is not offence 2 / 240 s"
import json, sys
d = json.load(open(sys.argv[1]))
b = [x for x in d["active"] if x["address"] == "192.168.50.10"][0]
assert b["offence"] == 2, b
assert 230 <= b["expires_at"] - b["banned_at"] <= 240, b
EOF
nl_ok "repeat offender: offence 2 lasts 240 s (twice the first ban)"
R "$P" --db "$DB" guard unban $NL_CLIENT >/dev/null

# --- web UI failures ban too -------------------------------------------------------------------------------
nl_login
nl_api PUT /guard/settings '{"sources":["web"]}'
[ "$NL_CODE" = 200 ] || nl_fail "sources web: $NL_CODE"
ssh_fail 3
sleep 3
in_set ban4 $NL_CLIENT && nl_fail "SSH failures banned although only the web UI source is on"
nl_ok "a source that is switched off is not counted"
web_fail 3
wait_in_set ban4 $NL_CLIENT "3 failed web UI logins -> banned"
R "$P" --db "$DB" guard status --json > /t/guard-st.json
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert any(b["source"]=="web" for b in d["active"]), d' /t/guard-st.json \
  || nl_fail "web ban not recorded as source web"
R "$P" --db "$DB" guard unban $NL_CLIENT >/dev/null

# --- manual bans, IPv6 prefix, reboot ---------------------------------------------------------------------
nl_login
nl_api POST /guard/bans '{"address":"203.0.113.1","secs":3600,"reason":"lab ISP"}'
[ "$NL_CODE" = 201 ] || nl_fail "manual ban: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /guard/bans '{"address":"2001:db8:1:2::5","reason":"v6 scanner"}'
[ "$NL_CODE" = 201 ] || nl_fail "manual v6 ban: $NL_CODE $(cat "$NL_OUT")"
[ "$(nl_json "$NL_OUT" 'd["address"]')" = "2001:db8:1:2::/64" ] || nl_fail "v6 ban key: $(cat "$NL_OUT")"
wait_in_set ban6 2001:db8:1:2::/64 "a manual IPv6 ban covers the /64"
wait_in_set ban4 203.0.113.1 "a manual ban from the API is in the kernel set"
before=$(dropped)
ISP ping -c2 -W1 $NL_RTR_WAN >/dev/null 2>&1 || true
[ "$(dropped)" -gt "$before" ] || nl_fail "WAN-side packets from the banned ISP address were not dropped by the guard"
nl_ok "packets from a banned WAN address are dropped by the guard table"
nl_api POST /guard/bans '{"address":"127.0.0.1"}'
[ "$NL_CODE" = 400 ] || nl_fail "loopback ban accepted ($NL_CODE)"

nl_web_stop
kill "$(cat /run/guard-sshd.pid)" 2>/dev/null || true
rm -f /run/guard-sshd.pid
nl_boot "$DB"
in_set ban4 203.0.113.1 || { guard_table; nl_fail "ban lost across the reboot"; }
in_set ban6 2001:db8:1:2::/64 || nl_fail "IPv6 ban lost across the reboot"
grep -Eq '203\.0\.113\.1 (timeout|expires)' <<<"$(guard_table)" || nl_fail "rebooted ban has no timeout: $(guard_table)"
nl_ok "reboot: patronus apply rebuilds the table, bans keep their remaining time"

# --- off removes the table ---------------------------------------------------------------------------------
nl_web_start "$DB"
nl_login
nl_api PUT /guard/settings '{"enabled":false}'
[ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE"
[ -z "$(guard_table)" ] || nl_fail "table still there after turning off"
nl_ok "turned off: the table is gone"
nl_web_stop
echo "lane-b-guard: all checks passed"
