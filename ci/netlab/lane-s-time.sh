#!/usr/bin/env bash
# Lane S (device segmentation), parental time limits: a time policy attached
# to a group cuts the LAN client's traffic outside its window and when the
# daily quota of ACTIVE minutes is used up, restores it when the window opens /
# a parent adds minutes / the day rolls over, warns before the cut, keeps
# DNS and the "time's up" page reachable while blocked (never SSH / the admin
# UI), and still blocks after a reboot (`patronus apply` recomputes the sets
# before the first forwarded packet). Time is moved with
# PATRONUS_FAKE_TIME_FILE; the ticker runs every second.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-time.db
FAKE=$NL_T/nl-fake-time
export PATRONUS_FAKE_TIME_FILE=$FAKE PATRONUS_TIME_TICK_SECS=1
rm -f "$DB" "$NL_T/nl-jar"
# The limited LAN client must NOT reach the admin UI, so the test drives the API from the
# router's own namespace (loopback) instead of from the LAN client.
NL_UI=https://127.0.0.1:8443
nl_web() {
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  NL_CODE=$(R curl -sk -m 60 -b "$NL_T/nl-jar" -c "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' \
    -X "$1" -H 'content-type: application/json' "${data[@]}" "$NL_UI$2")
}
web_start() { # DB
  env PATRONUS_DB="$1" PATRONUS_BOOTSTRAP="$NL_TOML" PATRONUS_ADMIN_PASSWORD="$NL_PASS" \
      PATRONUS_ADMIN_PASSWORD_FILE=$NL_T/nl-pw PATRONUS_TLS_DIR=$NL_T/nl-tls RUST_LOG=info \
      ip netns exec nl-rtr "$WEB" >>"$NL_T/nl-web.log" 2>&1 &
  NL_WEB_PID=$!
  for _ in $(seq 1 60); do R curl -sk -o /dev/null "$NL_UI/login" && { rm -f "$NL_T/nl-jar"; return 0; }; sleep 0.5; done
  tail -50 "$NL_T/nl-web.log"; nl_fail "patronus-web did not come up"
}
tcp_open() { C python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 2)" "$1" "$2" 2>/dev/null; }
clock() { echo "$1" > "$FAKE"; }
clock "2026-10-12 15:00"   # a Monday
nl_write_installer_toml
nl_boot "$DB"

MAC=$(ip -n nl-client -br link show lan0 | awk '{print $3}')
# stand-ins on the router: a DNS server on :53 and the admin ports (22 exists)
nl_bg R dnsmasq --no-daemon --no-resolv --no-hosts --user=root --bind-interfaces \
  --listen-address=$NL_RTR_LAN --pid-file=/tmp/nl-rtr-dns.pid --address=/foo.test/10.9.9.9
sleep 0.5
dns_to_router() {
  C python3 - <<'EOF'
import socket
q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03foo\x04test\x00\x00\x01\x00\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(q, ('192.168.50.1', 53)); d = s.recv(512); print(socket.inet_ntoa(d[-4:]))
EOF
}

web_start "$DB"; nl_login
# group + device through the foundation's API (what the Segmentation page sends)
nl_api_ok "create group kids" POST /segmentation/groups '{"name":"kids"}'
nl_api_ok "enrol the tablet" POST /segmentation/devices "{\"name\":\"tablet\",\"mac\":\"$MAC\",\"group\":\"kids\",\"kind\":\"wifi\",\"segment\":\"@lan\",\"ip4\":\"$NL_CLIENT\"}"
nl_ok "device tablet ($MAC, $NL_CLIENT) enrolled in group kids"
nl_expect_http "no policy yet: LAN -> internet works" "http://$NL_WWW:8080/" "sees $NL_RTR_WAN"

# --- policy: windows 16:00-20:00 every day, quota 3 active minutes, warn 1 min before
nl_api_ok "create policy" POST /segmentation/time/policies \
  '{"name":"school","daily_limit_minutes":3,"reset_hour":6,"active_bytes_per_min":100,"grace_minutes":1,"allow_dns":true,
    "windows":[{"days":["mon","tue","wed","thu","fri","sat","sun"],"start":"16:00","end":"20:00"}]}'
PID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_code "bad window rejected" 400 POST /segmentation/time/policies '{"name":"bad","windows":[{"days":["funday"],"start":"16:00","end":"20:00"}]}'
nl_api_code "bad name rejected" 400 POST /segmentation/time/policies '{"name":"x;flush ruleset"}'
GID=$(sqlite3 -cmd ".timeout 8000" "$DB" "SELECT id FROM seg_groups WHERE name='kids'")
nl_api_ok "attach to group kids" POST /segmentation/time/assign "{\"kind\":\"group\",\"id\":$GID,\"policy_id\":$PID}"

tablet() { # "state/reason/used" of the tablet from the API
  nl_api GET /segmentation/time/usage
  nl_json "$NL_OUT" "[u['state']+'/'+u['reason']+'/'+str(u['used_minutes']) for u in d['usage'] if u['device']=='tablet'][0]" 2>/dev/null || echo "none: $(cat "$NL_OUT")"
}
state() { tablet | cut -d/ -f1-2; }
blocked_in_kernel() { local o; o=$(R nft list set inet patronus_time blocked_v4 2>/dev/null) || return 1; grep -q "$NL_CLIENT" <<<"$o"; }
wait_state() { # WANT (state): the API says so AND the ticker has moved the kernel set
  for _ in $(seq 1 60); do
    case "$(tablet)" in
      "$1"/*)
        if [ "$1" = blocked ]; then blocked_in_kernel && return 0; else blocked_in_kernel || return 0; fi ;;
    esac
    sleep 0.5
  done
  nl_fail "state never became $1: $(tablet); set: $(R nft list set inet patronus_time blocked_v4 2>&1 | tr '\n' ' ')"
}
used() { tablet | cut -d/ -f3; }
page() { C curl -s -m 5 "http://$NL_WWW/"; }   # port 80: redirected to the page while limited
wait_page() { # PATTERN: the redirected page shows PATTERN within 10 s (the ticker has to add the element)
  for _ in $(seq 1 20); do page | grep -q "$1" && return 0; sleep 0.5; done
  nl_fail "page never showed '$1': $(page)"
}
blocked_traffic() { nl_expect_no_tcp "$1" C $NL_WWW 9000; nl_expect_http_blocked "$1 (http 8080)" "http://$NL_WWW:8080/"; }

# --- 1. outside the window (15:00): cut
wait_state blocked
nl_ok "15:00 is outside 16:00-20:00: state $(state)"
blocked_traffic "15:00 outside the window"
nl_assert_nft_has "table inet patronus_time" "ip saddr @blocked_v4"
blocked_in_kernel || nl_fail "client not in blocked_v4: $(R nft list set inet patronus_time blocked_v4)"
nl_ok "client address is an element of inet patronus_time blocked_v4"
[ "$(dns_to_router)" = 10.9.9.9 ] || nl_fail "DNS to the router must keep working while blocked"
nl_ok "DNS (router :53) still answers while blocked"
nl_expect_no_tcp "blocked device -> router SSH (admin ports stay shut)" C $NL_RTR_LAN 22
if tcp_open $NL_RTR_LAN 8443; then nl_fail "blocked device reaches the admin UI on 8443"; fi
nl_ok "blocked device -> router web UI :8443 refused"
tcp_open $NL_RTR_LAN 8081 || nl_fail "blocked device cannot reach the time's-up page port 8081"
nl_ok "blocked device -> router :8081 (time's-up page) open"
nl_ok "ping router while blocked: $(C ping -c1 -W2 $NL_RTR_LAN >/dev/null 2>&1 && echo ok || echo FAIL)"
C ping -c1 -W2 $NL_RTR_LAN >/dev/null 2>&1 || nl_fail "ICMP to the router must keep working"
P1=$(page); grep -q "Time's up" <<<"$P1" || nl_fail "HTTP of a blocked device is not redirected to the time's-up page: $P1"
grep -q "switched off" <<<"$P1" && grep -q "16:00" <<<"$P1" || nl_fail "page lacks the reason / resume time: $P1"
nl_ok "plain HTTP of the blocked tablet shows the time's-up page (window, back at 16:00)"
C curl -s -m 5 -o /dev/null -w '%{http_code}' "http://connectivitycheck.gstatic.com/generate_204" --resolve connectivitycheck.gstatic.com:80:$NL_WWW > "$NL_OUT" || true
[ "$(cat "$NL_OUT")" = 200 ] || nl_fail "Android probe must not see 204 while blocked: $(cat "$NL_OUT")"
nl_ok "Android connectivity probe gets 200 (not 204): the phone opens the page by itself"

# --- 2. the window opens (16:00): restored
clock "2026-10-12 16:00"
wait_state ok
nl_expect_http "16:00 inside the window: restored" "http://$NL_WWW:8080/" "sees $NL_RTR_WAN"
if blocked_in_kernel; then nl_fail "client still in blocked_v4"; fi
tcp_open $NL_RTR_LAN 8443 || nl_fail "restored device cannot reach the admin UI again"
nl_ok "client address removed from blocked_v4 (no firewall reload: ruleset table patronus untouched)"

# --- 3. quota: 3 active minutes (>100 B/min) at 16:00 .. 16:02, idle minute does not count
active_minute() { # HH:MM
  clock "2026-10-12 $1"; sleep 1.6
  for _ in 1 2 3; do C curl -s -m 3 -o /dev/null "http://$NL_WWW:8080/" || true; done
  sleep 1.6   # let the ticker poll the counters before the minute ends
}
active_minute 16:01
sleep 1.6   # 16:00's traffic (the restore check above) is polled
clock "2026-10-12 16:02"; sleep 1.6   # closes 16:01 (traffic): 16:00 and 16:01 were active
[ "$(used)" = 2 ] || nl_fail "expected 2 active minutes so far, got $(used)"
clock "2026-10-12 16:03"; sleep 1.6   # 16:02 had no traffic: closed, not counted
[ "$(used)" = 2 ] || nl_fail "an idle minute was counted: $(used)"
nl_ok "two active minutes counted (16:00, 16:01); the idle minute 16:02 was not"

# bring the quota to the limit with traffic in consecutive minutes
M=4
while :; do
  S=$(state)
  case "$S" in blocked/quota) break ;; esac
  [ $M -le 12 ] || nl_fail "quota never ran out: $S $(cat "$NL_OUT")"
  # warning: when 1 minute is left, plain HTTP shows the grace page
  if [ "$S" = "warn/" ] && [ -z "${WARNED:-}" ]; then
    wait_page "minute left"; PW=$(page)
    nl_ok "grace warning: HTTP of the tablet shows '$(grep -o '[0-9]* minute[s]* left' <<<"$PW" | head -1)'"
    WARNED=1
  fi
  active_minute "16:$(printf %02d $M)"; M=$((M+1))
done
[ -n "${WARNED:-}" ] || nl_fail "never saw the grace warning (state warn)"
wait_state blocked
nl_ok "quota used up: $(state) after $((M-3)) active minutes"
blocked_traffic "quota used"
PQ=$(page); grep -q "used up" <<<"$PQ" && grep -q "06:00" <<<"$PQ" || nl_fail "quota page: $PQ"
nl_ok "page says today's time is used up, back at 06:00"
[ "$(used)" = 3 ] || nl_fail "usage is not 3: $(tablet)"

# --- 4. parent actions
DEV=$(sqlite3 -cmd ".timeout 8000" "$DB" "SELECT id FROM seg_devices WHERE name='tablet'")
nl_api_ok "+10 minutes today" POST /segmentation/devices/$DEV/time/bonus '{"minutes":10}'
wait_state ok
nl_expect_http "bonus minutes restore access" "http://$NL_WWW:8080/" "sees $NL_RTR_WAN"
nl_api_code "bonus 0 rejected" 400 POST /segmentation/devices/$DEV/time/bonus '{"minutes":0}'
nl_api_ok "pause internet now" POST /segmentation/devices/$DEV/time/pause '{}'
wait_state blocked
blocked_traffic "paused by a parent"
grep -q "paused" <(page) || nl_fail "page does not say paused"
nl_api_ok "resume" POST /segmentation/devices/$DEV/time/resume '{}'
wait_state ok
nl_expect_http "resume restores access" "http://$NL_WWW:8080/" "sees $NL_RTR_WAN"

# --- 5. the window closes (20:00), with a warning at 19:59
clock "2026-10-12 19:59"; wait_state warn
wait_page "minute left"
nl_ok "19:59: one minute before the window ends the page warns"
R nft delete element inet patronus_time warn_v4 "{ $NL_CLIENT }" 2>/dev/null || true
clock "2026-10-12 20:00"; wait_state blocked
blocked_traffic "20:00 window closed"

# --- 6. next day: the quota is fresh
clock "2026-10-13 16:00"; wait_state ok
nl_expect_http "next day inside the window: fresh quota" "http://$NL_WWW:8080/" "sees $NL_RTR_WAN"

# --- 7. a reboot keeps the block: usage is in the store, apply recomputes the sets
clock "2026-10-13 15:00"; wait_state blocked
nl_web_stop
nl_boot "$DB"          # fresh namespaces + `patronus apply`, no web, no ticker
grep -q "time limits: 1 device(s) with a policy, 1 blocked now" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "apply did not report the blocked device"; }
blocked_in_kernel || nl_fail "after the reboot the client is not blocked: $(R nft list ruleset)"
nl_ok "after a reboot, patronus apply blocked the tablet before any web or ticker ran"
nl_expect_no_tcp "after reboot, before the web UI: tablet is cut" C $NL_WWW 9000

# --- 8. policy deleted: unlimited again
web_start "$DB"; nl_login
nl_api_ok "delete the policy" DELETE /segmentation/time/policies/$PID
for _ in $(seq 1 30); do nl_api GET /segmentation/time/usage; [ "$(nl_json "$NL_OUT" "len(d['usage'])")" = 0 ] && break; sleep 0.5; done
[ "$(nl_json "$NL_OUT" "len(d['usage'])")" = 0 ] || nl_fail "usage not empty after deleting the policy: $(cat "$NL_OUT")"
nl_expect_http "no policy: online again" "http://$NL_WWW:8080/" "sees $NL_RTR_WAN"

nl_web_stop
echo "PASS lane-s-time"
