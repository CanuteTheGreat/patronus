#!/usr/bin/env bash
# Lane B: the firewall log viewer, proven with real packets.
#   rules with Log ticked log to NFLOG; patronus-web collects them into the
#   store and the API searches them: attribution to the rule (id + name),
#   filters, live cursor, threat-feed hits ("feed:<id>"), default-deny
#   logging, history that survives a restart of patronus-web, clearing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-fwlog.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
export PATRONUS_FEEDS_DIR=/t/fwlog-feeds
FEEDS=/t/fwlog-www
rm -rf "$FEEDS" "$PATRONUS_FEEDS_DIR"; mkdir -p "$FEEDS"

api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
# logs QUERY MIN: poll until at least MIN lines match (the collector writes once a second)
logs() {
  local end=$((SECONDS + 25)) n=0
  while [ "$SECONDS" -lt "$end" ]; do
    nl_api GET "/firewall/logs?$1"
    n=$(jget 'len(d["entries"])')
    [ "$n" -ge "${2:-1}" ] && return 0
    sleep 0.5
  done
  cat "$NL_OUT"; tail -5 "$NL_T/nl-web.log"
  nl_fail "log query '$1' returned $n line(s), wanted at least ${2:-1}"
}
rule() { # NAME ACTION DST
  echo "{\"name\":\"$1\",\"chain\":\"forward\",\"action\":\"$2\",\"interface\":\"@lan\",\"protocol\":\"tcp\",\"source\":\"any\",\"destination\":\"$3\",\"port\":\"9000\",\"description\":\"$1\",\"log\":true,\"enabled\":true}"
}

nl_boot "$DB"
ip netns exec nl-inet python3 -m http.server 8099 --bind $NL_WWW --directory "$FEEDS" >/t/feedsrv.log 2>&1 &
NL_PIDS+=($!)
nl_web_start "$DB"; nl_login

echo "=== collector"
for _ in $(seq 1 20); do
  nl_api GET "/firewall/logs"
  [ "$(jget 'd["collector"]["running"]')" = True ] && break; sleep 0.5
done
[ "$(jget 'd["collector"]["running"]')" = True ] || nl_fail "the NFLOG collector is not running: $(cat "$NL_OUT")"
nl_ok "the NFLOG collector is running"
[ "$(jget 'len(d["entries"])')" = 0 ] || nl_fail "a fresh box has log lines"

echo "=== a logging rule is attributed"
api_ok POST /firewall/rules "$(rule log-drop-9000 drop $NL_WWW)"
nl_api GET /firewall/rules
RID=$(python3 -c 'import json,sys; print([r["id"] for r in json.load(open(sys.argv[1])) if r["name"]=="log-drop-9000"][0])' "$NL_OUT")
nl_assert_nft_has "log prefix \"patronus[$RID] drop: \" group 7"
nl_expect_no_tcp "LAN -> $NL_WWW:9000 dropped" C $NL_WWW 9000
logs "rule=log-drop-9000" 1
E=$(python3 -c 'import json,sys; e=json.load(open(sys.argv[1]))["entries"][0]; print(e["rule_id"], e["rule"], e["action"], e["chain"], e["iface_in"], e["iface_out"], e["proto"], e["src"], e["sport"] is not None, e["dst"], e["dport"])' "$NL_OUT")
[ "$E" = "$RID log-drop-9000 drop forward $NL_LAN_IF $NL_WAN_IF TCP $NL_CLIENT True $NL_WWW 9000" ] || nl_fail "log line: $E"
nl_ok "line attributed: rule #$RID log-drop-9000, drop, forward $NL_LAN_IF -> $NL_WAN_IF, TCP $NL_CLIENT -> $NL_WWW:9000"

echo "=== accept rules log too"
api_ok POST /firewall/rules "$(rule log-accept-9000 accept $NL_BLOCKED)"
nl_expect_tcp "LAN -> $NL_BLOCKED:9000 allowed" C $NL_BLOCKED 9000
logs "action=accept&rule=log-accept" 1
[ "$(jget 'd["entries"][0]["dst"]')" = $NL_BLOCKED ] || nl_fail "accept line: $(cat "$NL_OUT")"
nl_ok "an accept rule's connection is logged as accept"

echo "=== search filters"
logs "rule=$RID" 1
logs "src=192.168.50.&dst=198.51.100.&port=9000&proto=tcp&iface=$NL_LAN_IF&minutes=5" 2
logs "q=log-drop" 1
for q in "rule=nope" "action=reject" "src=10.1." "port=9001" "proto=udp" "dst=198.51.100.99" "q=%25"; do
  nl_api GET "/firewall/logs?$q"
  [ "$(jget 'len(d["entries"])')" = 0 ] || nl_fail "filter $q should match nothing: $(cat "$NL_OUT")"
done
nl_api GET "/firewall/logs?q=%27%20OR%201%3D1%20--"
[ "$NL_CODE" = 200 ] && [ "$(jget 'len(d["entries"])')" = 0 ] || nl_fail "odd characters in a filter: $NL_CODE"
nl_ok "rule / action / source / destination / port / proto / interface / text / minutes filters combine; non-matching filters return nothing"

echo "=== live: only lines newer than the cursor"
nl_api GET /firewall/logs
CUR=$(jget 'd["last_id"]')
nl_expect_no_tcp "another attempt" C $NL_WWW 9000
logs "since_id=$CUR" 1
[ "$(jget 'min(e["id"] for e in d["entries"])')" -gt "$CUR" ] || nl_fail "since_id returned old lines"
nl_ok "since_id=$CUR returns only the new line(s) ($(jget 'len(d["entries"])'))"

echo "=== threat-feed hits are attributed to the feed"
printf '%s ; SBL1\n' $NL_BLOCKED > "$FEEDS/drop.txt"
for _ in $(seq 1 30); do INET curl -s -m 2 -o /dev/null "http://$NL_WWW:8099/" && break; sleep 0.2; done
api_ok PUT /firewall/threatintel/labfeed "{\"enabled\":true,\"url\":\"http://$NL_WWW:8099/drop.txt\",\"direction\":\"out\"}"
nl_wait 40 bash -c "R nft list chain inet patronus ti_check 2>/dev/null | grep -q labfeed" || nl_fail "the feed rules never appeared"
# the user's accept rule for the same host comes later: the feed wins and is the line's rule
nl_expect_no_tcp "LAN -> $NL_BLOCKED:9000 dropped by the feed" C $NL_BLOCKED 9000
logs "rule=feed:labfeed" 1
[ "$(jget 'd["entries"][0]["action"]')" = drop ] && [ "$(jget 'd["entries"][0]["rule_id"]')" = None ] || nl_fail "feed line: $(cat "$NL_OUT")"
nl_ok "feed hit logged as rule 'feed:labfeed' (drop)"

echo "=== default deny"
nl_expect_no_tcp "WAN -> router :22 (nothing allows it)" ISP $NL_RTR_WAN 22
nl_api GET "/firewall/logs?rule=default"
[ "$(jget 'len(d["entries"])')" = 0 ] || nl_fail "default-deny lines before the switch is on"
api_ok PUT /firewall/logs/default-deny '{"enabled":true}'
nl_assert_nft_has 'patronus[default] drop'
nl_expect_no_tcp "WAN -> router :22 again" ISP $NL_RTR_WAN 22
logs "rule=default" 1
E=$(python3 -c 'import json,sys; e=json.load(open(sys.argv[1]))["entries"][0]; print(e["rule"], e["chain"], e["iface_in"], e["src"], e["dport"])' "$NL_OUT")
[ "$E" = "default deny input $NL_WAN_IF 203.0.113.1 22" ] || nl_fail "default-deny line: $E"
nl_ok "default-deny drops are logged: $E"
api_ok PUT /firewall/logs/default-deny '{"enabled":false}'
nl_assert_nft_lacks 'patronus[default] drop'

echo "=== history survives a restart of patronus-web; the page has the viewer"
nl_api GET /firewall/logs
BEFORE=$(jget 'len(d["entries"])')
nl_web_stop; nl_web_start "$DB"; nl_login
nl_api GET /firewall/logs
[ "$(jget 'len(d["entries"])')" = "$BEFORE" ] && [ "$BEFORE" -ge 4 ] || nl_fail "history after restart: $(jget 'len(d["entries"])') lines, had $BEFORE"
nl_ok "$BEFORE stored lines are still there after a restart"
nl_web GET /firewall
for want in 'id="log-table"' 'id="log-filter"' 'logSearch' 'log-live'; do grep -q "$want" "$NL_OUT" || nl_fail "page lacks $want"; done
nl_ok "the Firewall page's Logs tab has the filter form, table and Live switch"

echo "=== clear"
api_ok DELETE /firewall/logs
nl_api GET /firewall/logs
[ "$(jget 'len(d["entries"])')" = 0 ] || nl_fail "log not cleared"
nl_ok "the stored log can be cleared"
nl_web_stop
nl_down
