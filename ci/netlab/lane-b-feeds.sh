#!/usr/bin/env bash
# Lane B: self-filling aliases, proven with real traffic through the kernel.
#   1. URL table alias (pfSense "URL Table"): entries come from a list served
#      on the internet host; a rule on the alias blocks; changing the list
#      and refreshing swaps the nft set live (no ruleset reload); a dead
#      feed keeps the old entries and the status says why; the periodic
#      task refreshes a due alias by itself.
#   2. GeoIP: a DB-IP style country database (served locally) -> a country
#      set alias -> one block rule; the lookup box; reboot with the network
#      to the feed down still enforces (entries are stored).
#   3. Threat intelligence: a Spamhaus-DROP-format feed. Its addresses are
#      dropped ahead of user rules, private ranges the feed lists are NOT
#      blocked (the LAN stays reachable), ti_allow exempts a host, a
#      per-feed entry cap truncates, a failing feed keeps its old list.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-feeds.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
export PATRONUS_FEEDS_DIR=/t/feeds-state PATRONUS_FEEDS_TICK_SECS=2
rm -rf "$PATRONUS_FEEDS_DIR"
FEEDS=/t/feeds-www
rm -rf "$FEEDS"; mkdir -p "$FEEDS"
FEED_URL=http://$NL_WWW:8099

api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
# wait_status ALIAS WORD [SECS]: the alias's last refresh status contains WORD
wait_status() {
  local end=$((SECONDS + ${3:-40})) st=
  while [ "$SECONDS" -lt "$end" ]; do
    nl_api GET "/firewall/aliases/$1"
    st=$(jget 'd.get("source",{}).get("last_status") or ""' 2>/dev/null || true)
    case "$st" in *"$2"*) return 0;; esac
    sleep 0.5
  done
  nl_fail "alias $1: status never contained '$2' (last: '$st')"
}
drop_rule() { # NAME DESTINATION
  echo "{\"name\":\"$1\",\"chain\":\"forward\",\"action\":\"drop\",\"interface\":\"@lan\",\"protocol\":\"any\",\"source\":\"any\",\"destination\":\"$2\",\"port\":\"any\",\"description\":\"$1\",\"enabled\":true}"
}
reach() { nl_expect_tcp "$1" C "$2" 9000; }
blocked() { nl_expect_no_tcp "$1" C "$2" 9000; }
start_feed_server() {
  ip netns exec nl-inet python3 -m http.server 8099 --bind 0.0.0.0 --directory "$FEEDS" >/t/feedsrv.log 2>&1 &
  NL_PIDS+=($!)
  for _ in $(seq 1 50); do INET curl -s -m 2 -o /dev/null "$FEED_URL/" && return 0; sleep 0.2; done
  cat /t/feedsrv.log; INET ss -ltn || true
  nl_fail "the feed server did not start"
}
stop_feed_server() {
  # (nl_down kill()s every pid it tracked and `set -e` stops on a dead one:
  # forget the feed server's pid once it is gone)
  local pids p live=()
  pids=$(pgrep -f 'http[.]server 8099' || true)
  # shellcheck disable=SC2086
  [ -z "$pids" ] || kill $pids
  for p in $pids; do wait "$p" 2>/dev/null || true; done
  for p in "${NL_PIDS[@]}"; do kill -0 "$p" 2>/dev/null && live+=("$p"); done
  NL_PIDS=("${live[@]}")
  pgrep -f 'http[.]server 8099' >/dev/null && nl_fail "the feed server did not stop"
  return 0
}
setdump() { R nft list set inet patronus "$1"; }

nl_boot "$DB"
start_feed_server
nl_web_start "$DB"; nl_login
reach "baseline: LAN -> $NL_BLOCKED:9000 is reachable" $NL_BLOCKED

echo "=== 1. URL table alias"
printf '# my blocklist\n%s\n\n203.0.113.250\nnot an address\n' $NL_BLOCKED > "$FEEDS/list.txt"
api_ok POST /firewall/aliases "{\"name\":\"urlbad\",\"type\":\"urltable\",\"entries\":[],\"source\":{\"kind\":\"url\",\"url\":\"$FEED_URL/list.txt\",\"refresh_secs\":300,\"max_entries\":1000}}"
wait_status urlbad "ok: 2 entries"
nl_ok "the alias was filled from the URL: $(jget 'd["source"]["last_status"]')"
[ "$(setdump alias_urlbad_v4 | grep -c "$NL_BLOCKED")" -ge 1 ] || nl_fail "set alias_urlbad_v4 lacks $NL_BLOCKED"
api_ok POST /firewall/rules "$(drop_rule urlblock '$urlbad')"
nl_assert_nft_has "ip daddr @alias_urlbad_v4"
blocked "LAN -> $NL_BLOCKED:9000 blocked by a rule on the URL-table alias" $NL_BLOCKED
reach "another host ($NL_WWW) is not in the list" $NL_WWW

echo "--- the list changes; a refresh swaps the set without reloading the ruleset"
R nft add table inet nl_marker
printf '%s\n' $NL_WWW > "$FEEDS/list.txt"
R nft add chain inet patronus nl_marker_chain
api_ok POST /firewall/aliases/refresh '{"names":["urlbad"]}'
wait_status urlbad "ok: 1 entries"
setdump alias_urlbad_v4 | grep "$NL_WWW" >/dev/null || nl_fail "the set lacks the new entry"
if setdump alias_urlbad_v4 | grep "$NL_BLOCKED" >/dev/null; then nl_fail "the set still has the removed entry"; fi
R nft list chain inet patronus nl_marker_chain >/dev/null || nl_fail "the refresh reloaded the whole ruleset"
reach "$NL_BLOCKED is no longer listed -> reachable" $NL_BLOCKED
blocked "$NL_WWW is listed now -> blocked" $NL_WWW
nl_ok "refresh swapped the set live (out-of-band chain survived)"

echo "--- a dead feed keeps the old entries and says why"
stop_feed_server
api_ok POST /firewall/aliases/refresh '{"names":["urlbad"]}'
grep -q '"ok":false' "$NL_OUT" || nl_fail "refresh of a dead feed claimed success: $(cat "$NL_OUT")"
wait_status urlbad "error"
ST=$(jget 'd["source"]["last_status"]')
setdump alias_urlbad_v4 | grep "$NL_WWW" >/dev/null || nl_fail "the failed refresh emptied the set"
blocked "still enforced with the feed down" $NL_WWW
nl_ok "failed refresh: $ST; entries kept"
start_feed_server

echo "--- the periodic task refreshes a due alias by itself"
printf '%s\n%s\n' $NL_WWW 192.0.2.77 > "$FEEDS/list.txt"
sqlite3 "$DB" "UPDATE firewall_alias_sources SET refresh_secs=3, last_attempt=0 WHERE alias='urlbad'"
nl_wait 30 bash -c "R nft list set inet patronus alias_urlbad_v4 | grep 192.0.2.77 >/dev/null" || { tail -20 "$NL_T/nl-web.log"; nl_fail "the periodic task did not refresh the due alias"; }
nl_ok "the periodic task picked up the change by itself"

echo "--- URL table of ports"
printf '9000\n9001-9003\n' > "$FEEDS/ports.txt"
api_ok POST /firewall/aliases "{\"name\":\"urlports\",\"type\":\"urltable_ports\",\"entries\":[],\"source\":{\"kind\":\"url\",\"url\":\"$FEED_URL/ports.txt\",\"refresh_secs\":300}}"
wait_status urlports "ok: 2 ports"
ports_set=$(R nft list set inet patronus alias_urlports_ports)   # (capture first: piping into grep -q makes nft die of SIGPIPE under pipefail)
grep -q '9000-9003' <<<"$ports_set" || { setdump alias_urlports_ports; nl_fail "port set not filled"; }
nl_ok "URL table (ports) filled: $(setdump alias_urlports_ports | tr -d '\n\t' | grep -o 'elements.*')"

echo "--- bad sources are refused"
for body in \
  '{"name":"u1","type":"urltable","entries":[],"source":{"kind":"url","url":"file:///etc/passwd"}}' \
  '{"name":"u2","type":"urltable","entries":[],"source":{"kind":"url","url":"https://x.test/l","refresh_secs":5}}' \
  '{"name":"u3","type":"urltable","entries":[],"source":{"kind":"url","url":"https://x.test/l","max_entries":99999999}}' \
  '{"name":"u4","type":"geoip","entries":["Germany"]}'; do
  nl_api POST /firewall/aliases "$body"
  [ "$NL_CODE" = 400 ] || nl_fail "accepted $body: $NL_CODE $(cat "$NL_OUT")"
done
nl_ok "file:// URLs, a 5 s interval, an absurd cap and a country name are refused (400)"
api_ok GET /firewall/aliases
nl_ok "an alias in the API list carries its source: $(jget '[a["name"] for a in d if a.get("source")]')"
# the page shows the new types
nl_web GET /firewall
for want in urltable geoip 'tab-geoip' 'tab-threat' 'tab-logs'; do grep -q "$want" "$NL_OUT" || nl_fail "firewall page lacks $want"; done
nl_ok "the Firewall page has the URL table / GeoIP types and the GeoIP, Threat Intel and Logs tabs"
api_ok DELETE /firewall/rules/$(python3 -c 'import json,sys; print([r["id"] for r in json.load(open(sys.argv[1])) if r["name"]=="urlblock"][0])' <(nl_api GET /firewall/rules; cat "$NL_OUT"))
api_ok DELETE /firewall/aliases/urlbad
api_ok DELETE /firewall/aliases/urlports

echo "=== 2. GeoIP"
# a tiny DB-IP "country lite" CSV: the lab's addresses live in CN/DE/US
cat > "$FEEDS/dbip.csv" <<EOF
"198.51.100.0","198.51.100.15","DE"
"198.51.100.16","198.51.100.31","CN"
"198.51.100.32","198.51.100.255","DE"
"203.0.113.0","203.0.113.255","US"
"2001:db8:100::","2001:db8:100::ffff","CN"
"1.0.0.0","1.0.0.255","AU"
"1.0.1.0","1.0.1.255","CN"
"2.0.0.0","2.0.0.255","FR"
"3.0.0.0","3.0.0.255","FR"
"4.0.0.0","4.0.0.255","FR"
"5.0.0.0","5.0.0.255","FR"
"6.0.0.0","6.0.0.255","FR"
"7.0.0.0","7.0.0.255","FR"
"8.0.0.0","8.0.0.255","FR"
EOF
nl_api GET /firewall/geoip
[ "$(jget 'd["database"]["present"]')" = False ] || nl_fail "database present before any download"
api_ok PUT /firewall/geoip "{\"db_url\":\"$FEED_URL/dbip.csv\",\"refresh_days\":30}"
api_ok POST /firewall/aliases '{"name":"cn","type":"geoip","entries":["cn"],"source":{"kind":"geoip","countries":["CN"],"max_entries":1000}}'
wait_status cn "ok: 3 ranges" 60
nl_ok "the country set was built from the database: $(jget 'd["source"]["last_status"]')"
setdump alias_cn_v4 | grep '198.51.100.16/28' >/dev/null || { setdump alias_cn_v4; nl_fail "CN range missing from the set"; }
setdump alias_cn_v6 | grep '2001:db8:100::/112' >/dev/null || nl_fail "CN IPv6 range missing"
nl_api GET "/firewall/geoip/lookup?ip=$NL_BLOCKED"
[ "$(jget 'd["country"]')" = CN ] || nl_fail "lookup of $NL_BLOCKED: $(cat "$NL_OUT")"
nl_api GET "/firewall/geoip/lookup?ip=$NL_WWW"
[ "$(jget 'd["country"]')" = DE ] || nl_fail "lookup of $NL_WWW: $(cat "$NL_OUT")"
nl_ok "lookup: $NL_BLOCKED = CN, $NL_WWW = DE"
api_ok GET /firewall/geoip
[ "$(jget 'd["database"]["present"]')" = True ] && [ "$(jget 'd["aliases"][0]["name"]')" = cn ] || nl_fail "geoip overview: $(cat "$NL_OUT")"
api_ok POST /firewall/rules "$(drop_rule geo-cn '$cn')"
blocked "LAN -> $NL_BLOCKED:9000 (CN) blocked by the country-set rule" $NL_BLOCKED
reach "LAN -> $NL_WWW:9000 (DE) allowed" $NL_WWW
echo "--- change the country set"
api_ok PUT /firewall/aliases/cn '{"name":"cn","type":"geoip","entries":[],"source":{"kind":"geoip","countries":["DE"]}}'
wait_status cn "for DE" 40
blocked "now DE is blocked" $NL_WWW
reach "and CN is allowed" $NL_BLOCKED
api_ok PUT /firewall/aliases/cn '{"name":"cn","type":"geoip","entries":[],"source":{"kind":"geoip","countries":["CN"]}}'
wait_status cn "for CN" 40
blocked "back to CN: blocked" $NL_BLOCKED
echo "--- a DB-IP update rebuilds the sets (forced download)"
sed -i 's/^"198.51.100.16","198.51.100.31","CN"/"198.51.100.16","198.51.100.23","CN"/; s/^"198.51.100.32","198.51.100.255","DE"/"198.51.100.24","198.51.100.255","DE"/' "$FEEDS/dbip.csv"
api_ok POST /firewall/geoip/refresh '{}'
setdump alias_cn_v4 | grep '198.51.100.16/29' >/dev/null || { setdump alias_cn_v4; nl_fail "set not rebuilt after the database changed"; }
nl_api GET "/firewall/geoip/lookup?ip=198.51.100.28"
[ "$(jget 'd["country"]')" = DE ] || nl_fail "lookup after the update: $(cat "$NL_OUT")"
nl_ok "database refresh rebuilt the country set (198.51.100.16/29) and the lookup follows"
echo "--- reboot with the feed server down"
nl_web_stop
nl_boot "$DB"          # kills the feed server too: nothing to download from
nl_assert_nft_has "set alias_cn_v4" "198.51.100.16/29" "ip daddr @alias_cn_v4"
blocked "after a reboot with no network to the feed: CN still blocked" $NL_BLOCKED
reach "and $NL_WWW (DE) allowed" $NL_WWW
start_feed_server
nl_web_start "$DB"; nl_login
api_ok DELETE /firewall/rules/$(python3 -c 'import json,sys; print([r["id"] for r in json.load(open(sys.argv[1])) if r["name"]=="geo-cn"][0])' <(nl_api GET /firewall/rules; cat "$NL_OUT"))
api_ok DELETE /firewall/aliases/cn

echo "=== 3. threat intelligence"
{
  echo '; Spamhaus DROP List 2026/10/26 - (c) 2026 The Spamhaus Project SLU'
  echo "$NL_BLOCKED/32 ; SBL256894"
  echo '10.0.0.0/8 ; a feed that lists private space'
  echo '192.168.50.0/24 ; ... including our own LAN'
  echo '0.0.0.0/0 ; and everything'
  echo '203.0.113.250/32 ; SBL1'
} > "$FEEDS/drop.txt"
python3 - "$FEEDS/big.txt" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    for i in range(1500):
        f.write(f"45.{i // 250}.{i % 250}.9\n")
PY
nl_api GET /firewall/threatintel
[ "$(jget '[f["id"] for f in d["feeds"] if f["id"]=="spamhaus_drop"][0]')" = spamhaus_drop ] || nl_fail "catalog lacks spamhaus_drop: $(cat "$NL_OUT")"
[ "$(jget 'len([f for f in d["feeds"] if not f["custom"]])')" -ge 5 ] || nl_fail "catalog too small"
nl_ok "catalog: $(jget '", ".join(f["name"] for f in d["feeds"] if not f["custom"])')"
nl_api PUT /firewall/threatintel/allow '{"url":"http://x.test/a"}'
[ "$NL_CODE" = 400 ] || nl_fail "feed id 'allow' accepted"
api_ok PUT /firewall/threatintel/labdrop "{\"enabled\":true,\"url\":\"$FEED_URL/drop.txt\",\"direction\":\"out\",\"refresh_secs\":3600,\"max_entries\":1000}"
for _ in $(seq 1 40); do nl_api GET /firewall/threatintel; [ "$(jget '[f["count"] for f in d["feeds"] if f["id"]=="labdrop"][0]')" != 0 ] && break; sleep 0.5; done
[ "$(jget '[f["count"] for f in d["feeds"] if f["id"]=="labdrop"][0]')" = 2 ] || nl_fail "labdrop should hold 2 entries (private ranges and /0 removed): $(cat "$NL_OUT")"
nl_ok "feed labdrop: 2 entries ($(jget '[f["status"] for f in d["feeds"] if f["id"]=="labdrop"][0]')); 10/8, our LAN and 0/0 were not taken over"
setdump alias_ti_labdrop_v4 | grep "$NL_BLOCKED" >/dev/null || nl_fail "feed set lacks $NL_BLOCKED"
if setdump alias_ti_labdrop_v4 | grep -E '10\.0\.0\.0|192\.168\.50|0\.0\.0\.0/0' >/dev/null; then setdump alias_ti_labdrop_v4; nl_fail "a private range / 0.0.0.0/0 got into the feed set"; fi
nl_assert_nft_has "jump ti_check" "ip daddr @alias_ti_labdrop_v4 counter" "patronus[ti:labdrop] drop"
blocked "LAN -> $NL_BLOCKED:9000 dropped by the threat feed (no user rule involved)" $NL_BLOCKED
reach "LAN -> $NL_WWW:9000 unaffected" $NL_WWW
nl_expect_tcp "the LAN can still reach the router (192.168.50.0/24 was in the feed)" C $NL_RTR_LAN 22
HITS=$(R nft list chain inet patronus ti_check | grep 'threat-intel labdrop' | grep -o 'packets [0-9]*' | head -1 | cut -d' ' -f2)
[ "${HITS:-0}" -gt 0 ] || { R nft list chain inet patronus ti_check; nl_fail "the feed rule counted no hits"; }
nl_ok "the drop rule counted $HITS packet(s)"
echo "--- a user rule comes after the feed: an allow for the same host does not win"
api_ok POST /firewall/rules "{\"name\":\"allow-blocked\",\"chain\":\"forward\",\"action\":\"accept\",\"interface\":\"@lan\",\"protocol\":\"any\",\"source\":\"any\",\"destination\":\"$NL_BLOCKED\",\"port\":\"any\",\"description\":\"x\",\"enabled\":true}"
blocked "the feed beats a later user allow" $NL_BLOCKED
echo "--- ti_allow exempts a host"
api_ok POST /firewall/aliases "{\"name\":\"ti_allow\",\"type\":\"host\",\"entries\":[\"$NL_BLOCKED\"]}"
nl_assert_nft_has "ip daddr @alias_ti_allow_v4 return"
reach "$NL_BLOCKED is in ti_allow -> reachable again" $NL_BLOCKED
api_ok DELETE /firewall/aliases/ti_allow
blocked "ti_allow removed -> dropped again" $NL_BLOCKED
echo "--- direction: inbound only does not stop LAN -> $NL_BLOCKED"
api_ok PUT /firewall/threatintel/labdrop '{"direction":"in"}'
nl_assert_nft_has "ip saddr @alias_ti_labdrop_v4 counter"
nl_assert_nft_lacks "ip daddr @alias_ti_labdrop_v4"
reach "direction=in: outbound to the listed host is allowed" $NL_BLOCKED
api_ok PUT /firewall/threatintel/labdrop '{"direction":"both"}'
blocked "direction=both: dropped" $NL_BLOCKED
echo "--- size cap and budget"
api_ok PUT /firewall/threatintel/bigfeed "{\"enabled\":true,\"url\":\"$FEED_URL/big.txt\",\"direction\":\"in\",\"max_entries\":1000}"
wait_status ti_bigfeed "truncated" 40
[ "$(jget 'd["source"]["last_count"]')" = 1000 ] || nl_fail "cap: $(cat "$NL_OUT")"
nl_ok "per-feed cap: 1500 entries in the list -> $(jget 'd["source"]["last_status"]')"
api_ok PUT /firewall/threatintel-budget '{"max_total":1001}'
api_ok POST /firewall/aliases/refresh '{"names":["ti_bigfeed"]}'
nl_api GET /firewall/aliases/ti_bigfeed
[ "$(jget 'd["source"]["last_count"]')" = 999 ] || nl_fail "the shared budget (1001 - 2 entries of labdrop) should cap bigfeed at 999: $(cat "$NL_OUT")"
nl_ok "shared budget: bigfeed capped at 999 ($(jget 'd["source"]["last_status"]'))"
nl_api PUT /firewall/threatintel-budget '{"max_total":5}'
[ "$NL_CODE" = 400 ] || nl_fail "a budget of 5 entries was accepted"
nl_ok "an absurd budget is refused (400)"
echo "--- a dead threat feed keeps its list"
stop_feed_server
api_ok POST /firewall/aliases/refresh '{"names":["ti_labdrop"]}'
grep -q '"ok":false' "$NL_OUT" || nl_fail "dead feed claimed success"
blocked "feed server down: the old list is still enforced" $NL_BLOCKED
start_feed_server
echo "--- reboot: feeds come from the store, no network needed"
nl_web_stop
nl_boot "$DB"
nl_assert_nft_has "jump ti_check" "patronus[ti:labdrop] drop"
blocked "after reboot the feed still drops $NL_BLOCKED" $NL_BLOCKED
reach "$NL_WWW still fine" $NL_WWW
nl_web_start "$DB"; nl_login
api_ok DELETE /firewall/threatintel/labdrop
api_ok DELETE /firewall/threatintel/bigfeed
nl_assert_nft_lacks "ti_check"
reach "feed removed: reachable again... (the allow rule is still there)" $NL_BLOCKED
nl_web_stop
nl_down
