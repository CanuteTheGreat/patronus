#!/usr/bin/env bash
# Lane W (network map & segmentation advisor, docs/design/network-map.md), through the shipped binaries:
#
#   LAN = bridge br0 192.168.50.0/24: laptop (nl-client .10), nas (.11), cam (.12), tv (.13), printer (.14)
#
# Proves: discovery from the kernel neighbour table (real ARP), up/down from a real link going away,
# classification (user label, MAC rule), the infra-map/v1 graph, the flat-network finding on a deliberately
# flat LAN, the advisor's dry run changing nothing, the one-click apply isolating the untrusted devices with
# real packets (device segmentation's nft table), trusted devices still printing / watching the camera / casting,
# the finding gone afterwards, read-only share keys (no key 401, stats-only key 403 on the graph, basic keys hide
# MACs, revoked = 401), the public live page and the map component, and that the isolation survives a reboot.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-w-netmap.db
. "$(dirname "$0")/fixtures/netmap-topo.sh"

rm -f "$DB" "$NL_T/nl-jar"
map_boot
nl_ok "booted: flat LAN br0 with laptop, nas, cam, tv, printer"
nl_web_start "$DB"; nl_login

# --- 1. discovery from the real neighbour table -------------------------------------------------
nl_api_ok "settings" PUT /map/settings '{"down_after_secs":"30","probe":"ping"}'
wake
nl_api_ok "discover" POST /map/discover
nl_api_ok "devices" GET /map/devices
N=$(jget 'len(d)'); UP=$(jget 'len([x for x in d if x["status"]=="up"])')
[ "$N" -ge 5 ] && [ "$UP" -ge 5 ] || { cat "$NL_OUT"; nl_fail "discovery: $N devices, $UP up (want 5 up)"; }
[ "$(jget '[x["segment"] for x in d if x["mac"]=="02:aa:00:00:00:12"][0]')" = "@lan" ] || nl_fail "cam not placed on @lan: $(cat "$NL_OUT")"
[ "$(jget '"192.168.50.1" in [x["ip"] for x in d]')" = False ] || nl_fail "the router's own address was listed as a device"
nl_ok "discovery: $N devices on @lan, all up, from the kernel neighbour table"

# --- 2. classification: labels and a MAC rule ----------------------------------------------------
nl_api_ok "label laptop" PUT /map/devices/02:aa:00:00:00:10 '{"name":"laptop","class":"computer"}'
nl_api_ok "label nas" PUT /map/devices/02:aa:00:00:00:11 '{"name":"nas","class":"infra"}'
nl_api_ok "label tv" PUT /map/devices/02:aa:00:00:00:13 '{"name":"living-tv","class":"media"}'
nl_api_ok "label printer" PUT /map/devices/02:aa:00:00:00:14 '{"name":"printer","class":"printer"}'
nl_api_code "rule" 201 POST /map/rules '{"field":"mac","pattern":"02:aa:00:00:00:12","class":"camera","priority":10}'
nl_api_code "bad class refused" 400 PUT /map/devices/02:aa:00:00:00:13 '{"class":"toaster"}'
nl_api_ok "devices" GET /map/devices
[ "$(jget '[x["class"]+"/"+x["class_source"] for x in d if x["mac"]=="02:aa:00:00:00:12"][0]')" = "camera/rule" ] || nl_fail "MAC rule did not classify the camera: $(cat "$NL_OUT")"
nl_ok "classes: labels + MAC rule"

# --- 3. graph + flat-network finding -------------------------------------------------------------
nl_api_ok "graph" GET /map/graph
[ "$(jget 'd["schema"]')" = infra-map/v1 ] || nl_fail "graph schema: $(head -c 300 "$NL_OUT")"
[ "$(jget '[g["id"] for g in d["groups"]]')" = "['seg:@lan']" ] || nl_fail "groups: $(jget 'd["groups"]')"
[ "$(jget '[n["class"] for n in d["nodes"] if n["id"]=="dev:02:aa:00:00:00:12"][0]')" = camera ] || nl_fail "graph node class"
[ "$(jget '[n["group"] for n in d["nodes"] if n["id"]=="dev:02:aa:00:00:00:14"][0]')" = "seg:@lan" ] || nl_fail "printer not in seg:@lan"
[ "$(jget '[f["severity"] for f in d["findings"] if f["id"]=="flat-network"]')" = "['high']" ] || nl_fail "no high flat-network finding: $(jget 'd["findings"]')"
nl_ok "graph: infra-map/v1, LAN group, devices with classes, flat-network finding (high)"
nl_api_ok "advisor" GET /segmentation/advisor
[ "$(jget 'sorted(m["group"] for m in d["plans"][0]["moves"])')" = "['cameras', 'media', 'printers']" ] || nl_fail "plan moves: $(cat "$NL_OUT")"
nl_ok "advisor plan: cam -> cameras, tv -> media, printer -> printers"

want_ok "flat: cam -> laptop tcp 7000" http_ok nl-cam 192.168.50.10 7000
want_ok "flat: printer -> nas 8080" http_ok nl-prn 192.168.50.11 8080

# --- 4. dry run changes nothing, apply isolates ----------------------------------------------------
FP=$(nl_ruleset_fingerprint)
nl_api_ok "dry run" POST /segmentation/advisor/apply '{"segment":"@lan","dry_run":true}'
[ "$(jget 'd["applied"]')" = False ] || nl_fail "dry run applied"
[ "$(nl_ruleset_fingerprint)" = "$FP" ] || nl_fail "the dry run changed the ruleset"
R nft list table inet patronus_seg >/dev/null 2>&1 && nl_fail "segmentation table exists after a dry run"
nl_ok "dry run: plan returned, ruleset unchanged"
wake
nl_api_ok "apply" POST /segmentation/advisor/apply '{"segment":"@lan"}'
[ "$(jget 'd["applied"]')" = True ] || nl_fail "apply: $(cat "$NL_OUT")"
nl_assert_nft_has "table inet patronus_seg"
nl_ok "applied: device segmentation table loaded"
check_isolated() {
  want_deny "cam -> laptop tcp 7000" http_ok nl-cam 192.168.50.10 7000
  want_deny "cam -> nas tcp 8080" http_ok nl-cam 192.168.50.11 8080
  want_deny "printer -> nas tcp 8080" http_ok nl-prn 192.168.50.11 8080
  want_deny "printer -> internet (printers: internet deny)" http_ok nl-prn "$NL_WWW" 80
  want_deny "laptop -> cam tcp 8080 (not a camera port)" C curl -s -m 3 -o /dev/null http://192.168.50.12:8080/
  want_ok "laptop -> cam tcp 80 (service home -> cameras)" C curl -s -m 3 -o /dev/null http://192.168.50.12:80/
  want_ok "laptop -> printer tcp 9100 (service home -> printers)" C curl -s -m 3 -o /dev/null http://192.168.50.14:9100/
  want_ok "laptop -> tv tcp 8080 (link home <-> media)" C curl -s -m 3 -o /dev/null http://192.168.50.13:8080/
  want_ok "tv -> laptop tcp 7000 (link home <-> media)" http_ok nl-tv 192.168.50.10 7000
  want_ok "laptop -> nas tcp 8080 (both trusted, home)" C curl -s -m 3 -o /dev/null http://192.168.50.11:8080/
  want_ok "cam is online (cameras: internet allow)" http_ok nl-cam "$NL_WWW" 80
}
check_isolated
nl_api_ok "advisor after" GET /segmentation/advisor
[ "$(jget 'len(d["findings"])')" = 0 ] || nl_fail "finding still raised after the apply: $(cat "$NL_OUT")"
nl_ok "after apply: no flat-network finding"

# --- 5. down detection: a device's link goes away ---------------------------------------------------
X nl-tv ip link set eth0 down
sleep 31
nl_api_ok "discover" POST /map/discover
nl_api_ok "devices" GET /map/devices
[ "$(jget '[x["status"] for x in d if x["mac"]=="02:aa:00:00:00:13"][0]')" = down ] || nl_fail "tv not down after its link went away: $(cat "$NL_OUT")"
[ "$(jget '[x["status"] for x in d if x["mac"]=="02:aa:00:00:00:12"][0]')" = up ] || nl_fail "cam should still be up"
nl_ok "down detection: tv down, cam up"
X nl-tv ip link set eth0 up

# --- 6. share keys, live view, stats ---------------------------------------------------------------
nl_api_code "key view" 201 POST /map/keys '{"name":"wall","scope":"view","detail":"basic"}'
KV=$(jget 'd["key"]')
nl_api_code "key stats" 201 POST /map/keys '{"name":"widget","scope":"stats"}'
KS=$(jget 'd["key"]')
pub() { NL_CODE=$(C curl -sk -m 10 -o "$NL_OUT" -w '%{http_code}' "$@"); }
pub "$NL_UI/api/map/shared/graph"; [ "$NL_CODE" = 401 ] || nl_fail "shared graph without key: $NL_CODE"
pub -H "X-Map-Key: pmk_0000" "$NL_UI/api/map/shared/graph"; [ "$NL_CODE" = 401 ] || nl_fail "shared graph with a wrong key: $NL_CODE"
pub -H "X-Map-Key: $KS" "$NL_UI/api/map/shared/graph"; [ "$NL_CODE" = 403 ] || nl_fail "stats key read the graph: $NL_CODE"
pub -H "X-Map-Key: $KV" "$NL_UI/api/map/shared/graph"; [ "$NL_CODE" = 200 ] || nl_fail "view key: $NL_CODE $(cat "$NL_OUT")"
[ "$(jget 'any(n.get("mac") for n in d["nodes"]) or any("href" in n for n in d["nodes"])')" = False ] || nl_fail "basic share leaks MACs or admin links"
pub -H "X-Map-Key: $KS" "$NL_UI/api/map/stats"; [ "$NL_CODE" = 200 ] || nl_fail "stats: $NL_CODE"
[ "$(jget 'd["devices"]')" -ge 5 ] && [ "$(jget 'd["findings"]')" = 0 ] || nl_fail "stats: $(cat "$NL_OUT")"
pub "$NL_UI/api/map/stats"; [ "$NL_CODE" = 401 ] || nl_fail "stats without key or session: $NL_CODE"
pub "$NL_UI/map/live"; [ "$NL_CODE" = 200 ] && grep -q "ui-map/map.js" "$NL_OUT" || nl_fail "live page: $NL_CODE"
NL_CODE=$(C curl -sk -m 10 -o "$NL_OUT" -D "$NL_T/map-h" -w '%{http_code}' "$NL_UI/ui-map/map.js")
[ "$NL_CODE" = 200 ] && grep -qi "content-type: text/javascript" "$NL_T/map-h" && grep -q "toMermaid" "$NL_OUT" || nl_fail "map.js: $NL_CODE"
pub "$NL_UI/api/map/graph"; [ "$NL_CODE" = 401 ] || nl_fail "the full graph answered without a session: $NL_CODE"
nl_api_ok "keys" GET /map/keys
ID=$(jget '[k["id"] for k in d if k["name"]=="wall"][0]')
[ "$(jget '[k["last_used"] is not None for k in d if k["name"]=="wall"][0]')" = True ] || nl_fail "last_used not recorded"
nl_api_ok "revoke" DELETE /map/keys/$ID
pub -H "X-Map-Key: $KV" "$NL_UI/api/map/shared/graph"; [ "$NL_CODE" = 401 ] || nl_fail "revoked key still works: $NL_CODE"
nl_ok "share keys: 401 without/wrong/revoked, 403 stats-only, basic hides MACs, stats widget JSON, public live page + map.js"

# --- 7. reboot: the isolation is configuration, it comes back ---------------------------------------
nl_web_stop
nl_kill_daemons patronus-web
map_boot
nl_assert_nft_has "table inet patronus_seg"
wake
check_isolated
nl_ok "after a reboot the advisor's isolation is still enforced"
echo "lane-w-netmap: PASS"
