#!/usr/bin/env bash
# Lane B/J: security overview + one-click hardening baseline + threat-feed hit counters
# (crates/patronus-web/src/security.rs, docs/SECURITY-OVERVIEW.md) on the real binaries,
# with nftables and real traffic between the lab namespaces.
#
# Proves:
#   - the checks read LIVE state: a user rule that opens the web UI on the WAN is reported as
#     failing (the ISP really connects), brute-force protection switched off fails, SYN flood /
#     bogon / private-source guards off fail;
#   - the baseline dry run changes nothing (same nft ruleset, no new revision) and lists every
#     change with before/after plus what it leaves alone;
#   - applying it is ONE revision: afterwards the kernel has the guard table, the SYN-flood and
#     WAN-guard rules, the WAN rule is gone, the ISP can no longer reach the web UI, the admin's
#     LAN session keeps working and the LAN still reaches the internet;
#   - a stale plan token is refused (409), an empty plan is refused (400);
#   - Undo restores that revision: the WAN rule is back and the ISP reaches the web UI again;
#   - an admin connected over the WAN (from a reserved address) gets a plan that leaves the
#     WAN web rule and the bogon guard alone, and keeps the session after applying it;
#   - a threat feed's hits (real dropped packets) are sampled into the hourly history, also in
#     "alert only" mode, where the traffic passes but is still counted; an undo never rewinds it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-security.db
rm -f "$DB" "$NL_T/nl-jar" /t/sec-isp-jar
FEEDS=/t/sec-feeds; rm -rf "$FEEDS"; mkdir -p "$FEEDS"
FEED_URL=http://$NL_WWW:8099
nl_write_installer_toml
cleanup() {
  set +e
  [ -n "${FEEDSRV:-}" ] && kill "$FEEDSRV" 2>/dev/null
  nl_web_stop
}
trap cleanup EXIT

jget() { nl_json "$NL_OUT" "$1"; }
check() { nl_json "$NL_OUT" "[c for c in d['checks'] if c['id']=='$1'][0]['$2']"; }
isp_web() { # METHOD PATH [JSON]: the web UI from the ISP side (WAN), own cookie jar
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  NL_CODE=$(ISP curl -sk -m 10 -b /t/sec-isp-jar -c /t/sec-isp-jar -o "$NL_OUT" -w '%{http_code}' \
    -X "$1" -H 'content-type: application/json' "${data[@]}" "https://$NL_RTR_WAN:8443$2") || NL_CODE=000
}
wan_reaches_ui() { ISP curl -sk -m 4 -o /dev/null "https://$NL_RTR_WAN:8443/login"; }
revisions() { sqlite3 "$DB" "SELECT count(*) FROM config_revisions"; }
ruleset_hash() { nl_ruleset_fingerprint; }

nl_boot "$DB"
nl_web_start "$DB"
nl_login

# --- an insecure starting point: what an older install can look like --------------------------------
nl_api_ok "guard off" PUT /guard/settings '{"enabled":false}'
nl_api_ok "web UI opened on the WAN" POST /firewall/rules '{"name":"web-from-wan","chain":"input","action":"accept","interface":"@wan","protocol":"tcp","source":"any","destination":"any","port":"8443","description":"web UI from the internet","enabled":true}'
for _ in $(seq 1 20); do wan_reaches_ui && break; sleep 0.5; done
wan_reaches_ui || nl_fail "the ISP cannot reach the web UI although a rule opens it"
nl_ok "real traffic: the ISP (WAN side) reaches the web UI through the user's rule"

nl_api_ok "overview" GET /security
[ "$(check web_wan status)" = fail ] || nl_fail "web_wan: $(check web_wan status) $(check web_wan evidence)"
grep -q "port 8443 on $NL_WAN_IF" <<<"$(check web_wan evidence)" || nl_fail "web_wan evidence: $(check web_wan evidence)"
[ "$(check guard status)" = fail ] || nl_fail "guard: $(check guard evidence)"
[ "$(check synflood status)" = fail ] || nl_fail "synflood: $(check synflood evidence)"
[ "$(check wan_bogons status)" = fail ] || nl_fail "wan_bogons: $(check wan_bogons evidence)"
[ "$(check wan_private status)" = fail ] || nl_fail "wan_private: $(check wan_private evidence)"
[ "$(jget 'd["live"]')" = True ] || nl_fail "live facts not read: $(jget 'd["live_error"]')"
G0=$(jget 'd["grade"]'); S0=$(jget 'd["score"]')
[ "$G0" = D ] || [ "$G0" = F ] || nl_fail "grade $G0 with the web UI open on the WAN (critical)"
nl_ok "overview reads live state: web UI open on $NL_WAN_IF (critical), guard/SYN flood/WAN guards off -> grade $G0 ($S0)"

# --- threat feed hits: real drops counted, then alert only ------------------------------------------
printf '%s/32 ; lab\n' "$NL_BLOCKED" > "$FEEDS/drop.txt"
ip netns exec nl-inet python3 -m http.server 8099 --bind 0.0.0.0 --directory "$FEEDS" >/t/sec-feedsrv.log 2>&1 &
FEEDSRV=$!
nl_api_ok "faster sampling" PUT /security/settings '{"sample_secs":10}'
nl_api_ok "lab feed" PUT /firewall/threatintel/labdrop "{\"enabled\":true,\"url\":\"$FEED_URL/drop.txt\",\"direction\":\"out\",\"refresh_secs\":3600,\"max_entries\":100}"
for _ in $(seq 1 40); do R nft list chain inet patronus ti_check 2>/dev/null | grep 'threat-intel labdrop' >/dev/null && break; sleep 0.5; done
nl_expect_no_tcp "LAN -> $NL_BLOCKED:9000 dropped by the feed" C "$NL_BLOCKED" 9000
nl_expect_no_tcp "a second try is dropped too" C "$NL_BLOCKED" 9000
hits() { nl_api GET /security/feeds; jget '[f["hits_24h"] for f in d["threat"]["feeds"] if f["id"]=="labdrop"][0]'; }
for _ in $(seq 1 100); do [ "$(hits)" -gt 0 ] && break; sleep 1; done
H1=$(hits)
[ "$H1" -gt 0 ] || { R nft list chain inet patronus ti_check; nl_fail "no hits sampled for labdrop"; }
[ "$(sqlite3 "$DB" "SELECT sum(packets) FROM sec_feed_hits WHERE feed='labdrop'")" -ge "$H1" ] || nl_fail "sec_feed_hits not written"
nl_ok "the feed's dropped packets are sampled into the hourly history ($H1 packets in 24 h)"
nl_api_ok "alert only" PUT /firewall/threatintel/labdrop '{"action":"alert"}'
nl_assert_nft_has "patronus[ti:labdrop] alert"
nl_assert_nft_lacks 'drop comment "threat-intel labdrop"'
nl_expect_tcp "alert only: LAN -> $NL_BLOCKED:9000 passes" C "$NL_BLOCKED" 9000
for _ in $(seq 1 60); do [ "$(hits)" -gt "$H1" ] && break; sleep 1; done
H2=$(hits)
[ "$H2" -gt "$H1" ] || nl_fail "alert-only matches not counted ($H1 -> $H2)"
nl_ok "alert only: the traffic passes and is still counted ($H1 -> $H2)"
nl_api_ok "back to drop" PUT /firewall/threatintel/labdrop '{"action":"drop"}'

# --- dry run: nothing changes -----------------------------------------------------------------------
REV0=$(revisions); HASH0=$(ruleset_hash)
nl_api_ok "dry run" GET /security/baseline
cp "$NL_OUT" /t/sec-plan.json
TOKEN=$(jget 'd["plan"]["token"]')
kinds=$(jget '",".join(sorted(set(c["check"] for c in d["plan"]["changes"])))')
for c in guard synflood wan_bogons wan_private web_wan threat_feeds; do
  grep -q "$c" <<<"$kinds" || nl_fail "plan lacks $c: $kinds"
done
[ "$(jget 'd["plan"]["session"]["over_wan"]')" = False ] || nl_fail "LAN session seen as WAN: $(jget 'd["plan"]["session"]')"
grep -q admin_2fa <<<"$(jget '",".join(s["check"] for s in d["plan"]["skipped"])')" || nl_fail "skipped list lacks admin_2fa"
[ "$(revisions)" = "$REV0" ] || nl_fail "the dry run took a revision"
[ "$(ruleset_hash)" = "$HASH0" ] || nl_fail "the dry run changed the ruleset"
nl_ok "dry run: $kinds; no revision, ruleset unchanged"

nl_api_code "stale token refused" 409 POST /security/baseline '{"token":"0000000000000000"}'

# --- apply: one revision, kernel state, real traffic -------------------------------------------------
nl_api_ok "apply" POST /security/baseline "{\"token\":\"$TOKEN\"}"
REV_BEFORE=$(jget 'd["revision_before"]')
[ "$(revisions)" = $((REV0 + 1)) ] || nl_fail "baseline took $(( $(revisions) - REV0 )) revisions, want 1"
[ "$(sqlite3 "$DB" "SELECT summary FROM config_revisions WHERE id=$REV_BEFORE")" = "before security baseline" ] || nl_fail "revision $REV_BEFORE is not the baseline's"
nl_ok "applied as one configuration revision (#$REV_BEFORE = before security baseline)"
R nft list table inet patronus_guard >/dev/null 2>&1 || nl_fail "no guard table after the baseline"
nl_assert_nft_has "SYN flood protection" "WAN: block bogon sources" "WAN: block private sources"
R nft list ruleset | grep 'web UI from the internet' >/dev/null && nl_fail "the WAN web rule is still loaded"
nl_ok "kernel: guard table, SYN flood + WAN guard rules loaded, the WAN web rule is gone"
wan_reaches_ui && nl_fail "the ISP still reaches the web UI after the baseline"
nl_ok "real traffic: the ISP no longer reaches the web UI"
nl_api_ok "the admin's LAN session still works" GET /security
[ "$(check web_wan status)" = pass ] || nl_fail "web_wan after: $(check web_wan evidence)"
[ "$(check guard status)" = pass ] || nl_fail "guard after: $(check guard evidence)"
[ "$(check synflood status)" = pass ] || nl_fail "synflood after: $(check synflood evidence)"
S1=$(jget 'd["score"]'); G1=$(jget 'd["grade"]')
[ "$S1" -gt "$S0" ] || nl_fail "score did not improve ($S0 -> $S1)"
nl_ok "after the baseline: grade $G1 ($S0 -> $S1), the same LAN session works"
nl_expect_http "the LAN still reaches the internet (bogon guard keeps answers)" "http://$NL_WWW/"
nl_api GET /security/baseline
T2=$(jget 'd["plan"]["token"]')
[ "$(jget 'len(d["plan"]["changes"])')" = 0 ] || nl_fail "second dry run still has changes: $(cat "$NL_OUT")"
nl_api_code "empty plan refused" 400 POST /security/baseline "{\"token\":\"$T2\"}"

# --- undo --------------------------------------------------------------------------------------------
HB=$(sqlite3 "$DB" "SELECT sum(packets) FROM sec_feed_hits WHERE feed='labdrop'")
nl_api_code "undo with a wrong revision refused" 400 POST /security/baseline/undo '{"revision":1}'
nl_api_ok "undo" POST /security/baseline/undo "{\"revision\":$REV_BEFORE}"
for _ in $(seq 1 20); do wan_reaches_ui && break; sleep 0.5; done
wan_reaches_ui || nl_fail "after undo the ISP does not reach the web UI again"
R nft list table inet patronus_guard >/dev/null 2>&1 && nl_fail "guard table still there after undo"
nl_assert_nft_lacks "SYN flood protection"
[ "$(sqlite3 "$DB" "SELECT sum(packets) FROM sec_feed_hits WHERE feed='labdrop'")" -ge "$HB" ] || nl_fail "undo rewound the hit history"
nl_ok "undo: the WAN rule is back (the ISP reaches the web UI), guard and SYN flood off again, hit history kept"

# --- the admin's own WAN session is never cut ---------------------------------------------------------
isp_web POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$NL_PASS\"}"
[ "$NL_CODE" = 200 ] || nl_fail "login from the WAN: $NL_CODE $(cat "$NL_OUT")"
isp_web GET /api/security/baseline
[ "$NL_CODE" = 200 ] || nl_fail "dry run from the WAN: $NL_CODE"
[ "$(jget 'd["plan"]["session"]["over_wan"]')" = True ] || nl_fail "WAN session not recognised: $(jget 'd["plan"]["session"]')"
jget '[c["action"] for c in d["plan"]["changes"]]' | grep DisableRule >/dev/null && nl_fail "plan would disable the rule carrying the WAN session"
jget '[c["check"] for c in d["plan"]["changes"]]' | grep wan_bogons >/dev/null && nl_fail "plan would drop the session's bogon source"
jget '[s["reason"] for s in d["plan"]["skipped"] if s["check"] in ("web_wan","wan_bogons")]' | grep 'over the WAN' >/dev/null || nl_fail "no reason given: $(cat "$NL_OUT")"
TW=$(jget 'd["plan"]["token"]')
isp_web POST /api/security/baseline "{\"token\":\"$TW\"}"
[ "$NL_CODE" = 200 ] || nl_fail "apply from the WAN: $NL_CODE $(cat "$NL_OUT")"
isp_web GET /api/security
[ "$NL_CODE" = 200 ] || nl_fail "the WAN session broke after its own baseline ($NL_CODE)"
wan_reaches_ui || nl_fail "a new WAN connection to the web UI is refused after a WAN-session baseline"
nl_assert_nft_has "SYN flood protection"
nl_ok "an admin on the WAN keeps the session and the WAN web rule; the rest of the baseline is applied"

nl_web_stop
echo "lane-b-security: all checks passed"
