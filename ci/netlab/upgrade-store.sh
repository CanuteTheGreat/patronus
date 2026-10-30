#!/usr/bin/env bash
# Upgrade + migration. Two sources of an existing store:
#  1. (always) a store in the pre-migrations layout of v0.1.0
#     (fixtures/store-v0.1.0-schema.sql, no schema_migrations table), with
#     rows written the way v0.1.0 wrote them;
#  2. (when PATRONUS_OLD_BIN / PATRONUS_OLD_WEB are set -- the nightly
#     builds them from the previous release commit) a store created and
#     edited by the previous release's own `patronus apply` + web API.
# HEAD must open it, migrate it (exactly once), keep every rule, and enforce
# them in real traffic after a reboot -- and a second boot must change
# nothing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
nl_write_installer_toml

migrations() { sqlite3 "$1" 'SELECT group_concat(version) FROM schema_migrations ORDER BY version'; }

# Device segmentation (lane s) ships migrations 1300 (groups/devices/segments), 1310 (Wi-Fi),
# 1320 (DNS policy + logs), 1330/1331 (insight, uplink history) and 1340 (time limits). An upgraded
# store must carry all of them, must NOT have isolation switched on (it is opt-in per segment), must
# not have rebinding protection forced on, and must leave no segmentation table in the kernel.
seg_upgrade_checks() { # DB LABEL
  local db=$1 have v
  have=$(sqlite3 "$db" 'SELECT group_concat(version) FROM schema_migrations')
  for v in 1300 1310 1320 1340; do
    case ",$have," in *",$v,"*) ;; *) nl_fail "$2: migration $v missing after the upgrade (have: $have)" ;; esac
  done
  [ "$(sqlite3 "$db" "SELECT count(*) FROM seg_segments WHERE enabled <> 0")" = 0 ] \
    || nl_fail "$2: isolation is on for a segment nobody opted in: $(sqlite3 "$db" 'SELECT segment,enabled FROM seg_segments')"
  [ "$(sqlite3 "$db" "SELECT count(*) FROM seg_devices")" = 0 ] || nl_fail "$2: the upgrade invented segmentation devices"
  [ "$(sqlite3 "$db" "SELECT count(*) FROM seg_groups WHERE name IN ('home','quarantine') AND builtin=1")" = 2 ] \
    || nl_fail "$2: built-in groups (home, quarantine) not seeded"
  [ "$(sqlite3 "$db" "SELECT count(*) FROM seg_time_policies") $(sqlite3 "$db" "SELECT count(*) FROM seg_dns_policies") $(sqlite3 "$db" "SELECT count(*) FROM seg_wifi_networks")" = "0 0 0" ] \
    || nl_fail "$2: policies/networks appeared out of nowhere"
  [ -z "$(sqlite3 "$db" "SELECT value FROM lan_settings WHERE key='dns.rebind_protection'")" ] \
    || nl_fail "$2: rebinding protection was forced onto an existing store (only new installs get it on)"
  if R nft list table inet patronus_seg >/dev/null 2>&1; then
    R nft list table inet patronus_seg; nl_fail "$2: a segmentation table exists although nothing opted in"
  fi
  if R nft list table inet patronus_time >/dev/null 2>&1 || R nft list table inet patronus_dnspol >/dev/null 2>&1; then
    nl_fail "$2: a time-limit/DNS-policy table exists although no policy does"
  fi
  [ -z "$(R pgrep -x hostapd || true)" ] || nl_fail "$2: hostapd running on an upgraded store with no Wi-Fi network"
  nl_ok "$2: segmentation migrations 1300/1310/1320/1340 present, isolation off, no segmentation kernel state"
}

echo "=== 1. v0.1.0 store layout -> HEAD"
DB=/t/legacy.db
rm -f "$DB"
sqlite3 "$DB" < "$NL_T/fixtures/store-v0.1.0-schema.sql"
now=$(date +%s)
sqlite3 "$DB" "
INSERT INTO firewall_rules (name, enabled, chain, action, source, destination, protocol, sport, dport, interface_in, interface_out, comment, priority, created_at, updated_at)
 VALUES ('legacy-block', 1, 'forward', 'drop', NULL, '198.51.100.20', 'tcp', NULL, '{\"Single\":80}', '$NL_LAN_IF', NULL, 'legacy-block', 0, $now, $now),
        ('legacy-wan-2222', 1, 'input', 'accept', NULL, NULL, 'tcp', NULL, '{\"Multiple\":[2222]}', '$NL_WAN_IF', NULL, 'legacy-wan-2222', 0, $now, $now);
INSERT INTO system_config (key, value, updated_at) VALUES ('hostname', 'legacy-box', $now);"
nl_boot "$DB"
rm -f /t/ref.db; R "$P" --db /t/ref.db config revisions >/dev/null   # a brand-new HEAD store
[ "$(migrations "$DB")" = "$(migrations /t/ref.db)" ] \
  || nl_fail "legacy store migrated to $(migrations "$DB"), a new store has $(migrations /t/ref.db)"
nl_ok "legacy store migrated to versions $(migrations "$DB")"
nl_assert_store_ok "$DB"
seg_upgrade_checks "$DB" "legacy store"
[ "$(sqlite3 "$DB" "SELECT value FROM system_config WHERE key='hostname'")" = legacy-box ] || nl_fail "system_config lost"
[ "$(sqlite3 "$DB" "SELECT count(*) FROM firewall_rules WHERE name LIKE 'legacy-%' AND origin='user'")" = 2 ] || nl_fail "legacy rules lost or re-owned"
nl_ok "legacy rows kept (origin user), system_config kept"
nl_assert_router_baseline
nl_assert_nft_has legacy-block legacy-wan-2222
nl_expect_http_blocked "legacy block rule enforced" http://blocked.example.test/
nl_expect_tcp "legacy WAN allow rule enforced" ISP $NL_RTR_WAN 2222
nl_expect_online
fp=$(nl_ruleset_fingerprint)
nl_boot "$DB"
[ "$(nl_ruleset_fingerprint)" = "$fp" ] || nl_fail "second boot changed the ruleset"
[ "$(sqlite3 "$DB" "SELECT count(*) FROM firewall_rules WHERE name = 'Anti-lockout'")" = 1 ] || nl_fail "defaults seeded twice"
nl_ok "second boot is a no-op (same ruleset, defaults seeded once)"

if [ -z "${PATRONUS_OLD_BIN:-}" ]; then
  echo "(previous-release upgrade skipped: PATRONUS_OLD_BIN not set; the nightly runs it)"
  nl_down; echo "UPGRADE: ALL CHECKS PASSED"; exit 0
fi

echo "=== 2. previous release ($(cat "$NL_T/old-version" 2>/dev/null || echo old)) -> HEAD"
DB=/t/prev.db
rm -f "$DB"
nl_up
R "$PATRONUS_OLD_BIN" --db "$DB" apply --bootstrap "$NL_TOML" >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "old release first boot"; }
nl_ok "old release booted the box"
WEB=$PATRONUS_OLD_WEB nl_web_start "$DB"
nl_login
nl_api POST /firewall/rules '{"name":"prev-block","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"prev-block","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "old release add rule: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /firewall/nat '{"rule_type":"SNAT","interface":"@wan","source":"192.168.60.0/24","destination":"any","target":"203.0.113.2","description":"prev-snat","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "old release add NAT: $NL_CODE $(cat "$NL_OUT")"
nl_expect_http_blocked "old release enforces prev-block" http://blocked.example.test/
nl_web_stop
old_rules=$(sqlite3 "$DB" "SELECT name||'|'||chain||'|'||action||'|'||coalesce(dport,'') FROM firewall_rules ORDER BY name")
old_migs=$(migrations "$DB")

echo "--- upgrade: reboot into HEAD"
nl_boot "$DB"
nl_ok "HEAD booted the previous release's store (migrations $old_migs -> $(migrations "$DB"))"
nl_assert_store_ok "$DB"
seg_upgrade_checks "$DB" "previous-release store"
[ "$(sqlite3 "$DB" "SELECT name||'|'||chain||'|'||action||'|'||coalesce(dport,'') FROM firewall_rules ORDER BY name")" = "$old_rules" ] \
  || nl_fail "rules changed by the upgrade"
nl_ok "every rule row intact"
nl_assert_router_baseline
nl_assert_nft_has prev-block prev-snat
nl_expect_http_blocked "after upgrade prev-block enforced" http://blocked.example.test/
nl_expect_online
nl_expect_wan_closed
nl_web_start "$DB"; nl_login
nl_api GET /firewall/rules; grep -q prev-block "$NL_OUT" || nl_fail "HEAD web lost prev-block"
nl_api POST /firewall/rules '{"name":"head-rule","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"8080","description":"head-rule","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "HEAD edit of an upgraded store: $NL_CODE"
nl_expect_http_blocked "HEAD edit on the upgraded store enforced" http://blocked.example.test:8080/
nl_web_stop
nl_ok "upgraded store is editable from HEAD's web UI"

nl_down
echo "UPGRADE: ALL CHECKS PASSED"
