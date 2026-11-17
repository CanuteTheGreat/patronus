#!/usr/bin/env bash
# Customer journey: config generations and commit-confirmed changes.
#
# A risky change that locks the LAN client out of the internet (and of a router
# service) is applied "on trial" (X-Confirm-In). Proven on kernel state and real
# traffic, with the independent timer in the root `patronus applyd`:
#   1. at the deadline the previous generation is back: nft ruleset equals the
#      one from before, the client has its access again, a revert generation
#      records it (real 1-minute deadline);
#   2. Confirm from the client keeps the change, also past the original deadline;
#   3. restarting patronus-web while pending still reverts at the deadline;
#   4. a reboot while pending: deadline passed -> the previous generation boots;
#      deadline not passed -> the change is enforced again and the countdown
#      resumes, then reverts;
#   5. CLI: generations, diff (secrets masked), rollback --confirm-in, confirm,
#      revert-now, the declarative file (export -> import -> export identical,
#      dry run, import --confirm-in) and the anti-lockout rule always holds.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/cg.db
SOCK=/t/cg-applyd.sock
rm -f "$DB" "$SOCK" /t/cg-applyd.log
export PATRONUS_APPLYD_SOCKET=$SOCK
nl_write_installer_toml

CG_APPLYD=
cg_applyd_start() {
  env PATRONUS_DB="$DB" RUST_LOG=info ip netns exec nl-rtr "$P" --db "$DB" applyd --socket "$SOCK" --group root \
    >>/t/cg-applyd.log 2>&1 &
  CG_APPLYD=$!
  nl_wait 20 test -S "$SOCK" || { cat /t/cg-applyd.log; nl_fail "applyd socket did not appear"; }
  nl_wait 20 cg_watchdog_ok || { cat /t/cg-applyd.log; nl_fail "applyd's commit-confirm timer is not running"; }
}
cg_applyd_stop() {
  [ -n "$CG_APPLYD" ] && kill "$CG_APPLYD" 2>/dev/null
  wait "$CG_APPLYD" 2>/dev/null || true
  CG_APPLYD=
}
cg_watchdog_ok() {
  python3 - "$SOCK" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1])
s.sendall(b'{"op":"watchdog"}\n')
sys.exit(0 if json.loads(s.makefile().readline()).get("watchdog") else 1)
PY
}
# cg_set_deadline SECONDS: move the stored deadline to now+SECONDS (the timer reads the store)
cg_set_deadline() {
  python3 - "$DB" "$1" <<'PY'
import json, sqlite3, sys, time
c = sqlite3.connect(sys.argv[1], timeout=30)
p = json.loads(c.execute("select value from config_generation_state where key='pending'").fetchone()[0])
p["deadline"] = int(time.time()) + int(sys.argv[2])
c.execute("update config_generation_state set value=? where key='pending'", (json.dumps(p),))
c.commit()
PY
}
cg_pending() { sqlite3 "$DB" "select count(*) from config_generation_state where key='pending'"; }
cg_no_pending() { [ "$(cg_pending)" = 0 ]; }
# The revert is finished when the timer has also applied it and recorded the result: the pending state is
# cleared first (so a boot in between loads the safe store), the kernel follows a moment later.
cg_last_revert() { sqlite3 "$DB" "select value from config_generation_state where key='last_revert'"; }
CG_LR0=
cg_reverted() { [ -n "$(cg_last_revert)" ] && [ "$(cg_last_revert)" != "$CG_LR0" ] && cg_no_pending; }
cg_has_pending() { [ "$(cg_pending)" = 1 ]; }
cg_stop_all() { nl_web_stop; cg_applyd_stop; }
# cg_web METHOD PATH JSON [HEADER...]: like nl_api with extra request headers; response headers in /t/cg-hdr
cg_web() {
  local m=$1 p=$2 d=$3; shift 3
  local hs=() h
  for h in "$@"; do hs+=(-H "$h"); done
  NL_CODE=$(C curl -sk -m 60 -b "$NL_T/nl-jar" -c "$NL_T/nl-jar" -D /t/cg-hdr -o "$NL_OUT" -w '%{http_code}' \
    -X "$m" -H 'content-type: application/json' "${hs[@]}" -d "$d" "$NL_UI/api$p")
}
LOCKOUT='{"name":"cg-lockout","chain":"forward","action":"drop","interface":"@lan","protocol":"any","source":"any","destination":"any","port":"any","description":"cg-lockout","enabled":true}'
SVCBLOCK='{"name":"cg-svc-block","chain":"input","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"any","port":"2222","description":"cg-svc-block","enabled":true}'
# the risky change: the LAN client loses the internet and the router's service port
cg_arm_risky() { # MINUTES
  CG_LR0=$(cg_last_revert)
  cg_web POST /firewall/rules "$LOCKOUT" "X-Confirm-In: $1" "X-Commit-Message: risky%20lockout%20test"
  [ "$NL_CODE" = 201 ] || nl_fail "risky rule: $NL_CODE $(cat "$NL_OUT")"
  grep -qi '^x-pending-deadline:' /t/cg-hdr || { cat /t/cg-hdr; nl_fail "no X-Pending-Deadline header: the change was not armed"; }
  cg_web POST /firewall/rules "$SVCBLOCK" ""
  [ "$NL_CODE" = 201 ] || nl_fail "service rule: $NL_CODE $(cat "$NL_OUT")"
}
cg_assert_locked_out() {
  nl_assert_nft_has cg-lockout cg-svc-block
  nl_expect_http_blocked "$1: LAN client -> internet" "http://$NL_WWW/"
  nl_expect_no_tcp "$1: LAN client -> router :2222" C $NL_RTR_LAN 2222
  nl_expect_tcp "$1: anti-lockout still holds (router SSH from the LAN)" C $NL_RTR_LAN 22
}
cg_assert_access_back() {
  nl_assert_nft_lacks cg-lockout cg-svc-block
  nl_expect_online
  nl_expect_tcp "$1: LAN client -> router :2222" C $NL_RTR_LAN 2222
}
cg_gen_field() { # PYEXPR on the newest generation g (from `config generations --json`)
  R "$P" --db "$DB" config generations --json >"$NL_OUT" 2>/dev/null || { cat "$NL_OUT"; nl_fail "config generations"; }
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); g=d["generations"][0]; print(eval(sys.argv[2]))' "$NL_OUT" "$1"
}

echo "=== boot a configured router; applyd (root) and the web UI (from the LAN) are up"
nl_boot "$DB"
cg_applyd_start
nl_web_start "$DB"; nl_login
nl_expect_online
nl_expect_tcp "LAN client -> router :2222 (before)" C $NL_RTR_LAN 2222
F0=$(nl_ruleset_fingerprint)

echo "=== 1. a risky change is applied on trial and reverted at the deadline (real 1-minute deadline)"
cg_arm_risky 1
cg_assert_locked_out "on trial"
cg_has_pending || nl_fail "no pending state in the store"
nl_api GET /system/generations/pending
[ "$(nl_json "$NL_OUT" "d['pending']['seconds_left'] > 40")" = True ] || nl_fail "countdown: $(cat "$NL_OUT")"
nl_ok "the stored countdown is running ($(nl_json "$NL_OUT" "d['pending']['seconds_left']") s left); the UI is still reachable from the locked-out client"
nl_api GET /system/generations
[ "$(nl_json "$NL_OUT" "any(g['message']=='risky lockout test' and g['actor']=='admin' for g in d['generations'])")" = True ] || nl_fail "commit message: $(cat "$NL_OUT")"
nl_ok "the change is a generation with the user's commit message"
nl_wait 120 cg_reverted || { tail -30 /t/cg-applyd.log; nl_fail "the change was not reverted at the deadline"; }
cg_assert_access_back "after the deadline"
[ "$(nl_ruleset_fingerprint)" = "$F0" ] || { nl_ruleset; nl_fail "the ruleset after the revert differs from the one before the change"; }
nl_ok "the nft ruleset after the revert is identical to the one before the risky change"
[ "$(cg_gen_field "g['kind']")" = revert ] || nl_fail "newest generation is not a revert: $(cat "$NL_OUT")"
[ "$(cg_gen_field "g['actor']")" = commit-confirm ] || nl_fail "revert actor"
grep -q 'commit-confirm deadline reached' /t/cg-applyd.log || nl_fail "applyd did not log the revert"
nl_ok "a revert generation (actor commit-confirm) records it; applyd's own timer did it"

echo "=== 2. Confirm keeps the change, also past the original deadline"
cg_arm_risky 1
cg_assert_locked_out "on trial (2)"
nl_api POST /system/generations/pending/confirm
[ "$NL_CODE" = 200 ] || nl_fail "confirm: $NL_CODE $(cat "$NL_OUT")"
cg_no_pending || nl_fail "confirm left a pending state"
nl_ok "confirmed from the LAN client's admin session"
sleep 70
cg_assert_locked_out "70 s later, past the deadline: the confirmed change stays"
[ "$(sqlite3 "$DB" "select count(*) from config_generations where kind='revert'")" = 1 ] || nl_fail "a second revert happened"
nl_api GET /system/generations
[ "$(nl_json "$NL_OUT" "[g for g in d['generations'] if g['live']][0]['boot']")" = True ] || nl_fail "confirmed generation is not the boot default"
nl_ok "the confirmed generation is the boot default"
# put the router back (a plain change, nothing on trial)
for n in cg-lockout cg-svc-block; do
  nl_api GET /firewall/rules
  id=$(nl_json "$NL_OUT" "[r['id'] for r in d if r['name']=='$n'][0]")
  nl_api DELETE "/firewall/rules/$id"; [ "$NL_CODE" = 200 ] || nl_fail "delete $n: $NL_CODE"
done
cg_assert_access_back "after removing the rules by hand"

echo "=== 3. restarting patronus-web while pending still reverts"
cg_arm_risky 5
cg_assert_locked_out "on trial (3)"
nl_web_stop
cg_set_deadline 6
nl_ok "patronus-web is stopped; deadline moved to +6 s"
nl_wait 60 cg_reverted || { tail -30 /t/cg-applyd.log; nl_fail "no revert with the web process down"; }
cg_assert_access_back "web UI down at the deadline"
nl_web_start "$DB"; nl_login
nl_api GET /system/generations/pending
[ "$(nl_json "$NL_OUT" "d['pending']")" = None ] || nl_fail "pending after revert: $(cat "$NL_OUT")"
[ "$(nl_json "$NL_OUT" "d['last_revert']['ok']")" = True ] || nl_fail "last revert: $(cat "$NL_OUT")"
nl_ok "the restarted web UI shows the revert (last_revert ok)"
# and a web restart while pending, before the deadline, keeps the countdown
cg_arm_risky 5
nl_web_stop; nl_web_start "$DB"; nl_login
nl_api GET /system/generations/pending
[ "$(nl_json "$NL_OUT" "d['pending']['seconds_left'] > 200")" = True ] || nl_fail "countdown lost on web restart: $(cat "$NL_OUT")"
nl_ok "the countdown survived a web restart ($(nl_json "$NL_OUT" "d['pending']['seconds_left']") s left)"
nl_api POST /system/generations/pending/revert-now
[ "$NL_CODE" = 200 ] || nl_fail "revert-now: $NL_CODE $(cat "$NL_OUT")"
cg_assert_access_back "Revert now"
cg_no_pending || nl_fail "revert-now left a pending state"

echo "=== 4. a reboot while pending"
echo "--- 4a. the deadline passes while the box is down: the previous generation boots"
cg_arm_risky 5
cg_assert_locked_out "on trial (4a)"
cg_stop_all
cg_set_deadline -5
nl_boot "$DB"
grep -q 'not confirmed before its deadline' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "boot did not say it reverted"; }
cg_assert_access_back "after boot, deadline passed"
cg_no_pending || nl_fail "pending survived the boot"
[ "$(cg_gen_field "g['kind']")" = revert ] || nl_fail "boot revert generation"
nl_ok "the box booted the previous generation (revert recorded)"
echo "--- 4b. the deadline has not passed: the change is enforced again and the countdown resumes"
cg_applyd_start
nl_web_start "$DB"; nl_login
cg_arm_risky 5
cg_stop_all
nl_boot "$DB"
grep -q 'still on trial' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "boot did not resume the countdown"; }
cg_assert_locked_out "after boot, still on trial"
cg_has_pending || nl_fail "pending lost across the boot"
nl_ok "the change on trial is enforced again after the reboot and the countdown resumed"
cg_applyd_start
cg_set_deadline 5
nl_wait 60 cg_reverted || { tail -30 /t/cg-applyd.log; nl_fail "no revert after the resumed countdown"; }
cg_assert_access_back "resumed countdown reached its deadline"
nl_web_start "$DB"; nl_login

echo "=== 5. the CLI: generations, diff, rollback on trial, confirm, revert-now"
R "$P" --db "$DB" config generations >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "config generations"; }
grep -q 'risky lockout test' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "generations list lacks the commit message"; }
grep -q 'live' "$NL_OUT" || nl_fail "no live marker"
nl_ok "patronus config generations lists messages, actors and the live/boot markers"
sqlite3 "$DB" "insert or replace into system_config (key, value, updated_at) values ('smtp.password','cg-OLD-SECRET',1)" 2>/dev/null \
  || sqlite3 "$DB" "insert or replace into system_config (key, value) values ('smtp.password','cg-OLD-SECRET')"
G_OLD=$(R "$P" --db "$DB" config generations --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["generations"][0]["id"])')
R "$P" --db "$DB" config diff "$G_OLD" live >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "config diff"; }
grep -q 'cg-OLD-SECRET' "$NL_OUT" && nl_fail "diff leaked a secret"
nl_ok "patronus config diff works against live (and shows no secret value)"

# a config change recorded as a generation, then a rollback on trial from the CLI
nl_api POST /firewall/rules "$SVCBLOCK"; [ "$NL_CODE" = 201 ] || nl_fail "svc rule: $NL_CODE"
nl_expect_no_tcp "service rule enforced" C $NL_RTR_LAN 2222
GEN_WITH=$(cg_gen_field "g['id']")
GEN_BEFORE=$(R "$P" --db "$DB" config generations --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin)["generations"]; print(d[1]["id"])')
R "$P" --db "$DB" config diff "$GEN_BEFORE" "$GEN_WITH" >"$NL_OUT" 2>&1
grep -q 'cg-svc-block' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "diff between two generations lacks the rule"; }
nl_ok "diff between two generations names the added rule"
R "$P" --db "$DB" config rollback "$GEN_BEFORE" --confirm-in 1 >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "rollback --confirm-in"; }
nl_assert_nft_lacks cg-svc-block
nl_expect_tcp "rolled back: router :2222 open again" C $NL_RTR_LAN 2222
cg_has_pending || nl_fail "rollback --confirm-in left nothing pending"
R "$P" --db "$DB" config pending >"$NL_OUT" 2>&1; grep -q 'applied on trial' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "config pending"; }
R "$P" --db "$DB" config revert-now >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "revert-now"; }
nl_assert_nft_has cg-svc-block
nl_expect_no_tcp "revert-now: back to the generation before the rollback" C $NL_RTR_LAN 2222
cg_no_pending || nl_fail "revert-now left pending"
R "$P" --db "$DB" config rollback "$GEN_BEFORE" --confirm-in 1 >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "rollback --confirm-in (2)"; }
R "$P" --db "$DB" config confirm >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "confirm"; }
cg_no_pending || nl_fail "CLI confirm left pending"
nl_assert_nft_lacks cg-svc-block
nl_ok "rollback --confirm-in, pending, revert-now and confirm work from the CLI, each proven on the ruleset"
# --confirm-in is refused when nothing can enforce the deadline, and changes nothing
cg_applyd_stop
fp=$(nl_ruleset_fingerprint)
if R "$P" --db "$DB" config rollback "$GEN_WITH" --confirm-in 1 >"$NL_OUT" 2>&1; then nl_fail "--confirm-in worked without applyd"; fi
grep -q 'needs `patronus applyd`' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "wrong refusal: $(cat "$NL_OUT")"; }
[ "$(nl_ruleset_fingerprint)" = "$fp" ] || nl_fail "the refused rollback changed the ruleset"
nl_ok "without applyd the on-trial apply is refused up front and nothing changes"
cg_applyd_start

echo "=== 6. the declarative file"
R "$P" --db "$DB" config export --declarative -o /t/cg1.yaml 2>"$NL_OUT" || { cat "$NL_OUT"; nl_fail "export --declarative"; }
[ "$(stat -c %a /t/cg1.yaml)" = 600 ] || nl_fail "declarative file is not 0600"
grep -q 'patronus_config_version: 1' /t/cg1.yaml || nl_fail "no version header"
grep -q 'cg-OLD-SECRET' /t/cg1.yaml && nl_fail "secret in the default export"
R "$P" --db "$DB" config import /t/cg1.yaml >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "import of the export"; }
grep -q 'identical' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "unchanged import not recognised"; }
R "$P" --db "$DB" config export --declarative -o /t/cg2.yaml 2>/dev/null
cmp /t/cg1.yaml /t/cg2.yaml || nl_fail "export -> import -> export is not a fixed point"
nl_ok "export -> import -> export is byte-identical; the file is 0600 and carries no secrets"
[ "$(sqlite3 "$DB" "select value from system_config where key='smtp.password'")" = cg-OLD-SECRET ] || nl_fail "the excluded secret was lost by the import"
nl_ok "an import without secrets kept the stored secret"
R "$P" --db "$DB" config export --declarative --include-secrets -o /t/cg-secrets.yaml 2>/dev/null
grep -q 'cg-OLD-SECRET' /t/cg-secrets.yaml || nl_fail "--include-secrets lacks the secret"
rm -f /t/cg-secrets.yaml
# edit: a new rule through the file, dry run first
# build the edited file from a real exported rule shape: add the rule through the API, export, remove it again
nl_api POST /firewall/rules "$SVCBLOCK"; [ "$NL_CODE" = 201 ] || nl_fail "svc rule (file): $NL_CODE"
R "$P" --db "$DB" config export --declarative -o /t/cg-with.yaml 2>/dev/null
nl_api GET /firewall/rules
id=$(nl_json "$NL_OUT" "[r['id'] for r in d if r['name']=='cg-svc-block'][0]")
nl_api DELETE "/firewall/rules/$id"; [ "$NL_CODE" = 200 ] || nl_fail "delete cg-svc-block: $NL_CODE"
nl_assert_nft_lacks cg-svc-block
R "$P" --db "$DB" config import /t/cg-with.yaml --dry-run >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "import --dry-run"; }
grep -q 'cg-svc-block' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "dry run did not show the diff"; }
nl_assert_nft_lacks cg-svc-block
nl_ok "import --dry-run shows the diff against live and changes nothing"
R "$P" --db "$DB" config export --declarative -o /t/cg-pre.yaml 2>/dev/null
CG_LR0=$(cg_last_revert)
R "$P" --db "$DB" config import /t/cg-with.yaml --confirm-in 1 >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "import --confirm-in"; }
nl_assert_nft_has cg-svc-block
nl_expect_no_tcp "imported file: router :2222 blocked" C $NL_RTR_LAN 2222
[ "$(cg_gen_field "g['kind']")" = import ] || nl_fail "import is not a generation of kind import"
cg_has_pending || nl_fail "import --confirm-in left nothing pending"
cg_set_deadline 4
nl_wait 60 cg_reverted || nl_fail "the import was not reverted"
nl_assert_nft_lacks cg-svc-block
nl_expect_tcp "imported on trial, not confirmed: router :2222 open again" C $NL_RTR_LAN 2222
R "$P" --db "$DB" config export --declarative -o /t/cg3.yaml 2>/dev/null
cmp /t/cg-pre.yaml /t/cg3.yaml || { diff /t/cg-pre.yaml /t/cg3.yaml | head -20; nl_fail "after import -> revert the exported file differs from the one before"; }
nl_ok "import --confirm-in applied the file as a generation and the timer reverted it; the export is the same file as before"
# a file without the anti-lockout rule: the rule is kept
python3 - <<'PY'
import re
lines = open("/t/cg-with.yaml").read().split("\n")
start = lines.index("  firewall_rules:")
end = next((j for j in range(start + 1, len(lines)) if re.match(r"^  [A-Za-z_]", lines[j]) or re.match(r"^\S", lines[j])), len(lines))
heads = [j for j in range(start + 1, end) if lines[j].startswith("  - ")]
for n, h in enumerate(heads):
    stop = heads[n + 1] if n + 1 < len(heads) else end
    if any("name: Anti-lockout" in l for l in lines[h:stop]):
        del lines[h:stop]
        break
else:
    raise SystemExit("anti-lockout item not found in the exported file")
open("/t/cg-nolock.yaml", "w").write("\n".join(lines))
PY
grep -q 'name: Anti-lockout' /t/cg-nolock.yaml && nl_fail "test file still has the anti-lockout rule"
R "$P" --db "$DB" config import /t/cg-nolock.yaml >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "import without anti-lockout"; }
[ "$(sqlite3 "$DB" "select count(*) from firewall_rules where origin='system'")" -ge 1 ] || nl_fail "anti-lockout rule is gone from the store"
nl_assert_nft_has "iifname \"$NL_LAN_IF\" tcp dport { 22, 8443 } accept"
nl_expect_tcp "anti-lockout still holds after importing a file that dropped it" C $NL_RTR_LAN 22
R "$P" --db "$DB" config import /t/cg1.yaml >/dev/null 2>&1 || true
nl_api GET /system/generations
nl_ok "an imported file cannot remove the anti-lockout rule"

cg_stop_all
nl_assert_store_ok "$DB"
nl_down
echo "JOURNEY CONFIG GENERATIONS: ALL CHECKS PASSED"
