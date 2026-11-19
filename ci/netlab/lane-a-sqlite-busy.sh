#!/usr/bin/env bash
# Lane A regression: the harness' sqlite3 waits for a busy store instead of failing.
#
# Daemons under test commit to the config store (journal_mode=DELETE) while a scenario
# reads it with the sqlite3 CLI. The CLI's default busy timeout is 0, so a read that lands
# in a commit window printed "database is locked" and the scenario saw an empty value
# (lane-n-dhcp6pd run 2106). lib.sh now wraps sqlite3 with a busy timeout; this proves
#  1. the symptom is real here: the bare CLI is refused while another connection holds
#     the write lock (so this test can go red), and
#  2. the library's sqlite3 waits for the lock to clear and returns the row.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=$NL_T/lane-a-sqlite-busy.db
HOLD_SECS=${NL_SQLITE_TEST_HOLD_SECS:-3}
rm -f "$DB" "$DB-journal"
command sqlite3 "$DB" "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('stored');"

# another connection takes the write lock and keeps it for HOLD_SECS
{ echo 'BEGIN EXCLUSIVE;'; sleep "$HOLD_SECS"; echo 'COMMIT;'; } | command sqlite3 "$DB" >/dev/null &
HOLDER=$!
trap 'kill "$HOLDER" 2>/dev/null || true' EXIT

# wait until the lock is really held (bare CLI refused)
held=0
for _ in $(seq 1 40); do
  out=$(command sqlite3 "$DB" 'SELECT v FROM t;' 2>&1 || true)
  case "$out" in *"database is locked"*) held=1; break ;; esac
  sleep 0.05
done
[ "$held" = 1 ] || nl_fail "could not make the store busy (bare sqlite3 said: $out)"
nl_ok "bare sqlite3 is refused while the store is locked (the symptom)"

start=$(date +%s)
got=$(sqlite3 "$DB" 'SELECT v FROM t;') || nl_fail "library sqlite3 failed on a busy store"
[ "$got" = stored ] || nl_fail "library sqlite3 returned '$got' on a busy store"
waited=$(( $(date +%s) - start ))
nl_ok "library sqlite3 waited ${waited}s for the lock and read the row"

# children started with bash -c get the same behaviour
wait "$HOLDER" || true
trap - EXIT
[ "$(bash -c 'sqlite3 "$1" "SELECT v FROM t;"' _ "$DB")" = stored ] || nl_fail "exported sqlite3 missing in a bash -c child"
nl_ok "sqlite3 wrapper is exported to bash -c children"
echo "PASS lane-a-sqlite-busy"
