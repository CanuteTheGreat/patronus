#!/usr/bin/env bash
# Crash consistency: the process writing the configuration is killed with
# SIGKILL at a random moment (mid edit through the web UI, mid
# `patronus apply`), then the box "loses power" (fresh namespaces: empty
# kernel state) and boots. Every time:
#   - the store passes SQLite's integrity check,
#   - the boot apply succeeds and the safe baseline is loaded,
#   - the kernel enforces exactly the rules the store holds (no rule the UI
#     reported as saved is lost, no half-written rule appears),
#   - the LAN is online and the WAN shut.
# NETLAB_POWER_CUTS sets the number of rounds (per-push: 4, nightly: 30).
#
# What this does not simulate: page-cache loss on real power failure. The
# store runs with synchronous=FULL and a rollback journal (asserted by
# patronus-config's file_store_is_durable_rollback_journal_with_full_sync),
# which is SQLite's documented power-loss-safe configuration.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROUNDS=${NETLAB_POWER_CUTS:-4}
DB=/t/pc.db
rm -f "$DB"
nl_write_installer_toml
nl_boot "$DB"

# rules as the store has them vs. as the kernel has them (by comment)
store_rules() { sqlite3 "$DB" "SELECT name FROM firewall_rules WHERE enabled = 1 AND origin = 'user' ORDER BY name"; }
kernel_rules() { nl_ruleset | grep -o 'comment "pc-[0-9-]*"' | sed 's/comment "//;s/"//' | sort -u; }

for round in $(seq 1 "$ROUNDS"); do
  echo "=== power cut $round/$ROUNDS"
  nl_web_start "$DB"; nl_login
  saved=/t/pc-saved-$round
  : > "$saved"
  # the admin keeps editing: add rules, delete every third one
  (
    i=0
    while true; do
      i=$((i + 1))
      nl_api POST /firewall/rules "{\"name\":\"pc-$round-$i\",\"chain\":\"forward\",\"action\":\"drop\",\"interface\":\"@lan\",\"protocol\":\"tcp\",\"source\":\"any\",\"destination\":\"198.51.100.$((100 + i % 100))\",\"port\":\"$((1000 + i))\",\"description\":\"pc-$round-$i\",\"enabled\":true}" || true
      if [ "$NL_CODE" = 201 ]; then
        echo "pc-$round-$i" >> "$saved"
        id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
        if [ $((i % 3)) = 0 ]; then
          nl_api DELETE "/firewall/rules/$id" || true
          [ "$NL_CODE" = 200 ] && sed -i "/^pc-$round-$i\$/d" "$saved"
        fi
      fi
    done
  ) &
  editor=$!
  sleep "$(python3 -c 'import random; print(round(random.uniform(0.5, 3.0), 2))')"
  kill -9 "$NL_WEB_PID"; wait "$NL_WEB_PID" 2>/dev/null || true; NL_WEB_PID=
  kill "$editor" 2>/dev/null; wait "$editor" 2>/dev/null || true
  # also kill a boot-time apply part way through, every other round.
  # Not via the R() helper: `R ... &` backgrounds a bash subshell running the
  # function, so $! is that subshell and kill -9 orphaned the real patronus
  # process, which kept running and held the store's write lock (nightly run
  # 420 died on round 26: "database is locked" from the integrity check).
  # `ip netns exec` execs into the binary, so here $! is patronus itself.
  if [ $((round % 2)) = 0 ]; then
    ip netns exec nl-rtr "$P" --db "$DB" apply --bootstrap "$NL_TOML" >/dev/null 2>&1 &
    a=$!
    sleep "0.0$((RANDOM % 9 + 1))"
    kill -9 "$a" 2>/dev/null || true; wait "$a" 2>/dev/null || true
  fi

  # power is back
  nl_assert_store_ok "$DB"
  nl_boot "$DB"
  nl_assert_router_baseline
  if ! diff <(store_rules) <(kernel_rules) >/tmp/pc.diff; then
    cat /tmp/pc.diff; nl_fail "kernel rules differ from the store after the crash"
  fi
  # every rule the UI confirmed (201, not deleted afterwards) is still there
  # (the last confirmation may have raced the kill: allow that one line only)
  missing=$(comm -23 <(sort "$saved") <(store_rules) | wc -l)
  [ "$missing" -le 1 ] || { comm -23 <(sort "$saved") <(store_rules); nl_fail "$missing confirmed rules lost"; }
  nl_ok "store intact, $(store_rules | wc -l) user rules in store == kernel, $(wc -l <"$saved") confirmed this round, $missing in flight"
  nl_expect_online
  nl_expect_wan_closed
done

nl_down
echo "FAILURE POWER CUT: ALL $ROUNDS ROUNDS PASSED"
