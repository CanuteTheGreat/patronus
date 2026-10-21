#!/usr/bin/env bash
# Lane M: GitOps in the shipped binary. A firewall rule committed to a git
# repository reaches the box through `patronus gitops sync|watch` (what the
# patronus-gitops service runs), lands in the config store, is enforced by
# nftables, follows later commits (change / delete / re-add) and survives a
# reboot (`patronus apply` from the store alone).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DIR=/t/gitops
DB=$DIR/config.db
UP=$DIR/upstream
rm -rf "$DIR"; mkdir -p "$DIR"
command -v git >/dev/null || { apt-get install -y -qq git >/dev/null; }

nl_write_installer_toml
cat >>"$NL_TOML" <<EOF

[gitops]
repo_url = "$UP"
branch = "main"
local_path = "$DIR/clone"
config_path = "firewall"
poll_interval_secs = 5
auto_apply = true
EOF

g() { git -C "$UP" -c user.name=QA -c user.email=qa@errant.solutions "$@"; }
rule() { # NAME PORT ACTION
  cat <<EOF
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata:
    name: $1
  spec:
    action: $3
    interface: "@lan"
    direction: inbound
    source: { address: "192.168.50.0/24" }
    destination: { address: "$NL_WWW", ports: [$2] }
    protocol: tcp
    enabled: true
EOF
}
git init -q -b main "$UP"
mkdir -p "$UP/firewall" "$UP/docs"
rule block-www-9000 9000 reject >"$UP/firewall/block.yaml"
echo "not a config" >"$UP/docs/README.md"
g add -A && g commit -qm "block LAN -> www:9000"

wait_nft() { # has|lacks TEXT SECONDS
  local i rs
  for i in $(seq 1 "$3"); do
    rs=$(nl_ruleset)
    if [ "$1" = has ] && grep -qF -- "$2" <<<"$rs"; then return 0; fi
    if [ "$1" = lacks ] && ! grep -qF -- "$2" <<<"$rs"; then return 0; fi
    sleep 1
  done
  echo "$rs"; nl_fail "after ${3}s the ruleset still $([ "$1" = has ] && echo lacks || echo has): $2"
}

echo "=== boot without the repository applied"
nl_boot "$DB"
nl_expect_online
nl_expect_tcp "LAN -> www:9000 before GitOps" C $NL_WWW 9000

echo "=== gitops sync --dry-run: validated, nothing applied"
R "$P" --db "$DB" gitops sync --dry-run --bootstrap "$NL_TOML" --state-dir "$DIR/state" >"$NL_OUT" 2>&1 \
  || { cat "$NL_OUT"; nl_fail "gitops sync --dry-run"; }
grep -q "1 resource(s) in 1 file(s)" "$NL_OUT" && grep -q "not applied" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "dry-run output"; }
nl_assert_nft_lacks "gitops:block-www-9000"
nl_expect_tcp "LAN -> www:9000 after a dry run" C $NL_WWW 9000

echo "=== the patronus-gitops service (gitops watch) applies the commit"
nl_bg R "$P" --db "$DB" gitops watch --bootstrap "$NL_TOML" --state-dir "$DIR/state"
wait_nft has "gitops:block-www-9000" 30
nl_assert_nft_has "ip daddr 198.51.100.10 tcp dport 9000 reject with tcp reset" "gitops:block-www-9000"
nl_expect_no_tcp "LAN -> www:9000 rejected by the git rule" C $NL_WWW 9000
nl_expect_http "LAN -> www:80 still works" http://www.example.test/ "www.example.test sees $NL_RTR_WAN"
n=$(sqlite3 "$DB" "SELECT count(*) FROM firewall_rules WHERE origin='gitops' AND name='block-www-9000'")
[ "$n" -ge 1 ] || nl_fail "store has no gitops rows for block-www-9000"
nl_ok "config store holds the git rule ($n row(s), origin gitops)"

echo "=== a later commit changes the port: followed without a restart"
rule block-www-9000 8080 reject >"$UP/firewall/block.yaml"
g commit -qam "move the block to 8080"
wait_nft has "tcp dport 8080 reject with tcp reset" 30
nl_assert_nft_lacks "tcp dport 9000 reject"
nl_expect_tcp "LAN -> www:9000 open again" C $NL_WWW 9000
nl_expect_http_blocked "LAN -> www:8080 now rejected" http://www.example.test:8080/

echo "=== deleting the file in git removes the rule"
g rm -q firewall/block.yaml && g commit -qm "drop the block"
wait_nft lacks "gitops:block-www-9000" 30
nl_expect_http "LAN -> www:8080 works again" http://www.example.test:8080/ "www.example.test sees $NL_RTR_WAN"
n=$(sqlite3 "$DB" "SELECT count(*) FROM firewall_rules WHERE origin='gitops'")
[ "$n" = 0 ] || nl_fail "store still has $n gitops row(s)"
nl_ok "store has no gitops rows after the delete commit"

echo "=== re-added rule survives a reboot (store + patronus apply, no watcher)"
mkdir -p "$UP/firewall"   # `git rm` of the last file removed the directory
rule block-www-9000 9000 reject >"$UP/firewall/block.yaml"
g add -A && g commit -qm "block again"
wait_nft has "gitops:block-www-9000" 30
nl_boot "$DB"   # kills the watcher with the old namespaces
nl_assert_nft_has "gitops:block-www-9000"
nl_expect_no_tcp "after reboot: LAN -> www:9000 still rejected" C $NL_WWW 9000
nl_expect_online

echo "=== a broken commit is reported and changes nothing"
echo "- kind: [" >"$UP/firewall/bad.yaml"
g add -A && g commit -qm "broken"
if R "$P" --db "$DB" gitops sync --apply --bootstrap "$NL_TOML" --state-dir "$DIR/state" >"$NL_OUT" 2>&1; then
  cat "$NL_OUT"; nl_fail "sync of a broken commit succeeded"
fi
grep -q "bad.yaml" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "error does not name the broken file"; }
nl_assert_nft_has "gitops:block-www-9000"
nl_ok "broken commit refused with the file named, ruleset unchanged"

nl_down
echo "=== lane M gitops netlab: all checks passed"
