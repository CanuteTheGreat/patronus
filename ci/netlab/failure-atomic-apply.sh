#!/usr/bin/env bash
# Failure + recovery: an apply that cannot succeed must never leave the box
# open or lock the admin out.
#  A. a rule the kernel rejects, added through the web API: refused, the
#     store and the loaded ruleset are unchanged, traffic still enforced.
#  B. a damaged row in the store at boot: fail closed into the lockdown
#     ruleset (LAN can still reach SSH/UI, nothing is forwarded, WAN shut);
#     `patronus config rollback` repairs it.
#  C. the same damaged row on a running box: `patronus apply` fails and the
#     previous ruleset stays loaded, byte for byte.
#  D. restoring a backup that the kernel rejects: the import is reverted.
#  E. nft unusable at boot (no ruleset can load at all): forwarding is
#     switched off, so the box is not an open router.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/fail.db
rm -f "$DB"
nl_write_installer_toml
LONG_IF=averyveryverylongifname0   # > IFNAMSIZ: renders, but nft refuses it

# Fault injection: an `nft` that refuses any ruleset mentioning
# "kernel-rejects-me" (the way the kernel refuses a rule it cannot load),
# and passes everything else to the real nft. Independent of what the
# validation layer happens to catch today.
mkdir -p /t/faultnft
REAL_NFT=$(command -v nft)
cat > /t/faultnft/nft <<EOF
#!/bin/sh
if [ "\$1" = -f ]; then
  script=\$(cat)
  if printf '%s' "\$script" | grep kernel-rejects-me >/dev/null; then
    echo "Error: Could not process rule: Operation not supported (injected)" >&2; exit 1
  fi
  printf '%s\n' "\$script" | $REAL_NFT "\$@"
else
  exec $REAL_NFT "\$@"
fi
EOF
chmod +x /t/faultnft/nft

echo "=== A. kernel-rejected rule through the web API"
nl_boot "$DB"
PATH=/t/faultnft:$PATH nl_web_start "$DB"
nl_login
nl_api POST /firewall/rules '{"name":"keep-me","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"keep-me","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add keep-me: $NL_CODE $(cat "$NL_OUT")"
KEEP_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
before=$(nl_ruleset_fingerprint)
nl_api POST /firewall/rules '{"name":"bad","chain":"forward","action":"accept","interface":"@lan","protocol":"tcp","source":"any","destination":"any","port":"80","description":"kernel-rejects-me","enabled":true}'
[ "$NL_CODE" = 500 ] && grep -q 'failed to apply firewall to nftables' "$NL_OUT" \
  || nl_fail "kernel-rejected rule: want 500 'failed to apply', got $NL_CODE $(cat "$NL_OUT")"
nl_ok "API refused the rule nft could not load ($NL_CODE: $(head -c 160 "$NL_OUT"))"
[ "$(nl_ruleset_fingerprint)" = "$before" ] || nl_fail "loaded ruleset changed after a failed apply"
nl_ok "loaded ruleset unchanged"
nl_api GET /firewall/rules
if grep -q kernel-rejects-me "$NL_OUT"; then nl_fail "store kept the rejected rule"; fi
nl_ok "store does not keep the rejected rule"
nl_expect_http_blocked "keep-me still enforced" http://blocked.example.test/
nl_expect_online
nl_web_stop
nl_boot "$DB"
nl_assert_nft_has 'keep-me'
nl_assert_nft_lacks 'kernel-rejects-me'

echo "=== B. damaged row at boot -> lockdown, then repair by rollback"
REV=$(R "$P" --db "$DB" config revisions | awk '/before create firewall rule keep-me/{print $1; exit}')
[ -n "$REV" ] || nl_fail "no revision before keep-me"
sqlite3 "$DB" "UPDATE firewall_rules SET dport = 'garbage' WHERE id = $KEEP_ID"
nl_up
if nl_apply "$DB"; then cat "$NL_OUT"; nl_fail "boot apply succeeded with a damaged rule"; fi
grep -q 'lockdown ruleset loaded' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no lockdown message"; }
nl_ok "boot apply failed closed: $(grep -o 'lockdown ruleset loaded[^)]*' "$NL_OUT")"
nl_assert_lockdown
R "$P" --db "$DB" config rollback "$REV" >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "rollback"; }
nl_ok "patronus config rollback $REV repaired the store"
nl_assert_router_baseline
nl_expect_online

echo "=== C. damaged row on a running box -> previous ruleset stays"
nl_web_start "$DB"; nl_login
nl_api POST /firewall/rules '{"name":"keep-me-2","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"keep-me-2","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add keep-me-2: $NL_CODE"
ID2=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
nl_web_stop
before=$(nl_ruleset_fingerprint)
sqlite3 "$DB" "UPDATE firewall_rules SET protocol = 'sctp' WHERE id = $ID2"
if nl_apply "$DB"; then nl_fail "apply succeeded with a damaged rule"; fi
grep -q 'previous ruleset left in place' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no 'previous ruleset left' message"; }
[ "$(nl_ruleset_fingerprint)" = "$before" ] || nl_fail "ruleset changed after a failed runtime apply"
nl_ok "failed runtime apply left the previous ruleset loaded unchanged"
nl_expect_http_blocked "keep-me-2 still enforced" http://blocked.example.test/
sqlite3 "$DB" "UPDATE firewall_rules SET protocol = 'tcp' WHERE id = $ID2"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "apply after repair"; }

echo "=== D. restoring a backup the kernel rejects is reverted"
R "$P" --db "$DB" config export -o /t/good.json 2>/dev/null
[ "$(stat -c %a /t/good.json)" = 600 ] || nl_fail "export is not mode 0600"
python3 - /t/good.json /t/bad.json "$LONG_IF" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
for r in d["tables"]["firewall_rules"]:
    if r["name"] == "keep-me-2":
        r["interface_in"] = sys.argv[3]
json.dump(d, open(sys.argv[2], "w"))
EOF
before=$(nl_ruleset_fingerprint)
if R "$P" --db "$DB" config import /t/bad.json >"$NL_OUT" 2>&1; then nl_fail "bad import succeeded"; fi
grep -q 'previous configuration was restored' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "import not reverted"; }
[ "$(nl_ruleset_fingerprint)" = "$before" ] || nl_fail "ruleset changed by a reverted import"
R "$P" --db "$DB" config export -o /t/after.json 2>/dev/null
python3 - /t/good.json /t/after.json <<'EOF'
import json, sys
a, b = (json.load(open(p))["tables"] for p in sys.argv[1:3])
assert a == b, "store differs after a reverted import"
EOF
nl_ok "rejected backup import reverted: store and ruleset as before"
nl_up; nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot after reverted import"; }
nl_expect_http_blocked "after reboot keep-me-2 enforced" http://blocked.example.test/
nl_expect_online

echo "=== E. nft unusable at boot -> forwarding off"
nl_up
mkdir -p /t/nonft   # an empty PATH: `nft` cannot be run
if R env PATH=/t/nonft "$P" --db "$DB" apply --bootstrap "$NL_TOML" >"$NL_OUT" 2>&1; then nl_fail "apply without nft succeeded"; fi
grep -q 'forwarding switched off' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "forwarding not switched off"; }
nl_assert_sysctl net.ipv4.ip_forward 0
nl_assert_sysctl net.ipv6.conf.all.forwarding 0
nl_expect_http_blocked "LAN -> internet with no firewall loaded" "http://$NL_WWW/"
nl_ok "no ruleset could load: the box stopped routing instead of forwarding unfiltered"

echo "=== F. store file unreadable at boot -> lockdown from patronus.toml"
cp "$DB" /t/fail-good.db
head -c 8192 /dev/urandom > "$DB"
nl_up
if nl_apply "$DB"; then nl_fail "apply with a garbage store succeeded"; fi
grep -q 'lockdown ruleset loaded' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no lockdown with an unreadable store"; }
nl_ok "unreadable store: $(tail -1 "$NL_OUT" | cut -c1-160)"
nl_assert_lockdown
cp /t/fail-good.db "$DB"
nl_boot "$DB"
nl_expect_online

nl_down
echo "FAILURE ATOMIC APPLY: ALL CHECKS PASSED"
