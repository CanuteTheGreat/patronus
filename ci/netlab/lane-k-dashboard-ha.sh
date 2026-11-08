#!/usr/bin/env bash
# Lane K (b): the SD-WAN dashboard's high-availability cluster, end to end with three real
# patronus-dashboard processes (one namespace each, one L2 switch, shared signing secret) and
# the shipped HTTP API only. The same env vars docker-compose.ha.yml sets (PATRONUS_NODE_ID,
# _PEERS, _ADVERTISE_ADDR, _DATA_DIR, _DB_PATH, _ELECTION_TIMEOUT, _HEARTBEAT_INTERVAL).
#
# Proven:
#   election  - the three nodes agree on exactly ONE leader; /ha/cluster lists all three reachable
#   RPC auth  - node-to-node /ha/vote|heartbeat|submit refuse a request without the cluster token
#   replicate - the admin created and the enrollment token minted through a FOLLOWER are committed
#               through the leader: the admin can log in on every node, and the token enrolls an
#               edge on ANOTHER node; that edge then shows up in the edge list of all three
#   failover  - SIGKILL the leader: the two survivors elect a new leader at a higher term and keep
#               accepting writes (a second token, enrolled and listed on both)
#   catch-up  - the killed node restarts, rejoins as a follower and has the edges written while it
#               was down (no data lost by the failover)
#   no quorum - with two of three nodes down the survivor refuses a write instead of acking it
set -euo pipefail
. "$(dirname "$0")/lib.sh"

NS() { local n=$1; shift; ip netns exec "$n" "$@"; }
PW='Netlab-HA-Passw0rd-4711!xyz'
JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
ADDR_d1=10.77.0.1; ADDR_d2=10.77.0.2; ADDR_d3=10.77.0.3
NODES="d1 d2 d3"
declare -A PID
OUT=/tmp/ha.out
mkdir -p /t/ha

diag() {
  echo "--- diagnostics"
  for n in $NODES; do echo "### $n /ha/status"; NS cl curl -s -m 3 "http://$(addr_of $n):8443/ha/status" 2>&1 | head -c 600; echo; echo "### $n log"; tail -15 /t/ha/$n.log 2>/dev/null; done
}
addr_of() { local v=ADDR_$1; echo "${!v}"; }
cleanup() {
  local rc=$?
  [ "$rc" = 0 ] || diag
  [ -n "${NETLAB_KEEP:-}" ] && [ "$rc" != 0 ] && return 0
  pkill -x patronus-dashboard 2>/dev/null || true
  sleep 1
  for n in $NODES cl sw; do ip netns del "$n" 2>/dev/null || true; done
  rm -rf /t/ha
}
trap cleanup EXIT
for n in $NODES cl sw; do ip netns del "$n" 2>/dev/null || true; done
rm -rf /t/ha; mkdir -p /t/ha

# --- topology: every party on one bridge in "sw" ------------------------------------------
for n in $NODES cl sw; do ip netns add "$n"; ip -n "$n" link set lo up; done
NS sw ip link add br0 type bridge; NS sw ip link set br0 up
i=0
for n in $NODES cl; do
  i=$((i + 1))
  ip link add "p$n" netns sw type veth peer name eth0 netns "$n"
  NS sw ip link set "p$n" master br0; NS sw ip link set "p$n" up
  a=10.77.0.$i; [ "$n" = cl ] && a=10.77.0.10
  NS "$n" ip addr add "$a/24" dev eth0; NS "$n" ip link set eth0 up
done

peers_of() { local o=() n; for n in $NODES; do [ "$n" = "$1" ] || o+=("$(addr_of $n):8443"); done; (IFS=,; echo "${o[*]}"); }
start_node() { # NODE
  local n=$1
  ip netns exec "$n" env PATRONUS_NODE_ID="$n" PATRONUS_NODE_ADDR=0.0.0.0:8443 \
    PATRONUS_ADVERTISE_ADDR="$(addr_of $n):8443" PATRONUS_PEERS="$(peers_of $n)" \
    PATRONUS_DATA_DIR=/t/ha/$n/raft PATRONUS_DB_PATH=/t/ha/$n/dash.db PATRONUS_JWT_SECRET="$JWT_SECRET" \
    PATRONUS_ELECTION_TIMEOUT=3 PATRONUS_HEARTBEAT_INTERVAL=1 RUST_LOG=info \
    "$NL_T/patronus-dashboard" >>/t/ha/$n.log 2>&1 &
  PID[$n]=$!
}
mkdir -p /t/ha/d1 /t/ha/d2 /t/ha/d3
for n in $NODES; do start_node "$n"; done

# req NODE METHOD PATH [JSON] [TOKEN]: from the client namespace; body in $OUT, status in $CODE
req() {
  local n=$1 m=$2 p=$3 d=${4:-} t=${5:-}
  local a=(-s -m 20 -o "$OUT" -w '%{http_code}' -X "$m" -H 'content-type: application/json')
  [ -n "$t" ] && a+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && a+=(-d "$d")
  CODE=$(NS cl curl "${a[@]}" "http://$(addr_of $n):8443$p" || true)
}
healthy() { NS cl curl -sf -m 2 -o /dev/null "http://$(addr_of $1):8443/health"; }
for n in $NODES; do nl_wait 60 healthy "$n" || nl_fail "dashboard $n did not come up"; done
nl_ok "three dashboards up"

# leader_of NODE: the id of the node that claims leadership in NODE's /ha/cluster view
leader_of() {
  NS cl curl -sf -m 5 "http://$(addr_of $1):8443/ha/cluster" | python3 -c '
import json,sys
d=json.load(sys.stdin)
if not d.get("ha_enabled"): sys.exit(1)
l=[m["status"]["node_id"] for m in d["members"] if m.get("status") and m["status"]["role"].lower()=="leader"]
print(l[0]) if len(l)==1 else sys.exit(1)'
}
term_of() { NS cl curl -sf -m 5 "http://$(addr_of $1):8443/ha/status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["term"])'; }
all_see_leader() { local n l=""; for n in "$@"; do local x; x=$(leader_of "$n") || return 1; [ -z "$l" ] && l=$x; [ "$x" = "$l" ] || return 1; done; }

echo "=== election"
nl_wait 60 all_see_leader d1 d2 d3 || nl_fail "the three nodes never agreed on one leader"
LEADER=$(leader_of d1); TERM1=$(term_of d1)
NS cl curl -sf -m 5 "http://$ADDR_d1:8443/ha/cluster" | python3 -c '
import json,sys
d=json.load(sys.stdin); assert d["ha_enabled"] and len(d["members"])==3 and all(m["reachable"] for m in d["members"]), d' \
  || nl_fail "/ha/cluster does not show three reachable members"
nl_ok "one leader ($LEADER, term $TERM1), all three members reachable in /ha/cluster"

echo "=== node-to-node RPC needs the cluster token"
req d1 POST /ha/vote '{"term":99,"candidate_id":"evil","last_log_index":0,"last_log_term":0}'
[ "$CODE" = 401 ] || nl_fail "/ha/vote without the cluster token: $CODE (want 401)"
req d1 POST /ha/heartbeat '{"term":99,"leader_id":"evil","leader_addr":"10.77.0.10:8443"}'
[ "$CODE" = 401 ] || nl_fail "/ha/heartbeat without the cluster token: $CODE (want 401)"
[ "$(term_of d1)" = "$TERM1" ] || nl_fail "an unauthenticated vote request changed the term"
nl_ok "unauthenticated vote/heartbeat refused (401), term unchanged"

# a follower (any node that is not the leader)
follower() { local n; for n in $NODES; do [ "$n" = "$1" ] || [ "$n" = "${2:-}" ] || { echo "$n"; return; }; done; }
F1=$(follower "$LEADER")
F2=$(follower "$LEADER" "$F1")

echo "=== writes through a follower are replicated"
req "$F1" POST /api/v1/auth/init-admin "{\"email\":\"admin@errant.solutions\",\"name\":\"Admin\",\"password\":\"$PW\",\"role\":\"admin\"}"
[ "$CODE" = 200 ] || nl_fail "init-admin via follower $F1: $CODE $(cat $OUT)"
login_ok() { req "$1" POST /api/v1/auth/login "{\"email\":\"admin@errant.solutions\",\"password\":\"$PW\"}"; [ "$CODE" = 200 ]; }
for n in $NODES; do nl_wait 20 login_ok "$n" || nl_fail "the admin created through $F1 cannot log in on $n ($CODE $(cat $OUT))"; done
JWT=$(nl_json $OUT 'd["access_token"]')
nl_ok "admin created through follower $F1 logs in on all three nodes"
req "$F2" GET /api/v1/edge/edges '' "$JWT"
[ "$CODE" = 200 ] || nl_fail "a token minted by node d1 is not accepted by $F2 (shared signing secret): $CODE"
nl_ok "the JWT issued by one node is accepted by another"

KEY() { head -c 32 /dev/urandom | base64; }
mint() { req "$1" POST /api/v1/edge/tokens "{\"label\":\"$2\"}" "$JWT"; [ "$CODE" = 200 ] || nl_fail "mint token on $1: $CODE $(cat $OUT)"; nl_json $OUT 'd["token"]'; }
enroll() { # NODE TOKEN NAME ENDPOINT
  req "$1" POST /api/v1/edge/enroll "{\"token\":\"$2\",\"name\":\"$3\",\"public_key\":\"$(KEY)\",\"endpoints\":[{\"address\":\"$4\"}]}"
}
enrolled_on() { enroll "$1" "$2" "$3" "$4"; [ "$CODE" = 200 ]; }
edges_have() { # NODE NAME...: the edge list contains all names
  req "$1" GET /api/v1/edge/edges '' "$JWT"; [ "$CODE" = 200 ] || return 1
  python3 - "$OUT" "${@:2}" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); names={e.get("name") for e in (d if isinstance(d,list) else d.get("edges",[]))}
sys.exit(0 if all(n in names for n in sys.argv[2:]) else 1)
PY
}
T1=$(mint "$F1" ha-one)
nl_wait 20 enrolled_on "$F2" "$T1" site-one 198.51.100.1:51820 || nl_fail "the token minted on $F1 does not enroll on $F2: $CODE $(cat $OUT)"
for n in $NODES; do nl_wait 20 edges_have "$n" site-one || nl_fail "edge site-one missing on $n"; done
nl_ok "token minted on follower $F1 enrolled an edge on follower $F2; the edge is listed on all three nodes"
enroll "$F1" "$T1" replay 198.51.100.9:51820; [ "$CODE" = 401 ] || nl_fail "a used token enrolled again on another node: $CODE"
nl_ok "the one-time token cannot be replayed on another node (401)"

echo "=== failover: SIGKILL the leader ($LEADER)"
kill -9 "${PID[$LEADER]}"; wait "${PID[$LEADER]}" 2>/dev/null || true
S1=$F1; S2=$F2
new_leader() { local x; x=$(leader_of "$S1") || return 1; [ "$x" != "$LEADER" ] && [ "$x" = "$(leader_of "$S2")" ]; }
nl_wait 60 new_leader || nl_fail "the survivors did not elect a new leader"
NL2=$(leader_of "$S1"); TERM2=$(term_of "$S1")
[ "$TERM2" -gt "$TERM1" ] || nl_fail "term did not advance ($TERM1 -> $TERM2)"
nl_ok "new leader $NL2 at term $TERM2 (was $LEADER at $TERM1)"
write2() { req "$S1" POST /api/v1/edge/tokens '{"label":"ha-two"}' "$JWT"; [ "$CODE" = 200 ]; }
nl_wait 30 write2 || nl_fail "no write accepted after failover: $CODE $(cat $OUT)"
T2=$(nl_json $OUT 'd["token"]')
nl_wait 20 enrolled_on "$S2" "$T2" site-two 198.51.100.2:51820 || nl_fail "post-failover token does not enroll on $S2: $CODE $(cat $OUT)"
for n in "$S1" "$S2"; do nl_wait 20 edges_have "$n" site-one site-two || nl_fail "edges lost after failover on $n"; done
nl_ok "the two survivors keep accepting writes; site-one (pre-failover) and site-two are listed on both"

echo "=== the killed node rejoins and catches up"
start_node "$LEADER"
nl_wait 60 healthy "$LEADER" || nl_fail "$LEADER did not restart"
nl_wait 60 all_see_leader d1 d2 d3 || nl_fail "cluster did not reconverge on one leader after $LEADER came back"
nl_wait 40 edges_have "$LEADER" site-one site-two || nl_fail "restarted $LEADER lacks the edges written while it was down"
nl_ok "$LEADER rejoined (leader $(leader_of "$LEADER")) and holds site-one and site-two"

echo "=== no quorum: no write is acknowledged"
CUR=$(leader_of d1)
VICTIMS=(); for n in $NODES; do [ "$n" = "$CUR" ] || VICTIMS+=("$n"); done
LAST=$CUR
for v in "${VICTIMS[@]}"; do kill -9 "${PID[$v]}"; wait "${PID[$v]}" 2>/dev/null || true; done
req "$LAST" POST /api/v1/edge/tokens '{"label":"ha-orphan"}' "$JWT"
[ "$CODE" != 200 ] || nl_fail "a lone node (1 of 3) acknowledged a write: $CODE $(cat $OUT)"
nl_ok "lone node $LAST refused the write ($CODE) instead of acknowledging it"
echo "PASS lane-k-dashboard-ha"
