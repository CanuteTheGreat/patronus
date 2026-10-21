#!/usr/bin/env bash
# Real 3-node HA dashboard stack end-to-end test (run by rust-ci.yml after
# the Gentoo image build). Mirrors docker-compose.ha.yml: three
# patronus-dashboard nodes from the emerge-built image + haproxy:2.8-alpine
# with a cert produced by generate-ha-certs.sh, all on one private network.
#
# Proves, against the real running product:
#   * generate-ha-certs.sh output is loadable by haproxy (it used to
#     restart-loop on the 0600 key) and haproxy serves TLS + the UI;
#   * the haproxy stats page has no baked-in credentials;
#   * one leader is elected and every node agrees on it (/ha/status,
#     /ha/cluster -- the data behind the UI's Cluster view);
#   * writes made through haproxy AND directly on a follower replicate to
#     all three nodes (same site ids everywhere) and a user created on one
#     node can log in on every node (shared JWT secret + replicated users);
#   * after `docker kill` of the leader a new leader is elected that has
#     every write, writes keep working through haproxy, both survivors end
#     with identical site lists, and the killed node catches up on restart;
#   * the dashboard refuses to start with a known/placeholder JWT secret.
#
# Usage: ci/ha-e2e.sh <image> [built-frontend-dir]
# Everything it creates is removed on exit. Every container is memory/CPU capped.
set -euo pipefail

IMAGE=${1:?usage: ci/ha-e2e.sh <image> [static-dir]}
STATIC=${2:-}
REPO=$(cd "$(dirname "$0")/.." && pwd)
TAG=pha-${GITHUB_RUN_ID:-local}-$$
NET=$TAG-net
SECRET=$(openssl rand -hex 32)
STATS_PW=$(openssl rand -hex 12)
WORK=$(mktemp -d)
ADMIN_EMAIL=e2e-admin@example.test
ADMIN_PW='E2e-Adm1n-Passw0rd!'

log() { echo "[ha-e2e] $*"; }
fail() { echo "::error::[ha-e2e] $*"; exit 1; }

cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then
    for c in d1 d2 d3 hap; do
      echo "----- logs: $TAG-$c -----"; docker logs --tail 60 "$TAG-$c" 2>&1 || true
    done
  fi
  docker rm -f -v "$TAG-d1" "$TAG-d2" "$TAG-d3" "$TAG-hap" "$TAG-bad" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit $rc
}
trap cleanup EXIT

# All HTTP goes through a throwaway curl container on the stack's network,
# so this works the same from a CI job container (Docker-outside-of-Docker)
# and from a plain host shell.
docker pull -q curlimages/curl:latest >/dev/null
docker pull -q haproxy:2.8-alpine >/dev/null
hc() { docker run --rm --network "$NET" --memory 64m curlimages/curl:latest -sS --max-time 10 "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

docker network create "$NET" >/dev/null

# --- 0. weak secret is refused --------------------------------------------
log "dashboard must refuse a known default JWT secret"
if docker run --name "$TAG-bad" --memory 256m --cpus 0.5 \
     -e PATRONUS_JWT_SECRET=your-secret-key-change-in-production \
     -e PATRONUS_DB_PATH=/data/dashboard.db -w /app "$IMAGE" patronus-dashboard >"$WORK/bad.log" 2>&1; then
  fail "patronus-dashboard started with the old hardcoded secret"
fi
grep -qi "publicly known default" "$WORK/bad.log" || { cat "$WORK/bad.log"; fail "unexpected refusal reason"; }
docker rm -f "$TAG-bad" >/dev/null

# --- 1. three dashboard nodes ----------------------------------------------
start_node() {
  local i=$1 peers=$2
  docker create --name "$TAG-d$i" --network "$NET" --network-alias "dashboard$i" \
    --hostname "dashboard$i" --memory 512m --cpus 1 -w /app \
    -e PATRONUS_NODE_ID="dashboard$i" -e PATRONUS_NODE_ADDR=0.0.0.0:8443 \
    -e PATRONUS_PEERS="$peers" -e PATRONUS_DATA_DIR=/data/raft \
    -e PATRONUS_DB_PATH=/data/dashboard.db -e PATRONUS_JWT_SECRET="$SECRET" \
    -e PATRONUS_ELECTION_TIMEOUT=3 -e PATRONUS_HEARTBEAT_INTERVAL=1 \
    -e RUST_LOG=patronus_dashboard=info \
    "$IMAGE" patronus-dashboard >/dev/null
  if [ -n "$STATIC" ]; then docker cp "$STATIC/." "$TAG-d$i:/app/static/"; fi
  docker start "$TAG-d$i" >/dev/null
}
start_node 1 dashboard2:8443,dashboard3:8443
start_node 2 dashboard1:8443,dashboard3:8443
start_node 3 dashboard1:8443,dashboard2:8443

for i in 1 2 3; do
  for _ in $(seq 1 60); do
    hc -f "http://dashboard$i:8443/health/ready" >/dev/null 2>&1 && break; sleep 1
  done
  hc -f "http://dashboard$i:8443/health/ready" >/dev/null || fail "dashboard$i never became ready"
done
log "all three nodes ready"

leader_of() { # prints the leader all listed nodes agree on, or nothing
  local ids="" l
  for n in "$@"; do
    l=$(hc "http://$n:8443/ha/status" 2>/dev/null | json "d['leader_id'] or ''" 2>/dev/null || true)
    ids="$ids $l"
  done
  l=$(echo $ids | tr ' ' '\n' | sort -u)
  if [ "$(echo "$l" | wc -l)" = 1 ] && [ -n "$l" ]; then echo "$l"; fi
}
wait_leader() { # [--not <old-leader>] nodes...  (followers keep reporting
  # the dead leader until their election timeout fires, so after a failover
  # wait for agreement on a *different* leader)
  local l="" not=""
  if [ "$1" = --not ]; then not=$2; shift 2; fi
  for _ in $(seq 1 60); do
    l=$(leader_of "$@")
    [ -n "$l" ] && [ "$l" != "$not" ] && break
    l=""; sleep 1
  done
  [ -n "$l" ] || fail "no agreed leader${not:+ other than $not} among $*"
  echo "$l"
}
LEADER=$(wait_leader dashboard1 dashboard2 dashboard3)
log "leader elected: $LEADER"

# --- 2. haproxy with the generated cert -----------------------------------
mkdir -p "$WORK/repo"
cp "$REPO/generate-ha-certs.sh" "$WORK/repo/"
(cd "$WORK/repo" && ./generate-ha-certs.sh >/dev/null)
[ "$(stat -c %a "$WORK/repo/certs/patronus.pem")" = 600 ] || fail "private key PEM must stay 0600"
# Run haproxy as the user docker-compose.ha.yml actually configures, so
# dropping `user: root` from the compose file (the restart-loop bug) fails here.
HAP_USER=$(awk '/^  haproxy:/{f=1;next} f&&/^  [a-z]/{f=0} f&&/^    user:/{print $2}' "$REPO/docker-compose.ha.yml")
[ -n "$HAP_USER" ] || fail "docker-compose.ha.yml haproxy service has no user: (image default 'haproxy' cannot read the 0600 key)"
docker create --name "$TAG-hap" --network "$NET" --network-alias haproxy --user "$HAP_USER" \
  --memory 256m --cpus 0.5 -e HAPROXY_STATS_PASSWORD="$STATS_PW" haproxy:2.8-alpine >/dev/null
docker cp "$REPO/haproxy/haproxy.cfg" "$TAG-hap:/usr/local/etc/haproxy/haproxy.cfg"
docker cp -a "$WORK/repo/certs/." "$TAG-hap:/etc/ssl/certs/"
docker start "$TAG-hap" >/dev/null
for _ in $(seq 1 30); do
  code=$(hc -k -o /dev/null -w '%{http_code}' https://haproxy/health 2>/dev/null || true)
  [ "$code" = 200 ] && break; sleep 1
done
[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$TAG-hap")" = "true 0" ] || fail "haproxy is not running"
[ "${code:-}" = 200 ] || fail "haproxy did not serve https://haproxy/health (last: ${code:-none})"
hc -k https://haproxy/ | grep -qi "<html" || fail "haproxy did not serve the dashboard UI"
[ "$(hc -o /dev/null -w '%{http_code}' http://haproxy:8404/stats)" = 401 ] || fail "stats page must need auth"
[ "$(hc -u "admin:$STATS_PW" -o /dev/null -w '%{http_code}' http://haproxy:8404/stats)" = 200 ] || fail "stats auth"
log "haproxy up with generated cert (TLS OK, stats protected)"

# --- 3. auth + writes ------------------------------------------------------
hc -k -f -H 'content-type: application/json' https://haproxy/api/v1/auth/init-admin \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"name\":\"E2E\",\"password\":\"$ADMIN_PW\",\"role\":\"admin\"}" >/dev/null \
  || fail "init-admin failed"
login() { hc -f -H 'content-type: application/json' "$1/api/v1/auth/login" -k \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PW\"}" | json "d['access_token']"; }
TOKEN=$(login https://haproxy) || fail "login via haproxy failed"
gql_site() { # url name
  hc -k -f -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$1/api/v2/graphql" \
    -d "{\"query\":\"mutation { createSite(input: {name: \\\"$2\\\", location: \\\"e2e\\\"}) { id name } }\"}"
}
sites_on() { hc -f -H "authorization: Bearer $TOKEN" "http://$1:8443/api/v1/sites" | json "' '.join(sorted(s['id']+':'+s['name'] for s in d))"; }

out=$(gql_site https://haproxy e2e-hq); echo "$out" | grep -q '"e2e-hq"' || fail "createSite via haproxy: $out"
FOLLOWER=dashboard1; [ "$LEADER" = dashboard1 ] && FOLLOWER=dashboard2
out=$(gql_site "http://$FOLLOWER:8443" e2e-branch); echo "$out" | grep -q '"e2e-branch"' || fail "createSite on follower $FOLLOWER: $out"
log "two sites created (haproxy + follower $FOLLOWER)"

for i in 1 2 3; do
  login "http://dashboard$i:8443" >/dev/null || fail "admin cannot log in on dashboard$i (user not replicated?)"
done
S1=$(sites_on dashboard1); S2=$(sites_on dashboard2); S3=$(sites_on dashboard3)
echo "$S1" | grep -q e2e-hq && echo "$S1" | grep -q e2e-branch || fail "dashboard1 sites: $S1"
[ "$S1" = "$S2" ] && [ "$S2" = "$S3" ] || fail "nodes disagree: d1=[$S1] d2=[$S2] d3=[$S3]"
log "all three nodes hold identical site lists: $S1"

CL=$(hc -k https://haproxy/ha/cluster)
[ "$(echo "$CL" | json "d['leader_id']")" = "$LEADER" ] || fail "/ha/cluster leader mismatch: $CL"
[ "$(echo "$CL" | json "sum(1 for m in d['members'] if m['reachable'])")" = 3 ] || fail "/ha/cluster members: $CL"

# --- 4. failover -----------------------------------------------------------
LIDX=${LEADER#dashboard}
log "killing leader $LEADER"
docker kill "$TAG-d$LIDX" >/dev/null
# `if`, not `[ ] && echo`: with LIDX=3 the last iteration would return 1 and
# set -e/pipefail would abort the run whenever dashboard3 wins the election.
SURV=$(for i in 1 2 3; do if [ "$i" != "$LIDX" ]; then echo dashboard$i; fi; done | tr '\n' ' ')
NEW=$(wait_leader --not "$LEADER" $SURV)
[ "$NEW" != "$LEADER" ] || fail "leader did not change"
log "new leader: $NEW"
SN=$(sites_on "$NEW")
echo "$SN" | grep -q e2e-hq && echo "$SN" | grep -q e2e-branch || fail "new leader lost data: [$SN]"

ok=""
for _ in $(seq 1 30); do
  out=$(gql_site https://haproxy e2e-after-failover 2>/dev/null || true)
  if echo "$out" | grep -q '"e2e-after-failover"'; then ok=1; break; fi
  sleep 2
done
[ -n "$ok" ] || fail "write via haproxy after failover never succeeded: $out"
set -- $SURV
A=$(sites_on "$1"); B=$(sites_on "$2")
[ "$A" = "$B" ] || fail "survivors disagree after failover: [$A] vs [$B]"
echo "$A" | grep -q e2e-after-failover || fail "post-failover write missing: [$A]"
log "survivors identical after failover: $A"

# --- 5. killed node rejoins and catches up --------------------------------
docker start "$TAG-d$LIDX" >/dev/null
for _ in $(seq 1 60); do
  R=$(sites_on "$LEADER" 2>/dev/null || true)
  [ "$R" = "$A" ] && break; sleep 1
done
[ "$R" = "$A" ] || fail "restarted $LEADER did not catch up: [$R] vs [$A]"
log "restarted $LEADER caught up"
log "PASS"
