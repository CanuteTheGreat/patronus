#!/usr/bin/env bash
# End-to-end HA failover + replication test for docker-compose.ha.yml.
#
# Brings up the real 3-node dashboard cluster + haproxy (images built from
# this checkout), then checks what an operator relies on:
#   * exactly one leader is elected and haproxy routes to it
#   * writes made through haproxy AND directly on a follower (forwarded to the
#     leader) end up on every node (same replication generation everywhere)
#   * killing the leader elects a new one that still has every site and the
#     admin user (data survived the failover), and keeps accepting writes
#   * the old leader rejoins as a follower and catches up; a second failover
#     onto it again loses nothing
#   * node-to-node RPCs reject callers without the cluster credential, and
#     the REST API rejects unauthenticated requests
#
# Everything talks to the stack from a throwaway curl container on the
# compose network, and the haproxy config/cert are baked into a test image
# instead of bind-mounted, so this works from a CI job container that shares
# the host's Docker daemon (no host ports, no host paths).
#
# Usage: ci/ha-failover-test.sh            (from the repo root)
# Env:   HA_TEST_PROJECT (compose project name, default patronus-ha-test-$$)
#        HA_TEST_KEEP=1 to leave the stack running for inspection.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$(pwd)"
PROJECT="${HA_TEST_PROJECT:-patronus-ha-test-$$}"
NET="${PROJECT}_patronus-ha"
CURL_IMAGE="curlimages/curl:8.10.1"
PASSWORD='QaCheck!2026-HA-pass'
EMAIL="qa-ha@errant.solutions"
WORK="$(mktemp -d)"

export PATRONUS_JWT_SECRET="$(openssl rand -hex 32)"

log() { printf '[ha-test %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() {
    log "FAIL: $*"
    log "--- container status ---"
    docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" ps -a || true
    for c in patronus-dashboard-1 patronus-dashboard-2 patronus-dashboard-3 patronus-haproxy; do
        log "--- last log lines: $c ---"
        docker logs --tail 40 "${PROJECT}-$c" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' || true
    done
    exit 1
}

# --- test-only compose override: no host ports/bind mounts, resource caps ---
mkdir -p "$WORK/haproxy-ctx"
openssl req -x509 -nodes -days 2 -newkey rsa:2048 \
    -keyout "$WORK/haproxy-ctx/key.pem" -out "$WORK/haproxy-ctx/crt.pem" \
    -subj "/CN=haproxy" -addext "subjectAltName=DNS:haproxy,DNS:localhost" 2>/dev/null
cat "$WORK/haproxy-ctx/crt.pem" "$WORK/haproxy-ctx/key.pem" > "$WORK/haproxy-ctx/patronus.pem"
cp "$REPO/haproxy/haproxy.cfg" "$WORK/haproxy-ctx/haproxy.cfg"
cat > "$WORK/haproxy-ctx/Dockerfile" <<'EOF'
FROM haproxy:2.8-alpine
COPY --chown=haproxy:haproxy haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY --chown=haproxy:haproxy patronus.pem /etc/ssl/certs/patronus.pem
EOF

cat > "$WORK/override.yml" <<EOF
services:
  dashboard1: &dash
    container_name: ${PROJECT}-patronus-dashboard-1
    ports: !reset []
    mem_limit: 768m
    cpus: 1.0
  dashboard2:
    <<: *dash
    container_name: ${PROJECT}-patronus-dashboard-2
  dashboard3:
    <<: *dash
    container_name: ${PROJECT}-patronus-dashboard-3
  haproxy:
    container_name: ${PROJECT}-patronus-haproxy
    build:
      context: $WORK/haproxy-ctx
    image: ${PROJECT}-haproxy
    volumes: !reset []
    ports: !reset []
    mem_limit: 256m
    cpus: 0.5
networks:
  patronus-ha:
    ipam: !reset {}
EOF
COMPOSE_FILES=(-f "$REPO/docker-compose.ha.yml" -f "$WORK/override.yml")

cleanup() {
    if [ "${HA_TEST_KEEP:-0}" = "1" ]; then
        log "HA_TEST_KEEP=1: leaving stack ${PROJECT} running"
    else
        docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
        docker image rm "${PROJECT}-haproxy" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

c() { docker run --rm --network "$NET" "$CURL_IMAGE" -sk --max-time 10 "$@"; }
node_url() { echo "http://dashboard$1:8443"; }
LB="https://haproxy"

json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

status_of() { c "$(node_url "$1")/ha/status" 2>/dev/null || true; }

# Prints the node number (1-3) of the single leader among the given nodes,
# or nothing if there isn't exactly one.
leader_among() {
    local found=() n s
    for n in "$@"; do
        s="$(status_of "$n")"
        [ -n "$s" ] || continue
        if [ "$(echo "$s" | json 'd["role"]' 2>/dev/null)" = "Leader" ]; then found+=("$n"); fi
    done
    [ "${#found[@]}" -eq 1 ] && echo "${found[0]}"
    return 0
}

wait_leader() {
    local i l
    for i in $(seq 1 60); do
        l="$(leader_among "$@")"
        if [ -n "$l" ]; then echo "$l"; return 0; fi
        sleep 1
    done
    return 1
}

gql() { # gql <base-url> <token> <graphql-query>
    local body
    body="$(python3 -c 'import json,sys; print(json.dumps({"query": sys.argv[1]}))' "$3")"
    c -X POST "$1/api/v2/graphql" -H 'Content-Type: application/json' -H "Authorization: Bearer $2" -d "$body"
}

lb_retry() { # retry a haproxy request while a failover settles
    local i out
    for i in $(seq 1 30); do
        out="$("$@" 2>/dev/null || true)"
        if [ -n "$out" ] && ! echo "$out" | grep -q '503 Service Unavailable\|"error"'; then echo "$out"; return 0; fi
        sleep 1
    done
    echo "$out"
    return 1
}

site_names() { echo "$1" | json 'sorted(s["name"] for s in d["data"]["sites"])'; }

generations_equal() { # all listed nodes report the same generation > 0
    local gens=() n
    for n in "$@"; do gens+=("$(status_of "$n" | json 'd["generation"]' 2>/dev/null || echo x)"); done
    [ "$(printf '%s\n' "${gens[@]}" | sort -u | wc -l)" -eq 1 ] && [ "${gens[0]}" != "x" ] && [ "${gens[0]}" != "0" ]
}

wait_generations_equal() {
    local i
    for i in $(seq 1 30); do generations_equal "$@" && return 0; sleep 1; done
    return 1
}

# --- bring the stack up -------------------------------------------------
log "building + starting HA stack (project $PROJECT)"
docker pull -q "$CURL_IMAGE" >/dev/null
docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" up -d --build --quiet-pull dashboard1 dashboard2 dashboard3 haproxy >/dev/null

L1="$(wait_leader 1 2 3)" || fail "no single leader elected within 60s"
log "leader elected: dashboard$L1"

for i in $(seq 1 30); do
    [ "$(c -o /dev/null -w '%{http_code}' "$LB/ha/leader")" = "200" ] && break
    sleep 1
done
[ "$(c -o /dev/null -w '%{http_code}' "$LB/ha/leader")" = "200" ] || fail "haproxy is not routing to the leader"

# --- security: cluster RPCs and REST need credentials --------------------
code="$(c -o /dev/null -w '%{http_code}' -X POST "$(node_url "$L1")/ha/heartbeat" \
    -H 'Content-Type: application/json' -d '{"term":999,"leader_id":"attacker"}')"
[ "$code" = "401" ] || fail "unauthenticated /ha/heartbeat returned $code, expected 401"
code="$(c -o /dev/null -w '%{http_code}' "$LB/api/v1/sites")"
[ "$code" = "401" ] || fail "unauthenticated GET /api/v1/sites returned $code, expected 401"
log "unauthenticated cluster RPC and REST calls are rejected (401)"

# --- first admin + writes through haproxy and through a follower ---------
c -X POST "$LB/api/v1/auth/init-admin" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"name\":\"QA\",\"password\":\"$PASSWORD\",\"role\":\"admin\"}" >/dev/null
TOKEN="$(c -X POST "$LB/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | json 'd["access_token"]')" || fail "login failed"

gql "$LB" "$TOKEN" 'mutation { createSite(input: {name: "site-a-via-haproxy"}) { id } }' | grep -q '"id"' \
    || fail "createSite through haproxy failed"
FOLLOWER=""
for n in 1 2 3; do [ "$n" != "$L1" ] && { FOLLOWER="$n"; break; }; done
out="$(gql "$(node_url "$FOLLOWER")" "$TOKEN" 'mutation { createSite(input: {name: "site-b-via-follower"}) { id } }')"
echo "$out" | grep -q '"id"' || fail "write sent to follower dashboard$FOLLOWER was not forwarded: $out"
log "wrote one site via haproxy and one directly on follower dashboard$FOLLOWER"

wait_generations_equal 1 2 3 || fail "nodes did not converge on one replication generation"
log "all 3 nodes hold replication generation $(status_of 1 | json 'd["generation"]')"

# --- failover 1 ------------------------------------------------------------
log "killing leader dashboard$L1"
docker kill "${PROJECT}-patronus-dashboard-$L1" >/dev/null
REST=(); for n in 1 2 3; do [ "$n" != "$L1" ] && REST+=("$n"); done
L2="$(wait_leader "${REST[@]}")" || fail "no new leader after killing dashboard$L1"
log "new leader: dashboard$L2"

TOKEN2="$(lb_retry c -X POST "$LB/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | json 'd["access_token"]')" \
    || fail "admin user missing on new leader (login failed after failover)"
sites="$(site_names "$(lb_retry gql "$LB" "$TOKEN2" '{ sites { name } }')")"
[ "$sites" = "['site-a-via-haproxy', 'site-b-via-follower']" ] || fail "data lost on failover; new leader has $sites"
log "new leader has both sites and the admin user"

gql "$LB" "$TOKEN2" 'mutation { createSite(input: {name: "site-c-after-failover"}) { id } }' | grep -q '"id"' \
    || fail "write after failover failed"

# --- rejoin + failover 2 ---------------------------------------------------
log "restarting old leader dashboard$L1"
docker start "${PROJECT}-patronus-dashboard-$L1" >/dev/null
for i in $(seq 1 60); do
    role="$(status_of "$L1" | json 'd["role"]' 2>/dev/null || true)"
    [ "$role" = "Follower" ] && break
    sleep 1
done
[ "$role" = "Follower" ] || fail "old leader did not rejoin as follower (role=$role)"
[ "$(leader_among 1 2 3)" = "$L2" ] || fail "expected dashboard$L2 to be the only leader after the rejoin"
wait_generations_equal 1 2 3 || fail "rejoined node did not catch up"
log "dashboard$L1 rejoined as follower and caught up"

log "killing second leader dashboard$L2"
docker kill "${PROJECT}-patronus-dashboard-$L2" >/dev/null
REST=(); for n in 1 2 3; do [ "$n" != "$L2" ] && REST+=("$n"); done
L3="$(wait_leader "${REST[@]}")" || fail "no leader after second failover"
log "third leader: dashboard$L3"
sites="$(site_names "$(lb_retry gql "$LB" "$TOKEN2" '{ sites { name } }')")"
[ "$sites" = "['site-a-via-haproxy', 'site-b-via-follower', 'site-c-after-failover']" ] \
    || fail "data lost on second failover; leader has $sites"

ok=0
for i in 1 2 3 4 5 6; do
    [ "$(c -o /dev/null -w '%{http_code}' -X POST "$LB/api/v2/graphql" -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $TOKEN2" -d '{"query":"{ siteCount }"}')" = "200" ] && ok=$((ok + 1))
done
[ "$ok" -eq 6 ] || fail "only $ok/6 requests through haproxy succeeded after second failover"

log "PASS: two failovers, no data loss, single leader, haproxy follows the leader"
