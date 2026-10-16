#!/usr/bin/env bash
# Run patronus-operator's Kubernetes integration tests (the #[ignore]d
# site/policy lifecycle + health-endpoint suites) against a REAL Kubernetes
# API: a throwaway k3s server container (memory/CPU capped), with the CRDs
# generated from the operator's own Rust types (crdgen) and the real
# operator binary running against it. Everything is removed on exit.
#
# Works from a CI job container (Docker-outside-of-Docker: the job container
# joins the k3s network) or from a plain host shell.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=pk3s-${GITHUB_RUN_ID:-local}-$$
NET=$TAG-net
WORK=$(mktemp -d)
OP_PID=""
SELF=""
if [ -f /.dockerenv ]; then SELF=$(hostname); fi

cleanup() {
  rc=$?
  [ -n "$OP_PID" ] && kill "$OP_PID" 2>/dev/null || true
  if [ $rc -ne 0 ]; then
    echo "----- operator log -----"; tail -50 "$WORK/operator.log" 2>/dev/null || true
    echo "----- k3s log -----"; docker logs --tail 40 "$TAG" 2>&1 || true
  fi
  [ -n "$SELF" ] && docker network disconnect "$NET" "$SELF" >/dev/null 2>&1 || true
  docker rm -f -v "$TAG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit $rc
}
trap cleanup EXIT

cargo build -p patronus-operator --bins --tests

docker network create "$NET" >/dev/null
docker run -d --name "$TAG" --hostname "$TAG" --network "$NET" --privileged \
  --memory 2g --memory-swap 2g --cpus 2 \
  rancher/k3s:latest server --disable traefik --disable metrics-server \
  --disable servicelb --tls-san "$TAG" >/dev/null

APISERVER=127.0.0.1
if [ -n "$SELF" ]; then
  docker network connect "$NET" "$SELF"
  APISERVER=$TAG
else
  APISERVER=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TAG")
fi

for _ in $(seq 1 90); do
  docker exec "$TAG" kubectl get --raw /readyz >/dev/null 2>&1 && break; sleep 2
done
docker exec "$TAG" kubectl get --raw /readyz
docker exec "$TAG" cat /etc/rancher/k3s/k3s.yaml | sed "s#https://127.0.0.1:6443#https://$APISERVER:6443#" > "$WORK/kubeconfig"
export KUBECONFIG=$WORK/kubeconfig

# CRDs straight from the Rust types, so the cluster schema is what the code uses.
cargo run -q -p patronus-operator --bin crdgen > "$WORK/crds.yaml"
docker exec -i "$TAG" kubectl apply -f - < "$WORK/crds.yaml"
docker exec "$TAG" kubectl wait --for=condition=Established --timeout=60s crd --all

# Real operator process (health on :8081 as the health tests expect).
HEALTH_PORT=8081 METRICS_PORT=18080 RUST_LOG=info \
  target/debug/patronus-operator > "$WORK/operator.log" 2>&1 &
OP_PID=$!
for _ in $(seq 1 60); do
  curl -sf http://localhost:8081/readyz >/dev/null 2>&1 && break
  kill -0 "$OP_PID" || { echo "operator exited"; exit 1; }
  sleep 1
done

cargo test -p patronus-operator --no-fail-fast -- --ignored --test-threads=1
