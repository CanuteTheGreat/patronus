#!/usr/bin/env bash
# Browser sign-in with an older firmware's leftovers for the same address (ci/stale-origin-login-e2e.py), against
# the image as built: patronus-web serves HTTPS with HTTP/2, so real Firefox and Chromium send one `cookie` field per
# cookie, which is what broke sign-in when another cookie was stored for the address.
#
# Usage: ci/stale-origin-login-e2e.sh <image>
# Runs the web container (capped) and the official Playwright image in its network namespace; removes both on exit.
set -euo pipefail

IMAGE=${1:?usage: ci/stale-origin-login-e2e.sh <image>}
PW_IMAGE=${PW_IMAGE:-mcr.microsoft.com/playwright/python:v1.65.2-noble}
TAG=pso-${GITHUB_RUN_ID:-local}-$$
C=$TAG-web
B=$TAG-browser
HERE=$(cd "$(dirname "$0")" && pwd)

fail() { echo "::error::[stale-origin-login] $*"; exit 1; }
cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then echo "----- logs: $C -----"; docker logs --tail 60 "$C" 2>&1 || true; fi
  docker rm -f -v "$C" "$B" >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT

PW="E2e-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')-Pw1"
docker run -d --name "$C" -e PATRONUS_ADMIN_PASSWORD="$PW" --cap-add NET_ADMIN --cap-add NET_RAW \
  --memory 1g --memory-swap 1g --cpus 1 -e RUST_LOG=info "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$C" curl -ksf -o /dev/null https://localhost:8443/login && break
  sleep 1
done
docker exec "$C" curl -ksf -o /dev/null https://localhost:8443/login || fail "patronus-web did not come up"

docker pull -q "$PW_IMAGE" >/dev/null
docker create --name "$B" --network "container:$C" --memory 3g --memory-swap 3g --cpus 2 --ipc host \
  -e BASE_URL=https://localhost:8443 -e E2E_USER=admin -e E2E_PASSWORD="$PW" -e E2E_BACKOFF_USER=e2e-nobody \
  -w /e2e "$PW_IMAGE" python3 /e2e/stale-origin-login-e2e.py firefox,chromium >/dev/null
docker cp "$HERE/stale-origin-login-e2e.py" "$B:/e2e/stale-origin-login-e2e.py"
docker start -a "$B"

# the refused sign-ins are explained in the web log on the box (not only in the database)
docker logs "$C" 2>&1 | grep 'patronus::audit' | grep 'login failed user="e2e-nobody"' >/dev/null \
  || fail "failed sign-ins are not in the web log"
docker logs "$C" 2>&1 | grep 'patronus::audit' | grep 'login refused user="e2e-nobody"' >/dev/null \
  || fail "the lockout refusal is not in the web log"
echo "[stale-origin-login] ok: browsers sign in with old-firmware cookies present; refusals say so and are logged"
