#!/usr/bin/env bash
# Accessibility gate against a running patronus-web (ci/a11y/axe_gate.py, vendored axe-core, real browsers).
#
# Usage: ci/a11y/run-e2e.sh <image>                 (CI: the web image as built; same harness as stale-origin-login-e2e.sh)
#        WEB_BIN=/path/patronus-web ci/a11y/run-e2e.sh   (no image: run that binary in a plain container; local QA)
# Extra arguments after the image/- are passed to axe_gate.py (--browsers, --pages, --report).
set -euo pipefail

IMAGE=${1:-}
[ $# -gt 0 ] && shift
HERE=$(cd "$(dirname "$0")" && pwd)
PW_IMAGE=${PW_IMAGE:-mcr.microsoft.com/playwright/python:v1.65.2-noble}
WEB_RUN_IMAGE=${WEB_RUN_IMAGE:-debian:bookworm}
TAG=a11y-${GITHUB_RUN_ID:-local}-$$
C=$TAG-web
B=$TAG-browser

fail() { echo "::error::[a11y] $*"; exit 1; }
cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then echo "----- logs: $C -----"; docker logs --tail 60 "$C" 2>&1 || true; fi
  docker rm -f -v "$C" "$B" >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT

PW="E2e-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')-Pw1"
if [ -n "${WEB_BIN:-}" ]; then
  docker create --name "$C" -e PATRONUS_ADMIN_PASSWORD="$PW" -e PATRONUS_AUTH_ETC=/tmp/auth --cap-add NET_ADMIN --cap-add NET_RAW \
    --memory 1g --memory-swap 1g --cpus 1 -e RUST_LOG=info -e PATRONUS_HTTPS_PORT=8443 -e PATRONUS_HTTP_REDIRECT_PORT=0 --entrypoint /patronus-web "$WEB_RUN_IMAGE" >/dev/null
  docker cp "$WEB_BIN" "$C:/patronus-web"
  docker start "$C" >/dev/null
  CURL=(docker run --rm --network "container:$C" "$PW_IMAGE" curl)
else
  [ -n "$IMAGE" ] || fail "usage: ci/a11y/run-e2e.sh <image>"
  docker run -d --name "$C" -e PATRONUS_ADMIN_PASSWORD="$PW" --cap-add NET_ADMIN --cap-add NET_RAW \
    --memory 1g --memory-swap 1g --cpus 1 -e RUST_LOG=info "$IMAGE" >/dev/null
  CURL=(docker exec "$C" curl)
fi
for _ in $(seq 1 60); do
  "${CURL[@]}" -ksf -o /dev/null https://localhost:8443/login && break
  sleep 1
done
"${CURL[@]}" -ksf -o /dev/null https://localhost:8443/login || fail "patronus-web did not come up"

PWV=${PW_IMAGE##*:v}; PWV=${PWV%%-*}
docker pull -q "$PW_IMAGE" >/dev/null
docker create --name "$B" --network "container:$C" --memory 3g --memory-swap 3g --cpus 2 --ipc host \
  -e BASE_URL=https://localhost:8443 -e E2E_USER=admin -e E2E_PASSWORD="$PW" \
  -w /e2e --entrypoint sh "$PW_IMAGE" -c \
  "pip install -q --root-user-action=ignore --break-system-packages playwright==$PWV && python3 /e2e/axe_gate.py --report /e2e/report.json $*" >/dev/null
docker cp "$HERE/." "$B:/e2e/"
rc=0
docker start -a "$B" || rc=$?
docker cp "$B:/e2e/report.json" "${A11Y_REPORT:-/tmp/a11y-report.json}" >/dev/null 2>&1 || true
[ $rc -eq 0 ] || fail "accessibility gate found violations (see above)"
echo "[a11y] ok: no serious or critical axe violations on the gated pages"
