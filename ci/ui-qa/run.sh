#!/usr/bin/env bash
# UI QA against LIVE patronus-web builds (standard tier + router tier in AP and gateway role), real Firefox:
#   * ci/ux-qa/ux_crawl.py over every page reachable from the nav, desktop 1280 + phone 390, light + dark, with
#     --contrast (WCAG AA) and full-page screenshots;
#   * ci/ui-qa/kbd_firewall_rule.py: keyboard-only add / edit / delete of a firewall rule (standard + router gateway);
#   * ci/ui-qa/visual_diff.py: every screenshot against the pinned baseline set (ci/ui-qa/shots.pin).
#
# Usage: ci/ui-qa/run.sh <std patronus-web> <router multicall patronus-cli> [out dir]
# Runs one capped Playwright sibling container (docker.sock, as ci/a11y/run-e2e.sh); binaries and the harness are
# copied in, results copied out to OUT (default ./ui-qa-out): report-*.json, crawl-*.txt, kbd-*.txt, diff.json,
# shots-<variant>/<scheme>-<width>/<page>.png and ui-shots.tar.gz (the reduced set a baseline is made of).
set -euo pipefail
STD=${1:?std patronus-web binary}
EMB=${2:?router multicall patronus-cli binary}
OUT=${3:-ui-qa-out}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# The browser image must be the Ubuntu release the binaries were built on (or newer): the CI job builds in
# catthehacker/ubuntu:act-latest, which moves to new releases (26.04 links OpenSSL 3.5, glibc 2.43), so a fixed
# -noble image could not load them. Builds on Debian (rust:1-bookworm, older libs) run on the noble image.
pw_flavour() {
  local id="" code=""
  [ -r /etc/os-release ] && { id=$(. /etc/os-release; echo "${ID:-}"); code=$(. /etc/os-release; echo "${VERSION_CODENAME:-}"); }
  case "$id:$code" in
    ubuntu:jammy|ubuntu:noble|ubuntu:resolute) echo "$code";;
    *) echo "${UI_QA_PW_FLAVOUR_DEFAULT:-noble}";;
  esac
}
PW_IMAGE=${PW_IMAGE:-mcr.microsoft.com/playwright/python:v1.65.2-$(pw_flavour)}
echo "ui-qa: browser image $PW_IMAGE"
C=ui-qa-${GITHUB_RUN_ID:-local}-$$
trap 'docker rm -f -v "$C" >/dev/null 2>&1 || true' EXIT
mkdir -p "$OUT"
docker pull -q "$PW_IMAGE" >/dev/null
PWV=${PW_IMAGE##*:v}; PWV=${PWV%%-*}
docker create --name "$C" --memory 6g --memory-swap 6g --cpus 3 --ipc host --cap-add NET_ADMIN --cap-add NET_RAW \
  -e PWV="$PWV" -e VARIANTS="${UI_QA_VARIANTS:-std router-ap router-gw}" -e UI_QA_BASELINE_DIR=/q/baseline -e UI_QA_ONLY="${UI_QA_ONLY:-}" \
  -w /q --entrypoint bash "$PW_IMAGE" /q/ci/ui-qa/inner.sh >/dev/null
# one tar stream into / : /q/ci/{ux-qa,ui-qa}, /q/bin/{patronus-web-std,patronus-cli-emb}, /q/baseline (optional)
S=$(mktemp -d); trap 'docker rm -f -v "$C" >/dev/null 2>&1 || true; rm -rf "$S"' EXIT
mkdir -p "$S/q/bin" "$S/q/ci" "$S/q/baseline"
cp -a "$ROOT/ci/ux-qa" "$ROOT/ci/ui-qa" "$S/q/ci/"
cp "$STD" "$S/q/bin/patronus-web-std"; cp "$EMB" "$S/q/bin/patronus-cli-emb"; chmod 755 "$S/q/bin/"*
if [ -n "${UI_QA_BASELINE:-}" ] && [ -d "$UI_QA_BASELINE" ]; then cp -a "$UI_QA_BASELINE/." "$S/q/baseline/"; fi
tar -C "$S" -cf - q | docker cp - "$C:/"
rc=0
docker start -a "$C" || rc=$?
docker cp "$C:/q/out/." "$OUT/" >/dev/null 2>&1 || true
echo "ui-qa: results in $OUT (rc=$rc)"
exit $rc
