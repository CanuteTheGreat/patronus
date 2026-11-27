#!/usr/bin/env bash
# Runs INSIDE the Playwright image (see ci/ui-qa/run.sh): /q/bin has the binaries, /q/ci the harness, /q/baseline the
# pinned screenshot baseline (may be empty). Results go to /q/out. Exit 1 on any new crawl fail (incl. contrast),
# a keyboard e2e failure or a visual-diff fail.
set -u
mkdir -p /q/out
exec > >(tee /q/out/ui-qa.txt) 2>&1
export DEBIAN_FRONTEND=noninteractive
echo "== setup $(date -u +%T)"
apt-get update -qq >/dev/null && apt-get install -y -qq libnftnl11 libmnl0 libelf1 libpam0g nftables iproute2 >/dev/null 2>&1 \
  || echo "apt-get failed (binaries may still run)"
pip install -q --root-user-action=ignore --break-system-packages "playwright==${PWV}" pillow >/dev/null 2>&1 || { echo "pip install failed"; exit 1; }
cd /q
mkdir -p /q/emb && ln -sf /q/bin/patronus-cli-emb /q/emb/patronus-web   # multicall: the router binary answers as patronus-web
PW="UiQa-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')-1"
fails=()

run_variant() { # NAME BIN PORT KBD(yes|no) [env...]
  local name=$1 bin=$2 port=$3 kbd=$4; shift 4
  local t=/q/var-$name; rm -rf "$t"; mkdir -p "$t/tls"
  # PATRONUS_STATS_TICK_SECS=3600: the Monitoring page's History card turns from "Collecting" into six charts once the
  # first 5-minute point exists (5 sampler ticks); with the default 60 s tick that lands mid-crawl, so whichever
  # screenshots came after it were ~20 % taller and the visual diff failed at random. One tick per hour keeps every
  # run's pages in the same state.
  env PATRONUS_STATS_TICK_SECS=3600 PATRONUS_DB="$t/config.db" PATRONUS_ADMIN_PASSWORD="$PW" PATRONUS_ADMIN_PASSWORD_FILE="$t/pw" PATRONUS_TLS_DIR="$t/tls" \
      PATRONUS_HTTPS_PORT="$port" PATRONUS_HTTP_REDIRECT_PORT=0 PATRONUS_WEB_EXTRA_HTTPS_PORTS=none RUST_LOG=info "$@" \
      "$bin" > "/q/out/web-$name.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 90); do curl -sk -o /dev/null "https://127.0.0.1:$port/login" && break; sleep 1; done
  if ! curl -sk -o /dev/null "https://127.0.0.1:$port/login"; then
    echo "FAIL $name: patronus-web did not come up"; tail -30 "/q/out/web-$name.log"; fails+=("$name:start"); kill $pid 2>/dev/null; return
  fi
  if [ "${UI_QA_ONLY:-}" != kbd ]; then
  echo "== $name crawl $(date -u +%T)"
  ADMIN_PASSWORD="$PW" BROWSER=firefox timeout 3000 python3 ci/ux-qa/ux_crawl.py --config ci/ui-qa/live-crawl.json --contrast \
      --base "https://127.0.0.1:$port" --shots "/q/out/shots-$name" --report "/q/out/report-$name.json" > "/q/out/crawl-$name.txt" 2>&1
  local rc=$?
  tail -40 "/q/out/crawl-$name.txt"
  [ $rc -eq 0 ] || fails+=("$name:crawl")
  fi
  if [ "${UI_QA_ONLY:-}" != kbd ]; then
    echo "== $name dialogs $(date -u +%T)"
    BASE_URL="https://127.0.0.1:$port" E2E_PASSWORD="$PW" BROWSER=firefox timeout 900 python3 ci/ui-qa/dialog_shots.py \
        --shots "/q/out/shots-$name" > "/q/out/dialogs-$name.txt" 2>&1 || fails+=("$name:dialogs")
    tail -5 "/q/out/dialogs-$name.txt"
  fi
  if [ "$kbd" = yes ]; then
    echo "== $name keyboard firewall rule $(date -u +%T)"
    BASE_URL="https://127.0.0.1:$port" E2E_USER=admin E2E_PASSWORD="$PW" timeout 600 python3 ci/ui-qa/kbd_firewall_rule.py \
        > "/q/out/kbd-$name.txt" 2>&1 || fails+=("$name:keyboard")
    cat "/q/out/kbd-$name.txt"
  fi
  kill $pid; wait $pid 2>/dev/null
}

V=" ${VARIANTS:-std router-ap router-gw} "
case "$V" in *" std "*) run_variant std /q/bin/patronus-web-std 9443 yes;; esac
case "$V" in *" router-ap "*) run_variant router-ap /q/emb/patronus-web 9444 no PATRONUS_DEVICE_ROLE=ap PATRONUS_AUTH_BACKEND=shadow \
    PATRONUS_ARGON2_MEM_KIB=8192 PATRONUS_SYSLOG=/var/log/dpkg.log;; esac
case "$V" in *" router-gw "*) run_variant router-gw /q/emb/patronus-web 9445 yes PATRONUS_AUTH_BACKEND=shadow \
    PATRONUS_ARGON2_MEM_KIB=8192 PATRONUS_SYSLOG=/var/log/dpkg.log;; esac

[ "${UI_QA_ONLY:-}" = kbd ] && { [ ${#fails[@]} -eq 0 ] && { echo "ui-qa: keyboard only, passed"; exit 0; }; echo "ui-qa: FAILED: ${fails[*]}"; exit 1; }
echo "== visual diff $(date -u +%T)"
python3 ci/ui-qa/visual_diff.py --new /q/out --baseline /q/baseline --report /q/out/diff.json --pack /q/out/ui-shots.tar.gz \
  || fails+=("visual-diff")
if [ ${#fails[@]} -gt 0 ]; then echo "ui-qa: FAILED: ${fails[*]}"; exit 1; fi
echo "ui-qa: all passed"
