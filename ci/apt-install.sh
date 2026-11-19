#!/usr/bin/env bash
# Install apt packages on a CI runner, robust against transient archive/mirror trouble
# (connection timeouts, Launchpad 503s, "mirror sync in progress" size mismatches).
# `apt-get update` and `install` are retried TOGETHER as one unit (an install after a
# half-failed update fails with "Unable to locate package"), each fetch fails fast
# (Acquire timeouts) instead of hanging for minutes, and the whole thing is bounded.
#   usage: ci/apt-install.sh pkg [pkg...]
#   env:   APT_ATTEMPTS (default 6)  APT_BACKOFF seconds per attempt step (default 20)
#          APT_FETCH_TIMEOUT seconds (default 30)  APT_FETCH_RETRIES (default 3)
set -u
[ "$#" -gt 0 ] || { echo "usage: $0 pkg..." >&2; exit 2; }
attempts="${APT_ATTEMPTS:-6}"
backoff="${APT_BACKOFF:-20}"
opts=(-o "Acquire::Retries=${APT_FETCH_RETRIES:-3}"
      -o "Acquire::http::Timeout=${APT_FETCH_TIMEOUT:-30}"
      -o "Acquire::https::Timeout=${APT_FETCH_TIMEOUT:-30}"
      -o "DPkg::Lock::Timeout=300")
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
export DEBIAN_FRONTEND=noninteractive
i=1
while :; do
  if $SUDO apt-get update "${opts[@]}" && $SUDO apt-get install -y "${opts[@]}" "$@"; then
    exit 0
  fi
  if [ "$i" -ge "$attempts" ]; then
    echo "::error::apt-get update/install failed after $attempts attempts: $*" >&2
    exit 1
  fi
  wait=$((backoff * i))
  echo "apt attempt $i/$attempts failed; retrying in ${wait}s" >&2
  sleep "$wait"
  i=$((i + 1))
done
