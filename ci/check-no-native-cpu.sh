#!/bin/bash
# Lint: no release/ISO/package/container build may default to a host-tuned CPU target.
# A `-C target-cpu=native` build on an AVX-512 CI host shipped binaries that crashed with
# "invalid opcode" on a real Intel box. `native` is allowed only as an explicit opt-in
# (RUSTFLAGS env, PATRONUS_NATIVE=1 build-arch.sh, the ebuild's arch-native USE flag, docs).
set -u
cd "$(dirname "$0")/.."
fail=0
# 1. the cargo config every build inherits must pin the portable baselines
grep -qE 'target-cpu=x86-64-v2' .cargo/config.toml || { echo "::error::.cargo/config.toml: x86_64 must use target-cpu=x86-64-v2"; fail=1; }
grep -qE 'target-cpu=generic"' .cargo/config.toml || { echo "::error::.cargo/config.toml: aarch64 must use target-cpu=generic"; fail=1; }
grep -qE 'target-cpu=generic-rv64' .cargo/config.toml || { echo "::error::.cargo/config.toml: riscv64 must use target-cpu=generic-rv64"; fail=1; }
# 2. no build input outside the opt-in places names target-cpu=native (comments and docs excluded)
hits=$(git ls-files -z -- '.cargo' 'Dockerfile*' '*/Dockerfile*' '*.sh' '.forgejo/workflows' 'gentoo' 'ci' \
  | xargs -0 grep -nE 'target-cpu=native' 2>/dev/null \
  | grep -vE '^(ci/check-no-native-cpu\.sh|gentoo/net-firewall/patronus/patronus-[0-9.]*\.ebuild|gentoo/net-firewall/patronus/patronus-9999\.ebuild):' \
  | grep -vE '^[^:]+:[0-9]+:\s*#' \
  | grep -vE '^[^:]+:[0-9]+:[^#]*#.*target-cpu=native' || true)
# the ebuild may use it ONLY behind `use arch-native` / PATRONUS_TARGET_CPU (checked by eye in review; grep for a bare default)
if grep -nE 'target-cpu=native' gentoo/net-firewall/patronus/*.ebuild | grep -vE 'arch-native|PATRONUS_TARGET_CPU|^[^:]+:[0-9]+:\s*#' | grep -q .; then
  hits="$hits
gentoo ebuild: bare target-cpu=native outside the arch-native opt-in"
fi
if [ -n "$(echo "$hits" | tr -d '[:space:]')" ]; then
  echo "::error::target-cpu=native in a build input (portable baseline required; use RUSTFLAGS/PATRONUS_NATIVE=1 locally):"
  echo "$hits"
  fail=1
fi
[ $fail = 0 ] && echo "ok: no host-tuned target-cpu in build inputs (x86-64-v2 / generic / generic-rv64 pinned)"
exit $fail
