#!/usr/bin/env bash
# Forbid "<cmd> | grep -q ..." in ci/ and the workflows.
#
# grep -q exits at the first match; <cmd> then gets SIGPIPE/EPIPE, and under
# `set -o pipefail` the pipeline fails although the pattern was found (a Rust
# CLI even panics on EPIPE). This was the cause of repeated "flaky" netlab
# failures. Use one of:
#   OUT=$(cmd); grep -q PATTERN <<<"$OUT"      # grep -q on captured output
#   cmd | grep PATTERN >/dev/null              # grep reads all input, no SIGPIPE
# (`grep -q PATTERN file` and `grep -q ... <<<"$VAR"` are fine: nothing is piped.)
set -u
cd "$(dirname "$0")/.."
re='(?<!\|)\|[ \t]*(?:e|f)?grep(?:[ \t]+(?:-[A-Za-z0-9]+|--[a-z-]+))*?[ \t]+(?:-[A-Za-z]*q[A-Za-z]*|--quiet|--silent)(?=[ \t]|$)'
hits=$(grep -rnP --include='*.sh' --include='*.yml' --include='*.yaml' --include='*.start' --include='*.bash' -e "$re" ci .forgejo/workflows 2>/dev/null \
  | grep -vE '^[^:]+:[0-9]+:[ \t]*#' | grep -v 'lint-no-pipe-grep-q.sh:' || true)
if [ -n "$hits" ]; then
  echo "::error::'| grep -q' is forbidden (SIGPIPE under pipefail): capture the output first, or use 'grep ... >/dev/null'"
  echo "$hits"
  exit 1
fi
echo "lint-no-pipe-grep-q: ok"
