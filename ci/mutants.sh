#!/usr/bin/env bash
# Mutation testing baseline for the core of the product: the config store,
# the boot/apply engine and the firewall applier/renderer. A surviving
# mutant is a code change no test notices -- i.e. a missing assertion.
#
# For each "<package> <file> <floor>" line in ci/mutants-floors.txt this runs
# cargo-mutants on that file (tests of that package only), computes
#   score = (caught + timeout) / (caught + missed + timeout)   (unviable excluded)
# and fails if the score is below the floor. Floors only ratchet up: when a
# run beats a floor by >= 2 points, raise the floor in the same commit as the
# tests that earned it.
#
# Usage: ci/mutants.sh [floors-file]       env: MUTANTS_JOBS (default 2)
set -uo pipefail
cd "$(dirname "$0")/.."
FLOORS=${1:-ci/mutants-floors.txt}
JOBS=${MUTANTS_JOBS:-2}
OUTROOT=${MUTANTS_OUT:-target/mutants}
mkdir -p "$OUTROOT"
fail=0
summary=$OUTROOT/summary.txt
: > "$summary"

while read -r pkg file floor; do
  case "$pkg" in ''|'#'*) continue ;; esac
  name=$(echo "$file" | tr '/' '_')
  out=$OUTROOT/$name
  rm -rf "$out"
  echo "### cargo mutants -p $pkg --file $file (floor $floor%)"
  cargo mutants --package "$pkg" --file "$file" --jobs "$JOBS" --timeout-multiplier 3 \
    --no-shuffle --output "$out" >"$out.log" 2>&1
  rc=$?
  # exit 2 = missed mutants, 3 = timeouts: both are scored below; others are errors
  if [ $rc -ne 0 ] && [ $rc -ne 2 ] && [ $rc -ne 3 ]; then
    tail -40 "$out.log"; echo "cargo mutants failed for $file (exit $rc)"; fail=1; continue
  fi
  read -r caught missed timeout unviable < <(python3 - "$out/mutants.out/outcomes.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
c = {"CaughtMutant": 0, "MissedMutant": 0, "Timeout": 0, "Unviable": 0}
for o in d["outcomes"]:
    s = o.get("summary")
    if s in c:
        c[s] += 1
print(c["CaughtMutant"], c["MissedMutant"], c["Timeout"], c["Unviable"])
EOF
)
  total=$((caught + missed + timeout))
  score=$(python3 -c "print(100 if $total == 0 else int(100 * ($caught + $timeout) / $total))")
  line="$pkg $file: score $score% (caught $caught, missed $missed, timeout $timeout, unviable $unviable) floor $floor%"
  echo "$line" | tee -a "$summary"
  if [ -s "$out/mutants.out/missed.txt" ]; then
    echo "  surviving mutants:"; sed 's/^/    /' "$out/mutants.out/missed.txt"
  fi
  if [ "$score" -lt "$floor" ]; then echo "  BELOW FLOOR"; fail=1; fi
done < "$FLOORS"

echo "=== mutation summary"; cat "$summary"
exit $fail
