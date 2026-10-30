#!/usr/bin/env bash
# Compile patronus-cli once per cargo feature that the Gentoo ebuild maps a
# USE flag to (src_configure's myfeatures), each on its own with
# --no-default-features exactly like cargo_src_configure does, so a USE flag
# that only compiles as part of the full default set is caught. The list is
# read from the live ebuild, so a newly mapped USE flag is covered
# automatically. Also checks every mapped feature really exists in
# patronus-cli/Cargo.toml (a mismatch kills the real emerge).
set -euo pipefail
cd "$(dirname "$0")/.."

EBUILD=gentoo/net-firewall/patronus/patronus-9999.ebuild
mapfile -t FEATURES < <(grep -oE 'usex [a-z0-9-]+ "[a-z0-9-]+"' "$EBUILD" | awk -F'"' '{print $2}' | sort -u)
[ "${#FEATURES[@]}" -gt 5 ] || { echo "could not parse myfeatures from $EBUILD"; exit 1; }

CLI_FEATURES=$(awk '/^\[features\]/{f=1;next} /^\[/{f=0} f && /=/{print $1}' crates/patronus-cli/Cargo.toml)
for f in "${FEATURES[@]}"; do
  echo "$CLI_FEATURES" | grep -x "$f" >/dev/null || { echo "::error::ebuild maps a USE flag to cargo feature '$f' that patronus-cli does not define"; exit 1; }
done

echo "USE-mapped features: ${FEATURES[*]}"
for f in "${FEATURES[@]}"; do
  echo "::group::patronus-cli --no-default-features --features $f"
  cargo check -p patronus-cli --no-default-features --features "$f"
  echo "::endgroup::"
done
echo "::group::patronus-cli with every USE-mapped feature (cargo build)"
cargo build -p patronus-cli --no-default-features --features "$(IFS=,; echo "${FEATURES[*]}")"
echo "::endgroup::"
