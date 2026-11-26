#!/bin/bash
# Print the git tree id of the published Patronus overlay: gentoo/ of HEAD reduced to the Portage parts
# (metadata/, profiles/ and every category directory that holds ebuilds). Used by .forgejo/workflows/overlay-sync.yml
# and ci/netlab/lan-services.sh (update channel test); writes nothing but git objects (a temporary index).
set -euo pipefail
cd "$(dirname "$0")/.."
top=$PWD
g() { git -c safe.directory="$top" "$@"; }   # CI job containers check out as another uid
idx=$(mktemp); trap 'rm -f "$idx"' EXIT
export GIT_INDEX_FILE=$idx
g read-tree --empty
keep=(metadata profiles)
for d in gentoo/*/; do
  c=$(basename "$d")
  case "$c" in metadata|profiles) continue ;; esac
  # a category: name like net-firewall / acct-user / sec-keys with <pkg>/<pkg>-<ver>.ebuild below it
  [[ "$c" =~ ^[a-z0-9]+-[a-z0-9]+$ ]] || continue
  compgen -G "gentoo/$c/*/*.ebuild" >/dev/null || continue
  keep+=("$c")
done
for k in "${keep[@]}"; do
  g read-tree --prefix="$k/" "HEAD:gentoo/$k"
done
g write-tree
