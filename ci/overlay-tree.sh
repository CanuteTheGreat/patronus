#!/bin/bash
# Print the git tree id of the published Patronus overlay: gentoo/ of HEAD reduced to the Portage parts
# (metadata/, profiles/ and every category directory that holds ebuilds). Used by .forgejo/workflows/overlay-sync.yml;
# writes nothing but git objects (a temporary index).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
idx=$(mktemp); trap 'rm -f "$idx"' EXIT
export GIT_INDEX_FILE=$idx
git read-tree --empty
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
  git read-tree --prefix="$k/" "HEAD:gentoo/$k"
done
git write-tree
