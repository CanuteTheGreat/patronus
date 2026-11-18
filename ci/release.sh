#!/usr/bin/env bash
# Cut a Patronus release: ci/release.sh X.Y.Z[-pre]
#
#   1. checks: on main, clean tree, up to date with origin/main, X.Y.Z is valid
#      semver and newer than the last v* tag, HEAD's rust-ci.yml run is green
#   2. sets the workspace version in Cargo.toml (Cargo.lock is not committed in this repo), regenerates
#      CHANGELOG.md with ci/changelog.py --release, commits "release: vX.Y.Z"
#   3. creates the annotated tag vX.Y.Z (signed with -s when RELEASE_SIGN=1)
#
# Nothing is pushed: review, then `git push origin main vX.Y.Z`. The tag push
# runs release.yml (binaries, third-party license list, release notes from CHANGELOG.md) and the
# live-ISO workflows. What each kind of version means and the update/rollback
# policy: docs/UPDATE-POLICY.md.
#
# Env: SKIP_CI_CHECK=1 skips the green-CI check (offline use only).
set -euo pipefail

ver="${1:?usage: ci/release.sh X.Y.Z[-pre]}"
ver="${ver#v}"
tag="v$ver"
cd "$(git rev-parse --show-toplevel)"

[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
    { echo "not a semver version: $ver" >&2; exit 2; }
[ "$(git branch --show-current)" = main ] || { echo "release from main only" >&2; exit 2; }
git diff --quiet && git diff --cached --quiet || { echo "working tree not clean" >&2; exit 2; }
git fetch -q --tags origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
    { echo "HEAD is not origin/main: pull first" >&2; exit 2; }
git rev-parse -q --verify "refs/tags/$tag" >/dev/null && { echo "$tag already exists" >&2; exit 2; }

if [ "${SKIP_CI_CHECK:-0}" != 1 ]; then
    : "${FORGEJO_TOKEN:?set FORGEJO_TOKEN (read access) or SKIP_CI_CHECK=1}"
    sha="$(git rev-parse HEAD)"
    state="$(curl -fsS -H "Authorization: token $FORGEJO_TOKEN" \
        "https://git.canutethegreat.com/api/v1/repos/CanuteTheGreat/patronus/actions/runs?head_sha=$sha" |
        python3 -c 'import json,sys
runs=[r for r in json.load(sys.stdin).get("workflow_runs",[]) if r.get("workflow_id")=="rust-ci.yml" and r.get("status")!="cancelled"]
print(runs[0]["status"] if runs else "none")')"
    [ "$state" = success ] || { echo "rust-ci.yml on $sha is '$state', not success: release a green commit" >&2; exit 3; }
fi

# workspace version (the [workspace.package] block of the root Cargo.toml; crates with version.workspace = true follow)
python3 - "$ver" <<'PY'
import re, sys
p = "Cargo.toml"
s = open(p).read()
m = re.search(r"(\[workspace\.package\][^\[]*?\nversion\s*=\s*\")([^\"]+)(\")", s)
if not m:
    sys.exit("no [workspace.package] version in Cargo.toml")
open(p, "w").write(s[:m.start(2)] + sys.argv[1] + s[m.end(2):])
print(f"Cargo.toml: {m.group(2)} -> {sys.argv[1]}")
PY
python3 ci/changelog.py --release "$ver"
git add Cargo.toml CHANGELOG.md
git commit -q -m "release: $tag"
if [ "${RELEASE_SIGN:-0}" = 1 ]; then
    git tag -s -m "Patronus $tag" "$tag"
else
    git tag -a -m "Patronus $tag" "$tag"
fi
python3 ci/changelog.py --check
echo "release commit $(git rev-parse --short HEAD) tagged $tag."
echo "next: git push origin main $tag"
