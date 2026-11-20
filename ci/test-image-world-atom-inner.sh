#!/usr/bin/env bash
# Runs INSIDE the Gentoo CI base image (see ci/test-image-world-atom.sh).
set -euo pipefail
SRC=/src
HOOK=${HOOK:-$SRC/gentoo/live-iso/project/overlay/usr/libexec/project-image-packages}
fail() { echo "FAIL image-world-atom: $*"; exit 1; }

[ -d /var/db/repos/gentoo/profiles ] || [ -d /var/db/repos/gentoo/metadata ] || { echo "SKIP image-world-atom: no Portage tree in this image"; exit 0; }
export FEATURES="-sandbox -usersandbox -ipc-sandbox -network-sandbox -pid-sandbox"

# stage the product the way gentoo/live-iso/project/Dockerfile.app does, with dummy binaries
P=/usr/share/patronus-image
mkdir -p $P/payload/bin $P/payload/files $P/repo/net-firewall/patronus
for b in patronus-cli patronus-web patronus-install; do printf '#!/bin/sh\nexit 0\n' > $P/payload/bin/$b; chmod 755 $P/payload/bin/$b; done
cp -a $SRC/gentoo/net-firewall/patronus/files/. $P/payload/files/
cp -a $SRC/gentoo/acct-group $SRC/gentoo/acct-user $SRC/gentoo/sec-keys $P/repo/
cp $SRC/gentoo/live-iso/project/image/patronus-image.ebuild $P/repo/net-firewall/patronus/patronus-0.9.0_p20260101.ebuild

sh "$HOOK" || fail "the image hook failed"

WORLD=/var/lib/portage/world
echo "world entries for the product: $(grep -c '^net-firewall/patronus' $WORLD)"; grep '^net-firewall/patronus' $WORLD || true
if [ -z "${CONTROL:-}" ]; then
  grep -q -x 'net-firewall/patronus' $WORLD || fail "world does not carry the plain atom net-firewall/patronus"
  if grep -q '^net-firewall/patronus::' $WORLD; then fail "world pins net-firewall/patronus to a repository: $(grep '^net-firewall/patronus::' $WORLD)"; fi
fi
INST=$(qlist -Iv net-firewall/patronus || true)
grep -q '0.9.0_p20260101' <<<"$INST" || fail "the staged version is not installed: $INST"

# a second repository (another binhost/overlay) offers a newer build of the same package
R=/var/db/repos/second
mkdir -p $R/metadata $R/profiles $R/net-firewall/patronus /etc/portage/repos.conf
echo second > $R/profiles/repo_name
printf 'masters = gentoo\nthin-manifests = true\nauto-sync = false\n' > $R/metadata/layout.conf
cp $SRC/gentoo/live-iso/project/image/patronus-image.ebuild $R/net-firewall/patronus/patronus-0.9.1_p20260201.ebuild
ebuild $R/net-firewall/patronus/patronus-0.9.1_p20260201.ebuild manifest >/dev/null
# the CI base image accepts the live 9999 ebuild of the overlay: keep it out of this test, the upgrade must come from `second`
mkdir -p /etc/portage/package.mask
echo '>=net-firewall/patronus-9999' > /etc/portage/package.mask/zz-image-world-atom
printf '[second]\nlocation = %s\nauto-sync = no\n' "$R" > /etc/portage/repos.conf/second.conf

set +e
OUT=$(emerge -pv --usepkg=n --getbinpkg=n -u net-firewall/patronus 2>&1)
rc=$?
set -e
echo "$OUT" | tail -25
[ -z "${CONTROL:-}" ] || { echo "CONTROL run: emerge -pu exit $rc"; exit 0; }
[ $rc -eq 0 ] || fail "emerge -pu net-firewall/patronus from a second repository failed (exit $rc)"
if grep -q -i -E 'conflict|Multiple package instances|masked by' <<<"$OUT"; then fail "emerge -pu reports a conflict"; fi
grep -q 'net-firewall/patronus-0.9.1_p20260201::second' <<<"$OUT" || fail "the upgrade from the second repository was not selected"
echo "PASS image-world-atom: plain atom in world, upgrade from a second repository resolves without a conflict"
