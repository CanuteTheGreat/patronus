#!/usr/bin/env bash
# The installed Patronus image carries the product through Portage (gentoo/live-iso/project/image/patronus-image.ebuild, merged by
# /usr/libexec/project-image-packages), not through hand copies in the Dockerfile. Static gate against the old failure: the image
# lost every init script nobody had listed by hand (patronus-dhcpc: the setup wizard died with "service does not exist").
#   1. the image ebuild installs init scripts, units, timers by GLOB over the real ebuild's files/ directory (never a hand list)
#   2. Dockerfile.app stages the payload and no longer copies init scripts / units / config into / itself
#   3. project/setup.sh creates nothing by hand (no chmod of init scripts, groupadd, useradd): packages own it
#   4. the installer profile enables patronus-services (the second boot pass) and the files exist for both inits
#   5. both real ebuilds install patronus-services too (same service set as the image)
#   6. the ETPhoneHome router client (USE=etph, default on) is in the product's dependencies, staged into the image repository, verified
#      by project-image-packages (the build fails when a file of it is missing) and enabled by the installer profile (OpenRC + systemd files
#      are the package's: net-misc/etphonehome-bin ships /etc/init.d/etphonehome and etphonehome.service, which the image gate asserts)
# Usage: ci/check-image-ebuild-parity.sh [repo-root]
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
P=gentoo/live-iso/project
F=gentoo/net-firewall/patronus/files
rc=0
bad() { echo "::error::[image-ebuild] $*"; rc=1; }

E=$P/image/patronus-image.ebuild
[ -f "$E" ] || bad "$E missing"
for g in 'files/\*\.initd' 'files/\*\.service' 'files/\*\.timer'; do
  grep -Eq "$g" "$E" || bad "$E does not install by glob over $g (a hand-kept list loses new service files)"
done
grep -q 'newconfd files/patronus.confd patronus' "$E" || bad "$E does not install /etc/conf.d/patronus"
grep -q 'pamd_mimic_system patronus auth account' "$E" || bad "$E does not install the patronus PAM service"

D=$P/Dockerfile.app
grep -q '/usr/share/patronus-image' "$D" || bad "$D does not stage the payload under /usr/share/patronus-image"
if grep -Eq '^COPY .*(\.initd|\.service|\.confd|patronus\.toml|web-auth\.toml)' "$D"; then
  bad "$D copies product files into the image by hand: they must come from the package"
fi
grep -Eq 'cp .* /out/(etc|usr/lib/systemd)' "$D" && bad "$D copies files into /out/etc or /out/usr/lib/systemd by hand"

S=$P/setup.sh
grep -Eq '^[^#]*(chmod \+x /etc/init\.d|groupadd|useradd)' "$S" && bad "$S creates the user/group or fixes init-script modes by hand"
[ -x $P/overlay/usr/libexec/project-image-packages ] || bad "project-image-packages is missing or not executable"
grep -q 'project-image-packages' gentoo/live-iso/common/setup-rootfs.sh || bad "common/setup-rootfs.sh does not run /usr/libexec/project-image-packages"

grep -Eq '^services = \[.*"patronus-services"' $P/overlay/etc/live-installer/profile.toml || bad "installer profile does not enable patronus-services"
[ -f "$F/patronus-services.initd" ] && [ -f "$F/patronus-services.service" ] || bad "patronus-services needs both an OpenRC script and a systemd unit"
for e in gentoo/net-firewall/patronus/patronus-9999.ebuild gentoo/net-firewall/patronus/patronus-0.2.0.ebuild; do
  grep -q 'patronus-services.initd' "$e" && grep -q 'patronus-services.service' "$e" || bad "$e does not install patronus-services for both inits"
done
for e in gentoo/net-firewall/patronus/patronus-9999.ebuild gentoo/net-firewall/patronus/patronus-0.2.0.ebuild $E; do
  grep -Eq '^IUSE=.*\+etph|^[[:space:]]+\+etph' "$e" && grep -q 'etph? ( net-misc/etphonehome-bin )' "$e" || bad "$e lacks the default-on etph USE flag pulling net-misc/etphonehome-bin"
done
grep -q 'net-misc/etphonehome-bin' "$D" || bad "$D does not stage net-misc/etphonehome-bin into the image repository"
PK=$P/overlay/usr/libexec/project-image-packages
for f in /usr/sbin/etphonehome /etc/init.d/etphonehome /usr/lib/systemd/system/etphonehome.service /etc/etph/etph.conf; do
  grep -q "$f" "$PK" || bad "project-image-packages does not verify $f (a missing ETPhoneHome file must fail the image build)"
done
grep -Eq '^services = \[.*"etphonehome"' $P/overlay/etc/live-installer/profile.toml || bad "installer profile does not enable etphonehome"
[ $rc -eq 0 ] && echo "[image-ebuild] ok"
exit $rc
