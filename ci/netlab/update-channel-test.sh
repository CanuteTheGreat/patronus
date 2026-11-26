#!/usr/bin/env bash
# Update channel netlab test (standard tier). Runs INSIDE the Gentoo container started by
#   NETLAB_TEST=update-channel-test.sh ci/netlab/lan-services.sh openrc
# as root, with the shipped patronus-cli and the repository's Portage overlay (gentoo/ reduced to what
# ci/overlay-tree.sh publishes) in /t/overlay. Proves with the REAL Portage of the image that the files
# `patronus update channel` writes make each channel pick what it promises:
#   stable -> the newest tagged release, never a release candidate or the live ebuild;
#   testing -> release candidates too, never the live ebuild;
#   development -> net-firewall/patronus-9999, and `emerge -p` resolves it;
# plus the binary package host on/off, refused bad values that change nothing, and the "managed by
# Patronus" header. No network: the overlay is placed where a sync would put it (the git/rsync sync from
# the published mirror is proven by hand, see docs/UPDATE-POLICY.md).
set -u
INIT=${1:-openrc}
CLI=/t/patronus-cli
DB=/t/update-channel.db
REPO=/var/db/repos/patronus-test
fail=0
pass() { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }
chk() { if eval "$2"; then pass "$1"; else bad "$1"; fi; }
best() { portageq best_visible / net-firewall/patronus 2>/dev/null; }
uc() { $CLI --db $DB update channel "$@" > /t/uc.log 2>&1; }

[ -d /t/overlay/net-firewall/patronus ] || { echo "FAIL no overlay in /t/overlay"; exit 1; }
rm -rf "$REPO"; mkdir -p "$(dirname "$REPO")"; cp -a /t/overlay "$REPO"
rel=$(cd "$REPO/net-firewall/patronus" && ls patronus-*.ebuild | sed 's/\.ebuild$//; s/^patronus-//' \
  | grep -v -E '^9999$|_(alpha|beta|pre|rc)' | sort -V | tail -1)
echo "--- newest release ebuild in the overlay: $rel ($INIT)"
[ -n "$rel" ] || { echo "FAIL no release ebuild"; exit 1; }

uc --set stable --mirror file:///srv/patronus-overlay --location "$REPO" || { cat /t/uc.log; bad set-stable; }
chk repos-conf-managed 'grep -q "managed by Patronus" <<<"$(head -1 /etc/portage/repos.conf/patronus.conf)"'
chk repos-conf-mirror 'grep -qx "sync-uri = file:///srv/patronus-overlay" /etc/portage/repos.conf/patronus.conf'
chk repos-conf-location 'grep -qx "location = $REPO" /etc/portage/repos.conf/patronus.conf'
chk portage-knows-repo 'grep -qx patronus <<<"$(portageq get_repos / | tr " " "\n")"'
b=$(best); echo "stable: $b"
chk stable-gets-release '[ "$b" = "net-firewall/patronus-$rel" ]'

uc --set development || bad set-development
b=$(best); echo "development: $b"
chk development-gets-live '[ "$b" = net-firewall/patronus-9999 ]'
# (USE: this lab image's package.use turns VPN backends off; a real install has its own USE)
pv=$(USE="wireguard" emerge -p --nodeps =net-firewall/patronus-9999 2>&1)
chk emerge-resolves-live 'grep -q "^\[ebuild.*net-firewall/patronus-9999" <<<"$pv"' || true
grep -q "^\[ebuild.*net-firewall/patronus-9999" <<<"$pv" || tail -25 <<<"$pv"

# a release candidate newer than the release (what a vX.Y.Z-rc.N tag's ebuild looks like)
cp "$REPO/net-firewall/patronus/patronus-$rel.ebuild" "$REPO/net-firewall/patronus/patronus-99.0.0_rc1.ebuild"
uc --set testing || bad set-testing
b=$(best); echo "testing: $b"
chk testing-gets-rc '[ "$b" = net-firewall/patronus-99.0.0_rc1 ]'
uc --set stable || bad set-stable-again
chk stable-prerelease-mask 'grep -qx "=net-firewall/patronus-99.0.0_rc1" /etc/portage/package.mask/patronus-channel-prerelease'
b=$(best); echo "stable with an rc present: $b"
chk stable-refuses-rc '[ "$b" = "net-firewall/patronus-$rel" ]'

uc --binhost https://pkgs.example.org/patronus/amd64 || bad binhost-set
chk binrepo-written 'grep -qx "sync-uri = https://pkgs.example.org/patronus/amd64" /etc/portage/binrepos.conf/patronus.conf'
uc --binhost none || bad binhost-none
chk binrepo-removed '! test -e /etc/portage/binrepos.conf/patronus.conf'
before=$(cat /etc/portage/package.accept_keywords/patronus-channel /etc/portage/repos.conf/patronus.conf)
if uc --set nightly; then bad bad-channel-refused; else pass bad-channel-refused; fi
if uc --mirror 'https://x.example/a b'; then bad bad-mirror-refused; else pass bad-mirror-refused; fi
if uc --location relative/dir; then bad bad-location-refused; else pass bad-location-refused; fi
chk refused-changes-nothing '[ "$before" = "$(cat /etc/portage/package.accept_keywords/patronus-channel /etc/portage/repos.conf/patronus.conf)" ]'
out=$($CLI --db $DB update channel 2>/dev/null)
chk refused-keeps-stable 'grep -q "^channel:  stable" <<<"$out"'

rm -rf "$REPO" /etc/portage/repos.conf/patronus.conf /etc/portage/package.accept_keywords/patronus-channel \
  /etc/portage/package.mask/patronus-channel /etc/portage/package.mask/patronus-channel-prerelease
echo "RESULT update-channel fail=$fail"
exit $fail
