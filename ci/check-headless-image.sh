#!/usr/bin/env bash
# Headless-first / nothing-personal guard for the Patronus images (owner rule 2026-11-03: "It should work on a headless server too").
# Static, no build needed; runs in the rust-ci installer step. What it enforces (docs/HEADLESS.md):
#   1. the image's own package inputs (project/packages*.txt, project/portage, project/overlay, the ebuild's RDEPEND/IUSE) carry no desktop/GUI package,
#      no personal app/account/key (Tailscale, Nextcloud, browsers, the Rustinion agent, ssh keys, auth keys);
#   2. the shared common/ package lists only reach a GUI through packages-gui.txt, which is live-only (removed from every installed Server);
#   3. every architecture of the live-ISO matrix runs the headless gates (--headless-gates: late network, months-off RTC, no GUI stack, accounts).
set -u
cd "$(dirname "$0")/.."
L=gentoo/live-iso
fail=0
bad() { echo "::error::headless-image: $*"; fail=1; }

DENY='(^|[ /])(x11-base|x11-wm|x11-drivers|gui-wm|gui-apps|gnome-base|gnome-extra|kde-[a-z]+|xfce-[a-z]+|lxde-[a-z]+)/|gui-libs/(gtk|libadwaita)|x11-libs/(gtk\+|libX11)|media-libs/mesa|www-client/|net-vpn/tailscale|nextcloud|net-p2p/|app-admin/rustinion|rustinion-bin|dev-python/pygobject|app-office/|media-video/(vlc|mpv)|games-'
for f in $L/common/packages.txt $L/common/packages-extra.txt $L/project/packages.txt $L/project/packages-late.txt; do
  [ -f "$f" ] || continue
  hit=$(grep -v '^[[:space:]]*#' "$f" | grep -Ei "$DENY" || true)
  [ -z "$hit" ] || bad "$f lists a desktop/personal package: $(echo "$hit" | tr '\n' ' ')"
done
# project/portage and the overlay: no personal literal, no key material
if [ -d $L/project/portage ] || [ -d $L/project/overlay ]; then
  hit=$(grep -rIlEi 'tailscale|tskey-|nextcloud|rustinion|hogshead|gringotts|hogsmeade|ssh-(ed25519|rsa|ecdsa) AAAA|BEGIN [A-Z ]*PRIVATE KEY|authorized_keys' $L/project/portage $L/project/overlay 2>/dev/null | grep -v '\.gitkeep' || true)
  [ -z "$hit" ] || bad "personal or key material in the image inputs: $hit"
fi
# the Gentoo ebuild: no GUI USE flag / dependency (RDEPEND is installed on every box)
for e in gentoo/net-firewall/patronus/patronus-*.ebuild; do
  [ -f "$e" ] || continue
  hit=$(awk '/^RDEPEND="/{f=1} f{print} /^"/{if(f)exit}' "$e" | grep -Ei 'x11-|gui-|gnome|qt|gtk|wayland|xorg' || true)
  [ -z "$hit" ] || bad "$e RDEPEND pulls a GUI package: $hit"
  grep -Eq '^[[:space:]]*\+?(X|gtk|qt5|qt6|wayland|gui|desktop)$' "$e" && bad "$e has a GUI USE flag"
done
# the only GUI in the image is the live-only installer stack
grep -q 'live-only-packages' $L/common/Dockerfile.rootfs || bad "Dockerfile.rootfs no longer records the live-only (GUI installer) package list"
grep -q 'strip_live_gui' $L/common/overlay/usr/lib/live-installer/liveinst/system.py || bad "the installer no longer removes the live-only GUI stack from a Server install"
grep -q 'install_type' $L/project/overlay/etc/live-installer/profile.toml && bad "profile.toml must not offer a desktop install type"
# every architecture of the workflow matrix has a headless-gates run
for arch in x86_64 aarch64; do
  n=$(ARCH=$arch bash -c 'MATRIX=("a|--x"); PROJECT=patronus; . '$L'/project/ci-matrix.sh; printf "%s\n" "${MATRIX[@]}"' 2>/dev/null | grep -c -- '--headless-gates')
  [ "${n:-0}" -ge 1 ] || bad "$arch: no matrix run carries --headless-gates"
done
[ $fail = 0 ] && echo "headless-image: OK (no desktop/personal package in the image inputs; headless gates on every architecture)"
exit $fail
