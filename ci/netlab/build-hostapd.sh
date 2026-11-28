#!/usr/bin/env bash
# Build hostapd + wpa_supplicant from the upstream release with the 802.11 options of Gentoo's
# net-wireless/hostapd ebuild (CONFIG_IEEE80211AX/BE, SAE, OWE, OCV, nl80211), for the Wi-Fi 6/6E/7 hwsim lane.
# Debian/Ubuntu's hostapd is built without CONFIG_IEEE80211BE; Gentoo's (the product's) is built with it, so this is
# what the lane must run against. Installs into PREFIX (default /opt/wifi/wrap, first on the hwsim scenarios' PATH).
# Tarballs are pinned by SHA-256; usage: ci/netlab/build-hostapd.sh [VERSION] (inside the Debian/Ubuntu container).
set -euo pipefail
V=${1:-2.12}
PREFIX=${PREFIX:-/opt/wifi/wrap}
declare -A SUM=(
  [hostapd-2.12]=f43502561c28ba47ab77e18e1a973d07361c68cc8b14178e619bd5796b70eabd
  [wpa_supplicant-2.12]=08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6
)
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq build-essential pkg-config libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev curl ca-certificates >/dev/null
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
for p in hostapd wpa_supplicant; do
  f="$p-$V.tar.gz"
  [ -n "${SUM[$p-$V]:-}" ] || { echo "no pinned checksum for $p-$V"; exit 1; }
  curl -fsSL --retry 3 "https://w1.fi/releases/$f" -o "$W/$f"
  echo "${SUM[$p-$V]}  $W/$f" | sha256sum -c --quiet
  tar -C "$W" -xzf "$W/$f"
done
opts='CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y
CONFIG_ELOOP_EPOLL=y
CONFIG_CTRL_IFACE=y
CONFIG_IEEE80211R=y
CONFIG_IEEE80211AC=y
CONFIG_IEEE80211AX=y
CONFIG_IEEE80211BE=y
CONFIG_OCV=y
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_DEBUG_FILE=y'
( cd "$W/hostapd-$V/hostapd" && printf '%s\n' "$opts" > .config && make -s -j"$(nproc)" >/dev/null )
( cd "$W/wpa_supplicant-$V/wpa_supplicant" && grep -v -E 'DBUS|CONFIG_EAP_SIM|CONFIG_PCSC' defconfig > .config \
  && printf '%s\n' "$opts" | grep -v -E 'ELOOP_EPOLL|DEBUG_FILE' >> .config && make -s -j"$(nproc)" >/dev/null )
mkdir -p "$PREFIX"
install -m755 "$W/hostapd-$V/hostapd/hostapd" "$W/hostapd-$V/hostapd/hostapd_cli" "$PREFIX/"
install -m755 "$W/wpa_supplicant-$V/wpa_supplicant/wpa_supplicant" "$W/wpa_supplicant-$V/wpa_supplicant/wpa_cli" "$PREFIX/"
"$PREFIX/hostapd" -v 2>&1 | head -1
