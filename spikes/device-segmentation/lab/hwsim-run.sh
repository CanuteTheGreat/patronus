#!/bin/bash
# Host side (an rw-man host with mac80211_hwsim, sudo + docker). Creates 4 virtual radios, moves them into a
# throw-away privileged container (own netns), runs hwsim-inner.sh, then removes everything again.
# usage: hwsim-run.sh <dir with seg-spike binary> <dir with examples/hwsim.json + lab/>
set -u
OUT=$1; SRC=$2; C=segspike-hwsim-$$
cleanup() { docker rm -f $C >/dev/null 2>&1; sudo rmmod mac80211_hwsim 2>/dev/null; }
trap cleanup EXIT
lsmod | grep -q mac80211_hwsim && { echo "mac80211_hwsim already loaded by someone else; refusing"; exit 2; }
sudo modprobe mac80211_hwsim radios=4 || exit 1
docker run -d --name $C --privileged --security-opt apparmor=unconfined --memory=1g -v $OUT:/out:ro -v $SRC:/src:ro debian:trixie sleep 900 >/dev/null
docker exec $C sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends hostapd wpasupplicant iw iproute2 python3-minimal >/dev/null 2>&1; which hostapd wpa_supplicant iw ip python3 >/dev/null || exit 1'
PID=$(docker inspect -f '{{.State.Pid}}' $C)
# phy numbers keep counting up across modprobe cycles: take whatever the module created
PHYS=$(ls /sys/class/ieee80211 | sort -V); [ $(echo $PHYS | wc -w) -eq 4 ] || { echo "expected 4 hwsim phys, got: $PHYS"; exit 1; }
for p in $PHYS; do sudo iw phy $p set netns $PID || exit 1; done
docker exec $C bash /src/lab/hwsim-inner.sh /out/seg-spike /src/examples/hwsim.json
rc=$?
docker exec $C sh -c 'cat /w/log/hostapd-sae.log | grep -iE "sae|reload" | tail -5' 2>/dev/null | sed 's/^/  [hostapd sae log] /'
exit $rc
