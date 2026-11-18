#!/bin/sh
# handoff.sh: install an upgrade that `patronus-flash sysupgrade` staged, WITHOUT a restart first, on a GL-AX1800 unit
# whose early-boot verifier refuses every signed image (builds before the gpgv --ignore-time-conflict fix: at early boot
# the board has no clock yet, 1970, so the release key looks "created in the future" and the staged upgrade is rejected).
# The installer (upgrade-install install, the same code the early boot hands PID 1 to) runs here as PID 1 through
# OpenRC's re-exec: this script is bind-mounted over /sbin/openrc-init and `openrc-shutdown --reexec` makes PID 1 exec it.
# It then puts the box into the early-boot state (every process stopped, /etc /var/lib /root overlays unmounted) and
# execs the installer, which copies the parts to RAM, checks sha256 + release signature again (clock is right now),
# pivots to the RAM root, writes root + kernel with read-back, restarts. Any failure before writing restarts into the
# old system; the staged upgrade is then rejected by the next boot as before (nothing lost).
#   handoff-install.sh arm      (as root, after `patronus-flash sysupgrade <img>` WITHOUT --now): checks, then triggers
#   (PID 1 path)        the re-exec'd part (argument "reexec" from openrc-init)
set -u
if [ "$$" != 1 ]; then
  [ "${1:-}" = arm ] || { sed -n '2,15p' "$0"; exit 2; }
  [ "$(readlink /proc/1/exe)" = /sbin/openrc-init ] || { echo "PID 1 is not openrc-init"; exit 1; }
  [ -f /data/.upgrade/ready ] || { echo "nothing staged (patronus-flash sysupgrade <img> first)"; exit 1; }
  . /usr/libexec/patronus/fwcheck.sh
  fw_check_parts /data/.upgrade || { echo "the staged upgrade does not verify now"; exit 1; }
  me=$(readlink -f "$0"); chmod 755 "$me"
  echo "$(cut -d' ' -f1 /proc/uptime) handoff: arming PID 1 re-exec for $(sed -n 's/^BUILD=//p' /data/.upgrade/patronus-release)" >> /data/upgrade.log
  sync
  mount --bind "$me" /sbin/openrc-init || exit 1
  setsid sh -c 'sleep 2; openrc-shutdown --reexec' > /dev/null 2>&1 < /dev/null &
  echo "armed: PID 1 re-execs in 2 s, the box installs and restarts (~2-3 min)"
  exit 0
fi
# --- PID 1 ---
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
c() { echo "handoff: $*" > /dev/console 2>/dev/null; echo "$(cut -d' ' -f1 /proc/uptime) handoff: $*" >> /data/upgrade.log 2>/dev/null; }
c "PID 1 re-exec reached, stopping every process"
kill -TERM -1 2>/dev/null; sleep 3; kill -KILL -1 2>/dev/null; sleep 1
sync
for m in /root /var/lib /etc; do umount "$m" 2>/dev/null || { c "umount $m busy, detaching"; umount -l "$m"; }; done
umount -l /sbin/openrc-init 2>/dev/null
c "early-boot state reached, handing PID 1 to upgrade-install"
exec /usr/libexec/patronus/upgrade-install install
