#!/bin/sh
# kernel-track.sh [--check|--bump|--print]: keep the embedded tier on the newest patch release of its pinned LTS line.
#   --print  show pinned vs newest (default)
#   --check  exit 1 when the pin is behind kernel.org by more than MAX_LAG_DAYS (CI red = the kernel lags again)
#   --bump   rewrite KERNEL_PATCH/KERNEL_SHA256 in kernel.pin to the newest patch of KERNEL_LINE (nothing else), print
#            "bump <old> <new>" on stdout (nothing when current). The caller builds, gates, merges and queues the window flash.
# The line is configuration (kernel.pin KERNEL_LINE); MAX_LAG_DAYS, KERNEL_RELEASES_URL and KERNEL_SUMS_URL may be set in
# the environment (defaults below). Tests feed a local JSON/sums file through the two URL variables.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); PIN=${KERNEL_PIN:-$HERE/kernel.pin}; MODE=${1:---print}
. "$PIN"
MAX_LAG_DAYS=${MAX_LAG_DAYS:-3}
REL=${KERNEL_RELEASES_URL:-https://www.kernel.org/releases.json}
major=${KERNEL_LINE%%.*}
SUMS=${KERNEL_SUMS_URL:-https://cdn.kernel.org/pub/linux/kernel/v$major.x/sha256sums.asc}
fetch() { case $1 in http*) curl -fsSL --max-time 60 "$1";; *) cat "$1";; esac; }
J=$(fetch "$REL")
# newest version of the line + its release date (releases.json lists only maintained lines; a line that is gone is an error)
new=$(printf '%s' "$J" | python3 -c '
import sys,json
line=sys.argv[1]; best=None
for r in json.load(sys.stdin)["releases"]:
    v=r["version"]
    if v.startswith(line+".") and r["moniker"] in ("longterm","stable"):
        best=(v,r.get("released",{}).get("isodate",""))
if not best: sys.exit(3)
print(best[0],best[1])' "$KERNEL_LINE") || { echo "kernel-track: kernel.org no longer lists line $KERNEL_LINE (EOL?): move KERNEL_LINE in $PIN" >&2; exit 3; }
nv=${new%% *}; nd=${new#* }; np=${nv##*.}
case $MODE in
  --print) echo "pinned $KERNEL_LINE.$KERNEL_PATCH newest $nv ($nd)";;
  --check)
    [ "$np" -le "$KERNEL_PATCH" ] && { echo "kernel-track: current ($KERNEL_LINE.$KERNEL_PATCH)"; exit 0; }
    age=$(python3 -c 'import sys,datetime;d=datetime.date.fromisoformat(sys.argv[1][:10]);print((datetime.date.today()-d).days)' "$nd" 2>/dev/null || echo 999)
    if [ "$age" -gt "$MAX_LAG_DAYS" ]; then echo "kernel-track: LAG pinned $KERNEL_LINE.$KERNEL_PATCH, kernel.org has $nv since $nd ($age days > $MAX_LAG_DAYS)" >&2; exit 1; fi
    echo "kernel-track: $nv is only $age days old (limit $MAX_LAG_DAYS)";;
  --bump)
    [ "$np" -le "$KERNEL_PATCH" ] && exit 0
    h=$(fetch "$SUMS" | awk -v f="linux-$nv.tar.xz" '$2==f{print $1}')
    [ ${#h} -eq 64 ] || { echo "kernel-track: no sha256 for linux-$nv.tar.xz in $SUMS" >&2; exit 4; }
    sed -i -e "s/^KERNEL_PATCH=.*/KERNEL_PATCH=$np/" -e "s/^KERNEL_SHA256=.*/KERNEL_SHA256=$h/" "$PIN"
    echo "bump $KERNEL_LINE.$KERNEL_PATCH $nv";;
  *) echo "usage: kernel-track.sh [--print|--check|--bump]" >&2; exit 2;;
esac
