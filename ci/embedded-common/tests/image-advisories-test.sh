#!/bin/sh
# Host test of ci/embedded-common/make-package-manifest.py (the router image's package manifest + advisory gate):
# Alpine version ordering, the secdb match (fixed-version key, the "0" key ignored), accepted advisories, --enforce,
# a missing database leaving the manifest without a gate result (never a clean one). Needs python3 only.
set -eu
D=$(cd "$(dirname "$0")" && pwd); T=$D/../make-package-manifest.py
W=$(mktemp -d "${TMPDIR:-/tmp}/imgadv.XXXX"); trap 'rm -rf "$W"' EXIT
rc=0
fail() { echo "FAIL: $*"; rc=1; }
python3 - "$D/.." <<'PY' || fail "version ordering"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("m", sys.argv[1] + "/make-package-manifest.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.cmp_version
assert c("1.36.1-r5", "1.36.1-r6") == -1
assert c("1.36.1-r6", "1.36.1-r6") == 0
assert c("1.7.0-r4", "1.7.0_rc1-r0") == 1          # a release is newer than its rc
assert c("3.5.1-r0", "3.5.1_p1-r0") == -1          # _p patch level is newer
assert c("2024.10-r0", "2024.9-r0") == 1
assert c("1.2", "1.2.1") == -1
assert c("1.2a-r0", "1.2-r0") == 1
assert m.split_apk("linux-pam-1.7.0-r4") == ("linux-pam", "1.7.0-r4")
assert m.split_apk("libcrypto3-3.5.1-r0") == ("libcrypto3", "3.5.1-r0")
assert m.split_apk("u-boot-tools-2024.10-r0") == ("u-boot-tools", "2024.10-r0")
PY
echo "PASS: Alpine version ordering and package line splitting"
printf '# accepted on purpose\nCVE-2099-1001 not exploitable here: applet not enabled\n' > "$W/accepts"
python3 "$T" --apk-list "$D/fixtures/apk-installed.txt" --image ax1800 --version 0.2.1 --out "$W/m.json" --secdb "$D/fixtures/secdb-main.json" --date 2026-11-25 >"$W/out" 2>&1 || fail "report mode must exit 0"
python3 - "$W/m.json" <<'PY' || fail "manifest content"
import json, sys
m = json.load(open(sys.argv[1]))
assert m["schema"] == 1 and m["distribution"] == "alpine" and m["image"] == "ax1800"
assert [p["name"] for p in m["packages"]] == ["busybox", "curl", "libcrypto3", "linux-pam", "u-boot-tools"], m["packages"]
ids = sorted(f["advisory"] for f in m["gate"]["findings"])
assert ids == ["CVE-2099-1001"], ids      # the "0" key, equal versions and older fixes are not findings
f = m["gate"]["findings"][0]
assert f["package"] == "busybox" and f["installed"] == "1.36.1-r5" and f["fixed_in"] == ["1.36.1-r6"]
assert f["url"] == "https://security.alpinelinux.org/vuln/CVE-2099-1001"
assert m["gate"]["checked_at"] == "2026-11-25"
PY
echo "PASS: manifest lists the packages; only the affected advisory is a finding"
if python3 "$T" --apk-list "$D/fixtures/apk-installed.txt" --image ax1800 --version 0.2.1 --out "$W/m2.json" --secdb "$D/fixtures/secdb-main.json" --enforce >"$W/out2" 2>&1; then fail "--enforce passed with an unaccepted advisory"; else grep -q 'image-advisory.*busybox' "$W/out2" && echo "PASS: --enforce fails the build and names the package" || fail "--enforce message"; fi
python3 "$T" --apk-list "$D/fixtures/apk-installed.txt" --image ax1800 --version 0.2.1 --out "$W/m3.json" --secdb "$D/fixtures/secdb-main.json" --accepts "$W/accepts" --enforce >"$W/out3" 2>&1 || fail "an accepted advisory still failed the build: $(cat "$W/out3")"
python3 -c "
import json; m = json.load(open('$W/m3.json')); g = m['gate']
assert g['findings'] == [] and g['accepted'][0][0] == 'CVE-2099-1001' and 'not exploitable' in g['accepted'][0][1], g" || fail "accepted advisory recorded"
echo "PASS: an accepted advisory passes --enforce and is recorded with its reason"
# no database reachable: no gate result (and no fake clean one)
python3 "$T" --apk-list "$D/fixtures/apk-installed.txt" --image ax1800 --version 0.2.1 --out "$W/m4.json" --release 0.0.invalid >"$W/out4" 2>&1 || fail "unreachable database must not fail the build"
python3 -c "
import json; m = json.load(open('$W/m4.json')); assert 'gate' not in m, m" || fail "a gate result was invented"
echo "PASS: without a security database the manifest carries no gate result"
exit $rc
