#!/usr/bin/env python3
"""The shared map component is vendored, pinned and checksum-checked (crates/patronus-web/ui-map/map.pin).

* every `sha256 <file> = <hex>` line matches the vendored file (edit the component upstream in the Horcrux
  repo, ui-kit/map/, and re-vendor; never the copy here);
* router-tier budget: map.js <= 24 KB, map.css <= 6 KB as served;
* `--upstream DIR` (a horcrux checkout) also checks that `commit` holds exactly these bytes.
"""
import hashlib, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
D = ROOT / "crates" / "patronus-web" / "ui-map"
bad, pin, sums = [], {}, {}
for line in (D / "map.pin").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    k, _, v = line.partition("=")
    k, v = k.strip(), v.strip()
    if k.startswith("sha256 "):
        sums[k.split(None, 1)[1]] = v
    else:
        pin[k] = v
for need in ("version", "repo", "path", "commit"):
    if need not in pin:
        bad.append(f"map.pin: `{need}` missing")
for f in ("map.js", "map.css"):
    if f not in sums:
        bad.append(f"map.pin: no sha256 for {f}")
for f, want in sums.items():
    p = D / f
    if not p.exists():
        bad.append(f"{f}: pinned but not vendored")
        continue
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != want:
        bad.append(f"{f}: sha256 {got} != pinned {want} (edit ui-kit/map upstream, not the vendored copy)")
for f, cap in (("map.js", 24 * 1024), ("map.css", 6 * 1024)):
    if (D / f).exists() and len((D / f).read_bytes()) > cap:
        bad.append(f"{f}: {len((D / f).read_bytes())} B > {cap} B")
if "--upstream" in sys.argv:
    up = pathlib.Path(sys.argv[sys.argv.index("--upstream") + 1])
    if pin.get("commit") in (None, "", "pending"):
        bad.append("--upstream given but map.pin commit is pending")
    else:
        for f, want in sums.items():
            blob = subprocess.run(["git", "-C", str(up), "show", f"{pin['commit']}:{pin['path']}/{f}"],
                                  capture_output=True).stdout
            if hashlib.sha256(blob).hexdigest() != want:
                bad.append(f"{f}: horcrux {pin['commit'][:12]} does not hold the pinned bytes")
if bad:
    print("check-ui-map-pin: FAIL\n" + "\n".join(bad))
    sys.exit(1)
print(f"check-ui-map-pin: OK (ui-kit/map {pin['version']} @ {pin['commit']})")
