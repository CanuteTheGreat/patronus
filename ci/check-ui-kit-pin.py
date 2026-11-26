#!/usr/bin/env python3
"""The shared ui-kit is vendored, pinned and checksum-checked (crates/patronus-web/ui-kit/ui-kit.pin).

* every `sha256 <file> = <hex>` line matches the vendored file (a local edit of the kit fails here: change the kit
  upstream in the Horcrux repo and re-vendor, Patronus branding goes in crates/patronus-web/theme/patronus.css);
* the kit's own gate (ui-kit/check.py: size budget, ui- prefix, token contrast) passes on the vendored copy;
* the router-tier budget: tokens + components + theme <= 32 KB and ui.js <= 15 KB as served (unminified);
* `--upstream DIR` (a horcrux checkout) also checks that `commit` holds exactly these bytes.
"""
import hashlib, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
KIT = ROOT / "crates" / "patronus-web" / "ui-kit"
THEME = ROOT / "crates" / "patronus-web" / "theme" / "patronus.css"
bad = []
pin = {}
sums = {}
for line in (KIT / "ui-kit.pin").read_text().splitlines():
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
        bad.append(f"ui-kit.pin: `{need}` missing")
for f in ("tokens.css", "components.css", "ui.js"):
    if f not in sums:
        bad.append(f"ui-kit.pin: no sha256 for {f}")
for f, want in sums.items():
    p = KIT / f
    if not p.exists():
        bad.append(f"{f}: pinned but not vendored")
        continue
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    if got != want:
        bad.append(f"{f}: sha256 {got} != pinned {want} (edit the kit upstream, not the vendored copy)")
r = subprocess.run([sys.executable, str(KIT / "check.py")], capture_output=True, text=True)
if r.returncode != 0:
    bad.append("ui-kit/check.py failed:\n" + r.stdout + r.stderr)
css = sum(len((KIT / f).read_bytes()) for f in ("tokens.css", "components.css")) + len(THEME.read_bytes())
if css > 32 * 1024:
    bad.append(f"router-tier budget: kit css + theme = {css} B > 32 KB")
js = len((KIT / "ui.js").read_bytes())
if js > 15 * 1024:
    bad.append(f"router-tier budget: ui.js = {js} B > 15 KB")
if "--upstream" in sys.argv:
    up = pathlib.Path(sys.argv[sys.argv.index("--upstream") + 1])
    if pin.get("commit") in (None, "", "pending"):
        bad.append("--upstream given but ui-kit.pin commit is pending")
    else:
        for f, want in sums.items():
            blob = subprocess.run(["git", "-C", str(up), "show", f"{pin['commit']}:{pin['path']}/{f}"],
                                  capture_output=True).stdout
            if hashlib.sha256(blob).hexdigest() != want:
                bad.append(f"{f}: horcrux {pin['commit'][:12]} does not hold the pinned bytes")
if bad:
    print("check-ui-kit-pin: FAIL\n" + "\n".join(bad))
    sys.exit(1)
print(f"check-ui-kit-pin: OK (ui-kit {pin['version']} @ {pin['commit']}, css {css} B, js {js} B)")
