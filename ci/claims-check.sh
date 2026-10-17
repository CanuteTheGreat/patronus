#!/usr/bin/env bash
# README claims ledger check (see docs/claims-ledger.txt). Runs on every push.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'EOF'
import os, re, subprocess, sys

ledger = {}
for n, line in enumerate(open("docs/claims-ledger.txt"), 1):
    if not line.strip() or line.startswith("#"):
        continue
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 3 or not re.fullmatch(r"C\d+", parts[0]):
        sys.exit(f"docs/claims-ledger.txt:{n}: want 'Cn | claim | proofs'")
    ledger[parts[0]] = (parts[1], [p.strip() for p in parts[2].split(" ; ") if p.strip()])

readme = open("README.md").read()
errors = []

marked = set(re.findall(r"\[(C\d+)\]", readme))
for c in sorted(marked - ledger.keys()):
    errors.append(f"README.md claims [{c}] but docs/claims-ledger.txt has no proof for it")
for c in sorted(ledger.keys() - marked):
    errors.append(f"docs/claims-ledger.txt {c} is not referenced in README.md (delete it or mark the claim)")

# Boasts that must not come back without a ledger row.
for pat, why in [
    (r"✅", "check marks: state the claim with a [Cn] marker instead"),
    (r"(?i)feature parity|100\s*%", "parity / 100% boasts"),
    (r"(?i)production ready", "'production ready'"),
    (r"(?i)\bGbps\b", "throughput numbers (no benchmark in CI)"),
    (r"(?i)security(?: grade)?:? \*{0,2}A\+", "security grades"),
]:
    for m in re.finditer(pat, readme):
        ln = readme.count("\n", 0, m.start()) + 1
        errors.append(f"README.md:{ln}: {why}: {m.group(0)!r}")

workflows = "".join(open(os.path.join(".forgejo/workflows", f)).read()
                    for f in os.listdir(".forgejo/workflows") if f.endswith((".yml", ".yaml")))
netlab_run = open("ci/netlab/run.sh").read()
default_globs = re.findall(r"ci/netlab/(\w+)-\*\.sh", netlab_run)

def fn_exists(crate, name):
    r = subprocess.run(["grep", "-rqE", rf"fn {re.escape(name)}\b", f"crates/{crate}"])
    return r.returncode == 0

for cid, (claim, proofs) in sorted(ledger.items(), key=lambda kv: int(kv[0][1:])):
    if not proofs:
        errors.append(f"{cid}: no proof")
    for p in proofs:
        kind, _, rest = p.partition(":")
        if kind == "test":
            crate, _, name = rest.partition(":")
            if not os.path.isdir(f"crates/{crate}") or not fn_exists(crate, name):
                errors.append(f"{cid}: test fn {name} not found in crates/{crate}")
        elif kind == "netlab":
            script, _, text = rest.partition(":")
            path = f"ci/netlab/{script}"
            if not os.path.isfile(path):
                errors.append(f"{cid}: {path} missing"); continue
            if text not in open(path).read():
                errors.append(f"{cid}: {path} has no check {text!r}")
            if script.split("-")[0] not in default_globs:
                errors.append(f"{cid}: {path} is not run by ci/netlab/run.sh by default")
        elif kind == "ci":
            if not os.path.exists(rest):
                errors.append(f"{cid}: {rest} missing")
            elif not rest.startswith(".forgejo/") and rest not in workflows:
                errors.append(f"{cid}: {rest} is not run by any workflow")
        else:
            errors.append(f"{cid}: unknown proof kind {p!r}")

if errors:
    print("claims ledger check FAILED:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print(f"claims ledger: {len(ledger)} README claims, each mapped to CI-executed proof")
for cid, (claim, proofs) in sorted(ledger.items(), key=lambda kv: int(kv[0][1:])):
    print(f"  {cid}: {len(proofs)} proof(s)")
EOF
