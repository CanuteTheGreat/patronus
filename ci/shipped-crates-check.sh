#!/usr/bin/env bash
# docs/WORKSPACE-CRATES.md must list exactly which workspace crates the
# shipped binaries (patronus-cli, patronus-web, patronus-dashboard) pull in
# through path dependencies, and which ones are library-only. A new crate that
# is not linked into anything has to be added to the "Not shipped" list, so
# nobody mistakes it for a product feature (QA once planned scenarios against
# crates no binary contained).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'EOF'
import glob, re, sys, tomllib

crates = {}
for f in glob.glob("crates/*/Cargo.toml") + ["operator/Cargo.toml"]:
    t = tomllib.load(open(f, "rb"))
    deps = set()
    for sec in ("dependencies", "build-dependencies"):
        for k, v in t.get(sec, {}).items():
            if isinstance(v, dict) and "path" in v:
                deps.add(v.get("package", k))
    crates[t["package"]["name"]] = deps

seen, todo = set(), ["patronus-cli", "patronus-web", "patronus-dashboard"]
while todo:
    c = todo.pop()
    if c in seen or c not in crates:
        continue
    seen.add(c)
    todo += crates[c]

doc = open("docs/WORKSPACE-CRATES.md").read()
def section(name):
    m = re.search(rf"## {name}\n(.*?)(?=\n## |\Z)", doc, re.S)
    if not m:
        sys.exit(f"docs/WORKSPACE-CRATES.md has no '## {name}' section")
    return set(re.findall(r"^- `([a-z0-9-]+)`", m.group(1), re.M))

listed_ship, listed_not = section("Linked into the shipped binaries"), section("Not shipped")
errors = []
for c in sorted(seen - listed_ship):
    errors.append(f"{c} is linked into a shipped binary but not listed under 'Linked into the shipped binaries'")
for c in sorted(set(crates) - seen - listed_not):
    errors.append(f"{c} is not linked into any shipped binary: list it under 'Not shipped'")
for c in sorted(listed_ship - seen):
    errors.append(f"{c} is listed as shipped but no shipped binary depends on it")
for c in sorted(listed_not & seen):
    errors.append(f"{c} is listed as not shipped but a shipped binary depends on it")
for c in sorted((listed_ship | listed_not) - set(crates)):
    errors.append(f"{c} is listed but is not a workspace crate")
if errors:
    sys.exit("shipped-crates check failed:\n  " + "\n  ".join(errors))
print(f"shipped-crates check: {len(seen)} linked, {len(set(crates) - seen)} library-only, doc matches")
EOF
