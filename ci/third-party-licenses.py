#!/usr/bin/env python3
"""Generate THIRD-PARTY-LICENSES.txt: the licenses of every Rust crate compiled into the shipped binaries.

  ci/third-party-licenses.py                      # write THIRD-PARTY-LICENSES.txt
  ci/third-party-licenses.py --out X --gzip       # also write X.gz (what the web UI serves; deterministic bytes)
  ci/third-party-licenses.py --check-text         # exit 1 if a crate ships no license text at all

Which crates: the normal (non-dev, non-build) dependency closure of the shipped binaries (SHIPPED_PACKAGES)
with default features, for the platforms in PLATFORMS, resolved from Cargo.lock through `cargo metadata`.
The workspace has no committed Cargo.lock (it is gitignored), so the file is only reproducible for one
lockfile: release.yml generates the lockfile once, builds, and runs this script against the same lock.
Crate sources must be in the cargo registry (cargo metadata fetches them); license texts are the LICENSE /
COPYING / NOTICE files each crate ships. Equal texts are printed once, followed by the crates they cover.
The output is sorted and contains no dates, so the same lockfile always produces the same bytes.

The allowed licenses themselves are policy in .cargo/deny.toml and enforced by `cargo deny check licenses`.
"""
import argparse, gzip, hashlib, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Defaults for everything an operator may want to change; override with the environment (nothing is hard-coded).
SHIPPED_PACKAGES = os.environ.get("PATRONUS_LICENSE_ROOTS", "patronus-web,patronus-cli").split(",")
PLATFORMS = os.environ.get(
    "PATRONUS_LICENSE_PLATFORMS", "x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu"
).split(",")
TEXT_FILE = re.compile(r"^(licen[sc]e|copying|unlicense|notice|copyright)([-_.].*)?$", re.I)


def metadata(platform):
    out = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--filter-platform", platform],
        cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
    )
    return json.loads(out)


def closure(meta):
    """ids reachable from the shipped binaries through normal dependencies"""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    by_name = {p["name"]: p["id"] for p in meta["packages"] if p["source"] is None}
    todo = [by_name[n] for n in SHIPPED_PACKAGES if n in by_name]
    if len(todo) != len(SHIPPED_PACKAGES):
        sys.exit(f"shipped package missing from the workspace: {SHIPPED_PACKAGES}")
    seen = set()
    while todo:
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] is None for k in d["dep_kinds"]):
                todo.append(d["pkg"])
    return seen


def license_files(pkg):
    d = os.path.dirname(pkg["manifest_path"])
    found = []
    for dirpath, dirnames, files in os.walk(d):
        depth = dirpath[len(d):].count(os.sep)
        if depth >= 2:
            dirnames[:] = []
        # a vendored dependency's own tree is not this crate's license
        dirnames[:] = sorted(x for x in dirnames if x not in ("target", ".git", "node_modules", "vendor", "tests", "benches"))
        for f in sorted(files):
            if TEXT_FILE.match(f):
                found.append(os.path.join(dirpath, f))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "THIRD-PARTY-LICENSES.txt"))
    ap.add_argument("--gzip", action="store_true", help="also write <out>.gz")
    ap.add_argument("--check-text", action="store_true", help="fail if a crate has no license text")
    a = ap.parse_args()

    pkgs = {}
    for plat in PLATFORMS:
        meta = metadata(plat)
        ids = closure(meta)
        for p in meta["packages"]:
            if p["id"] in ids:
                pkgs[p["id"]] = p
    rows, texts, missing = [], {}, []
    for p in pkgs.values():
        if p["source"] is None:  # a Patronus crate: GPL-3.0-or-later, the repository LICENSE covers it
            continue
        lic = p.get("license") or p.get("license_file") or "UNKNOWN"
        repo = p.get("repository") or p.get("homepage") or ""
        rows.append((p["name"], p["version"], lic, repo))
        files = license_files(p)
        if not files:
            missing.append(f"{p['name']} {p['version']} ({lic})")
        for f in files:
            body = open(f, "rb").read().decode("utf-8", "replace").replace("\r\n", "\n").strip()
            if not body:
                continue
            h = hashlib.sha256(body.encode()).hexdigest()
            texts.setdefault(h, {"body": body, "crates": set()})["crates"].add(f"{p['name']} {p['version']}")
    rows.sort()

    me = open(os.path.join(ROOT, "Cargo.toml")).read()
    m = re.search(r"\[workspace\.package\][^\[]*?\nversion\s*=\s*\"([^\"]+)\"", me)
    if not m:
        sys.exit("no [workspace.package] version in Cargo.toml")
    ver = m.group(1)
    L = [
        f"Patronus {ver}: third-party software licenses",
        "",
        "Patronus itself is free software under the GNU General Public License, version 3 or (at your",
        "option) any later version (see LICENSE). The binaries (" + ", ".join(SHIPPED_PACKAGES) + ") also contain the Rust",
        "crates below, each under its own license. The operating system packages on the image (Gentoo",
        "Linux, the kernel, nftables, Unbound ...) are separate works with their own licenses, listed in",
        "/var/db/pkg/*/*/LICENSE on an installed system.",
        "",
        f"{len(rows)} crates, resolved for: {', '.join(PLATFORMS)}.",
        "",
        "=" * 78,
        "CRATES",
        "=" * 78,
        "",
    ]
    for n, v, lic, repo in rows:
        L.append(f"{n} {v}: {lic}" + (f" <{repo}>" if repo else ""))
    L += ["", "=" * 78, "LICENSE TEXTS", "=" * 78, ""]
    for h, t in sorted(texts.items(), key=lambda kv: (sorted(kv[1]["crates"])[0], kv[0])):
        cs = sorted(t["crates"])
        L.append("-" * 78)
        L.append(f"Used by ({len(cs)}): " + ", ".join(cs))
        L.append("-" * 78)
        L.append(t["body"])
        L.append("")
    if missing:
        L += ["-" * 78, "Crates that ship no license file (license given by the crate's manifest only):", "-" * 78]
        L += sorted(missing)
        L.append("")
    data = ("\n".join(L)).encode()
    with open(a.out, "wb") as f:
        f.write(data)
    print(f"wrote {a.out}: {len(rows)} crates, {len(texts)} distinct license texts, {len(missing)} without a file, {len(data)} bytes")
    if a.gzip:
        with open(a.out + ".gz", "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            gz.write(data)
        print(f"wrote {a.out}.gz: {os.path.getsize(a.out + '.gz')} bytes")
    if a.check_text and missing:
        print("no license text for: " + "; ".join(missing), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
