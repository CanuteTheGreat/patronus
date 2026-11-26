#!/usr/bin/env python3
"""Package manifest + advisory gate of a router image (docs/CVE-EXPOSURE.md "Router tier").

make-package-manifest.py --apk-list FILE --image NAME --version V --distribution alpine --release 3.24 --out FILE
                         [--secdb FILE ...] [--accepts FILE] [--enforce]

* FILE of --apk-list holds `apk info -v` lines (`busybox-1.37.0-r30`), one package per line.
* The advisories are the DISTRIBUTION's own security database (Alpine secdb: `main.json`, `community.json`), never
  Gentoo GLSAs: the AX1800 userland is Alpine packages. With no --secdb the files are downloaded for --release;
  when that fails the manifest is written WITHOUT a gate result (the device then says "cannot tell", never "clean").
* A package is affected by an advisory when its version is older than the fixed version the database names
  (`secfixes` key); the key `0` marks advisories that do not apply and is ignored.
* --accepts: lines `ADVISORY reason`; an accepted advisory is recorded under gate.accepted, not as a finding.
* --enforce: exit 1 when a finding is not accepted (the image build fails).

Writes the manifest JSON read by the router's CVE exposure view (patronus_network::cve::inventory::Manifest).
"""
import argparse
import datetime
import json
import re
import sys
import urllib.request

VER = re.compile(r"^(\d+(?:\.\d+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$")
SUFFIX_RANK = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "cvs": 5, "svn": 5, "git": 5, "hg": 5, "p": 5}
NONE_RANK = 4


def version_key(v):
    """Sortable key of an Alpine package version (apk's rules: numbers, a letter, _suffixes, -rN)."""
    m = VER.match(v)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    suffixes = []
    for s in re.findall(r"_([a-z]+)(\d*)", m.group(3) or ""):
        suffixes.append((SUFFIX_RANK[s[0]], int(s[1] or 0)))
    return (nums, m.group(2) or "", suffixes, int(m.group(4) or 0))


def cmp_version(a, b):
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        return None
    na, nb = ka[0], kb[0]
    for i in range(max(len(na), len(nb))):
        x = na[i] if i < len(na) else -1
        y = nb[i] if i < len(nb) else -1
        if x != y:
            return -1 if x < y else 1
    if ka[1] != kb[1]:
        return -1 if ka[1] < kb[1] else 1
    sa, sb = ka[2], kb[2]
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else (NONE_RANK, 0)
        y = sb[i] if i < len(sb) else (NONE_RANK, 0)
        if x != y:
            return -1 if x < y else 1
    if ka[3] != kb[3]:
        return -1 if ka[3] < kb[3] else 1
    return 0


def split_apk(line):
    m = re.match(r"^(.*?)-(\d[^-]*(?:-r\d+)?)$", line.strip())
    return (m.group(1), m.group(2)) if m else None


def load_secdb(paths):
    db = {}
    for p in paths:
        d = json.load(open(p))
        for e in d.get("packages", []):
            pkg = e["pkg"]
            db.setdefault(pkg["name"], {}).update(pkg.get("secfixes", {}))
    return db


def fetch_secdb(release, dest_dir):
    paths = []
    for repo in ("main", "community"):
        url = f"https://secdb.alpinelinux.org/v{release}/{repo}.json"
        path = f"{dest_dir}/secdb-{repo}.json"
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "patronus-image-gate/1"}), timeout=60) as r:
            data = r.read(64 << 20)
        json.loads(data)
        open(path, "wb").write(data)
        paths.append(path)
    return paths


def findings(packages, secdb):
    out = []
    for name, ver in packages:
        for fixed, ids in secdb.get(name, {}).items():
            if fixed == "0":
                continue
            c = cmp_version(ver, fixed)
            if c is None or c >= 0:
                continue
            for adv in ids:
                out.append({
                    "package": name,
                    "installed": ver,
                    "advisory": adv,
                    "title": f"{name} {ver} is older than {fixed}, which fixes {adv}",
                    "fixed_in": [fixed],
                    "url": f"https://security.alpinelinux.org/vuln/{adv}",
                })
    out.sort(key=lambda f: (f["package"], f["advisory"]))
    return out


def read_accepts(path):
    acc = {}
    if not path:
        return acc
    try:
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#"):
                k, _, why = line.partition(" ")
                acc[k] = why.strip() or "accepted"
    except FileNotFoundError:
        pass
    return acc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk-list", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--distribution", default="alpine")
    ap.add_argument("--release", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--secdb", action="append", default=[])
    ap.add_argument("--accepts", default="")
    ap.add_argument("--enforce", action="store_true")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args()

    pkgs = []
    for line in open(a.apk_list):
        if line.strip():
            p = split_apk(line)
            if p is None:
                print(f"::warning::cannot split package line {line.strip()!r}", file=sys.stderr)
                continue
            pkgs.append(p)
    pkgs.sort()
    manifest = {
        "schema": 1,
        "image": a.image,
        "built": a.date,
        "version": a.version,
        "distribution": a.distribution,
        "packages": [{"name": n, "version": v} for n, v in pkgs],
    }
    secdb_paths, source = a.secdb, "given files"
    if not secdb_paths and a.release:
        import tempfile
        d = tempfile.mkdtemp(prefix="secdb-")
        try:
            secdb_paths = fetch_secdb(a.release, d)
            source = f"Alpine secdb v{a.release} main+community"
        except Exception as e:  # noqa: BLE001
            print(f"::warning::advisory gate: security database unavailable ({e}); the image carries no gate result", file=sys.stderr)
            secdb_paths = []
    bad = []
    if secdb_paths:
        accepts = read_accepts(a.accepts)
        found = findings(pkgs, load_secdb(secdb_paths))
        bad = [f for f in found if f["advisory"] not in accepts]
        manifest["gate"] = {
            "checked_at": a.date,
            "source": source,
            "findings": bad,
            "accepted": [[f["advisory"], accepts[f["advisory"]]] for f in found if f["advisory"] in accepts],
        }
        print(f"advisory gate: {len(pkgs)} packages, {len(found)} advisories ({len(bad)} not accepted) against {source}")
        for f in bad:
            print(f"::error::[image-advisory] {f['package']} {f['installed']}: {f['advisory']} fixed in {f['fixed_in'][0]} ({f['url']})")
    json.dump(manifest, open(a.out, "w"), indent=1)
    sys.exit(1 if (bad and a.enforce) else 0)


if __name__ == "__main__":
    main()
