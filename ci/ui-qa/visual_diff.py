#!/usr/bin/env python3
"""Visual regression of the UI screenshots against the pinned baseline set.

  visual_diff.py --new OUT --baseline DIR [--report diff.json] [--pack ui-shots.tar.gz]

OUT holds shots-<variant>/<scheme>-<width>/<page>.png from ci/ux-qa/ux_crawl.py --shots. Each image is reduced to a
comparison form (width 320, greyscale: removes font anti-aliasing noise and keeps the files small) and compared with
the same path in the baseline DIR (the unpacked tarball pinned in ci/ui-qa/shots.pin):

  changed %  share of pixels whose grey value moved by more than 24 of 255
  fail       changed > FAIL_PCT (layout breakage: a stylesheet that did not load, a page that lost its grid) or the
             page height changed by more than 35 %; live values (counters, clocks, rates) stay far below that
  warn       changed > WARN_PCT, listed in the report for a human look
  new/gone   page in only one of the two sets (listed, never a fail: pages come and go with features)

--pack writes the reduced set of THIS run as a tarball: that is what a new baseline is made of (publish it as a
Forgejo generic package and put its URL + sha256 in ci/ui-qa/shots.pin).
An empty or missing baseline DIR = nothing to compare (exit 0, noted in the report).
"""
import argparse
import io
import json
import os
import sys
import tarfile

from PIL import Image, ImageChops

W = 320
FAIL_PCT = float(os.environ.get("UI_DIFF_FAIL_PCT", "25"))
WARN_PCT = float(os.environ.get("UI_DIFF_WARN_PCT", "4"))
HEIGHT_FAIL = 0.35


def reduce(path):
    im = Image.open(path).convert("L")
    h = max(1, round(im.height * W / im.width))
    return im.resize((W, h), Image.Resampling.BILINEAR)


def shots(root):
    out = {}
    for d, _sub, files in os.walk(root):
        for f in files:
            if f.endswith(".png"):
                rel = os.path.relpath(os.path.join(d, f), root)
                if rel.startswith("shots-") or "/" in rel:
                    out[rel] = os.path.join(d, f)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new", required=True)
    ap.add_argument("--baseline")
    ap.add_argument("--report")
    ap.add_argument("--pack")
    a = ap.parse_args()
    new = {k: v for k, v in shots(a.new).items() if k.startswith("shots-")}
    base = shots(a.baseline) if a.baseline and os.path.isdir(a.baseline) else {}
    reduced = {k: reduce(v) for k, v in sorted(new.items())}
    rows, fails, warns = [], [], []
    for k, im in reduced.items():
        if k not in base:
            rows.append({"page": k, "status": "new"})
            continue
        b = Image.open(base[k]).convert("L")
        hdelta = abs(im.height - b.height) / max(b.height, 1)
        h = min(im.height, b.height)
        diff = ImageChops.difference(im.crop((0, 0, W, h)), b.crop((0, 0, W, h)))
        moved = sum(1 for v in diff.getdata() if v > 24)
        pct = 100.0 * (moved + W * abs(im.height - b.height)) / (W * max(im.height, b.height))
        st = "fail" if pct > FAIL_PCT or hdelta > HEIGHT_FAIL else ("warn" if pct > WARN_PCT else "same")
        rows.append({"page": k, "status": st, "changed_pct": round(pct, 2), "height_delta_pct": round(100 * hdelta, 1)})
        (fails if st == "fail" else warns if st == "warn" else []).append(f"{k}: {pct:.1f}% changed, height {100 * hdelta:+.0f}%")
    gone = sorted(set(base) - set(reduced))
    rows += [{"page": k, "status": "gone"} for k in gone]
    rep = {"baseline": bool(base), "pages": len(reduced), "fail": len(fails), "warn": len(warns), "new": sum(r["status"] == "new" for r in rows),
           "gone": len(gone), "fail_pct": FAIL_PCT, "warn_pct": WARN_PCT, "rows": rows}
    if a.report:
        json.dump(rep, open(a.report, "w"), indent=1)
    if a.pack:
        with tarfile.open(a.pack, "w:gz") as t:
            for k, im in reduced.items():
                buf = io.BytesIO()
                im.save(buf, "PNG", optimize=True)
                ti = tarfile.TarInfo(k)
                ti.size = buf.tell()
                ti.mtime = 0
                buf.seek(0)
                t.addfile(ti, buf)
    for f in fails:
        print("FAIL", f)
    for w in warns:
        print("WARN", w)
    if not base:
        print(f"visual_diff: no baseline, {len(reduced)} pages packed")
    else:
        print(f"visual_diff: {len(reduced)} pages, {len(fails)} fail, {len(warns)} warn, {rep['new']} new, {len(gone)} gone")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
