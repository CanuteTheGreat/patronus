#!/usr/bin/env python3
"""Accessibility gate: runs the vendored axe-core on the most used pages of the Patronus web UI in a real browser.

Pages, widths, colour schemes, tags and the impact threshold come from a11y-config.json; justified false positives
from axe-allowlist.json. axe-core is vendored (vendor/axe.min.js, checksum pinned in the config): nothing is fetched
at test time. A violation whose impact is in `fail_impacts` (default serious + critical) fails the run unless an
allowlist entry covers it; the other impacts are printed as warnings.

Usage: BASE_URL=https://localhost:8443 E2E_USER=admin E2E_PASSWORD=... axe_gate.py [--config a11y-config.json]
         [--browsers firefox,chromium] [--pages id,id] [--report out.json]
Exit 0 = no un-allowlisted violation at or above the threshold.  Needs the `playwright` package and its browsers.
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))


def log(msg):
    print(msg, flush=True)


def run_axe(page, tags):
    return page.evaluate(
        """async (tags) => (await axe.run(document, {runOnly: {type: 'tag', values: tags}, resultTypes: ['violations']})).violations
             .map(v => ({id: v.id, impact: v.impact, help: v.help, url: v.helpUrl,
                         nodes: v.nodes.map(n => ({target: n.target.join(' '), html: n.html.slice(0, 160), summary: (n.failureSummary || '').split('\\n').slice(1).join(' ').slice(0, 220)}))}))""",
        tags,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(HERE, "a11y-config.json"))
    ap.add_argument("--browsers")
    ap.add_argument("--pages")
    ap.add_argument("--report")
    a = ap.parse_args()
    cfgdir = os.path.dirname(os.path.abspath(a.config))
    cfg = json.load(open(a.config))
    base = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
    user, password = os.environ["E2E_USER"], os.environ["E2E_PASSWORD"]

    axe_path = os.path.join(cfgdir, cfg["axe_file"])
    axe_src = open(axe_path, encoding="utf-8").read()
    digest = hashlib.sha256(axe_src.encode("utf-8")).hexdigest()
    if digest != cfg["axe_sha256"]:
        log(f"FAIL: vendored axe-core checksum {digest} does not match the pinned {cfg['axe_sha256']}")
        return 1
    allow = json.load(open(os.path.join(cfgdir, cfg["allowlist"])))["entries"]
    for e in allow:
        if not all(e.get(k) for k in ("rule", "page", "reason")):
            log(f"FAIL: allowlist entry needs rule, page and a reason: {e}")
            return 1
    used = set()
    want = set(a.pages.split(",")) if a.pages else None
    pages = [p for p in cfg["pages"] if not want or p["id"] in want]
    browsers = (a.browsers or ",".join(cfg["browsers"])).split(",")
    fail_imp, rep_imp = set(cfg["fail_impacts"]), set(cfg["report_impacts"])
    lg = cfg["login"]

    failures, warnings, results = [], [], []
    with sync_playwright() as p:
        for kind in browsers:
            browser = getattr(p, kind).launch(headless=True)
            for scheme in cfg["schemes"]:
                for vp, (w, h) in cfg["viewports"].items():
                    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": w, "height": h}, color_scheme=scheme)
                    ctx.add_init_script(axe_src)
                    page = ctx.new_page()
                    errors = []
                    page.on("pageerror", lambda e: errors.append(str(e)[:200]))
                    logged_in = False
                    for pg in pages:
                        if pg.get("auth", True) and not logged_in:
                            page.goto(base + lg["path"], wait_until="load")
                            page.fill(lg["user_sel"], user)
                            page.fill(lg["pass_sel"], password)
                            page.click(lg["submit_sel"])
                            page.wait_for_url(lambda u: "/login" not in u, timeout=30000)
                            logged_in = True
                        if not pg.get("auth", True) and logged_in:
                            ctx.clear_cookies()
                            logged_in = False
                        page.goto(base + pg["path"], wait_until="load")
                        label = f"{kind}/{vp}/{scheme}/{pg['id']}"
                        if pg.get("wait_for"):
                            try:
                                page.wait_for_selector(pg["wait_for"], state="attached", timeout=30000)
                            except Exception:  # noqa: BLE001
                                failures.append({"where": label, "rule": "page-not-rendered", "impact": "critical",
                                                 "detail": f"{pg['wait_for']} never appeared at {page.url} (title {page.title()!r})"})
                                log(f"FAIL {label}: page did not render ({page.url})")
                                continue
                        for sel in pg.get("click", []):
                            page.click(sel)
                        for sel, val in pg.get("select", {}).items():
                            page.select_option(sel, val)
                        page.wait_for_timeout(lg.get("settle_ms", 700))
                        if "/login" in page.url and pg.get("auth", True):
                            failures.append({"where": label, "rule": "page-not-reached", "impact": "critical", "detail": f"redirected to {page.url}"})
                            continue
                        viol = run_axe(page, cfg["axe_tags"])
                        cnt = Counter()
                        for v in viol:
                            for n in v["nodes"]:
                                hit = next((e for e in allow if e["rule"] == v["id"] and e["page"] in (pg["id"], "*") and e.get("target", "") in n["target"]), None)
                                rec = {"where": label, "rule": v["id"], "impact": v["impact"], "target": n["target"], "html": n["html"], "detail": n["summary"]}
                                if hit:
                                    used.add(id(hit))
                                    continue
                                if v["impact"] in fail_imp:
                                    failures.append(rec)
                                    cnt[v["id"]] += 1
                                elif v["impact"] in rep_imp:
                                    warnings.append(rec)
                        results.append({"where": label, "failing": dict(cnt)})
                        log(f"{'FAIL' if cnt else 'ok  '} {label}: {sum(cnt.values())} serious/critical node(s) {dict(cnt) if cnt else ''}")
                    if errors:
                        log(f"note: {kind}/{vp}/{scheme}: {len(errors)} page error(s): {errors[:2]}")
                    ctx.close()
            browser.close()

    stale = [e for e in allow if id(e) not in used and (not want or e["page"] in want or e["page"] == "*")]
    byrule = Counter((f["rule"], f["impact"]) for f in failures)
    # one line per rule and page (first node as the example), the full list is in --report
    first = {}
    for f in failures:
        first.setdefault((f["rule"], f["where"].split("/")[-1]), [f, 0])[1] += 1
    for (rule, pid), (f, n) in sorted(first.items()):
        log(f"  {f['impact']:8} {rule:24} {pid:15} x{n} e.g. {f.get('target', '')[:70]}  {f.get('detail', '')[:100]}")
    wr = Counter((f["rule"], f["impact"]) for f in warnings)
    if wr:
        log("warnings (below the threshold): " + ", ".join(f"{r}[{i}] x{c}" for (r, i), c in sorted(wr.items())))
    for e in stale:
        log(f"FAIL: allowlist entry matches nothing (remove it): {e['rule']} on {e['page']}")
    if a.report:
        json.dump({"failures": failures, "warnings": warnings, "results": results, "stale_allowlist": stale}, open(a.report, "w"), indent=1)
    log(f"axe gate: {len(results)} page runs, {len(failures)} failing node(s) {dict((f'{r}[{i}]', c) for (r, i), c in byrule.items())}, {len(warnings)} warning node(s), {len(stale)} stale allowlist entr(ies)")
    return 1 if failures or stale else 0


if __name__ == "__main__":
    sys.exit(main())
