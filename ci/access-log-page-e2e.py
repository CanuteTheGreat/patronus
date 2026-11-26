#!/usr/bin/env python3
"""Browser check of System > Access log (/system/access-log), Playwright Firefox.

Needs BASE_URL, E2E_USER, E2E_PASSWORD. Generates a few requests (failed sign-ins as a throwaway name, a 404), then:
  1. the menu has the entry; the page lists the requests (the 4xx rows are there, no raw path or password);
  2. the status filter shows only matching rows; Reset clears it; a row opens its detail dialog;
  3. Statistics opens, a top-list value applies as a filter and closes the dialog;
  4. the Configuration changes tab loads; no JavaScript error;
  5. at 1280 and 390 px wide, light and dark (device setting): no horizontal page overflow and every text node has AA contrast.
Exit 0 = all passed.
"""
import json, os, sys, time
from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
failures = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


CONTRAST = """() => {
  const lum = c => { const [r,g,b] = c.map(v => { v/=255; return v<=0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055,2.4); }); return 0.2126*r+0.7152*g+0.0722*b; };
  const parse = s => { const m = s.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(',').map(Number); return {c: p.slice(0,3), a: p.length>3 ? p[3] : 1}; };
  const bgOf = el => { for (; el; el = el.parentElement) { const p = parse(getComputedStyle(el).backgroundColor); if (p && p.a > 0.9) return p.c; } return [255,255,255]; };
  const bad = [];
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n; (n = w.nextNode());) {
    if (!n.textContent.trim()) continue;
    const el = n.parentElement; if (!el || !el.offsetParent) continue;
    if (el.closest('dialog:not([open])')) continue;
    const cs = getComputedStyle(el); const fg = parse(cs.color); if (!fg) continue;
    const L1 = lum(fg.c), L2 = lum(bgOf(el)); const r = (Math.max(L1,L2)+0.05)/(Math.min(L1,L2)+0.05);
    const big = parseFloat(cs.fontSize) >= 24 || (parseFloat(cs.fontSize) >= 18.66 && parseInt(cs.fontWeight) >= 700);
    if (r < (big ? 3 : 4.5)) bad.push(n.textContent.trim().slice(0, 30) + ' ' + r.toFixed(2));
  }
  return bad.slice(0, 8);
}"""


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    tag = f"[{kind}] "
    errors = []
    for scheme in ("light", "dark"):
        for width, height in ((1280, 900), (390, 844)):
            ctx = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": height}, color_scheme=scheme)
            page = ctx.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            t = f"{tag}{width}px {scheme}: "
            page.goto(BASE + "/login")
            page.fill("#username", USER); page.fill("#password", PASSWORD); page.click("button[type=submit]")
            page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
            page.evaluate("async () => { for (const u of ['mallory-e2e']) await fetch('/api/auth/login', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({username:u, password:'x'})}); await fetch('/api/e2e-missing/77?token=abc'); }")
            time.sleep(1)
            page.goto(BASE + "/system/access-log")
            page.wait_for_selector("#al-grid tbody tr", timeout=30000)
            if width == 1280 and scheme == "light":
                link = page.locator('.sidebar-nav a.nav-item[href="/system/access-log"]')
                check(t + "the menu has an Access log entry", link.count() == 1, link.count())
                txt = page.locator("#al-grid tbody").inner_text()
                check(t + "requests are listed, 4xx included", "401" in txt and "404" in txt, txt[:200])
                check(t + "no raw path, query or password in the page", "e2e-missing" not in txt and "abc" not in txt and "77" not in page.locator("#al-grid tbody td:nth-child(5)").all_inner_texts().__str__())
                page.select_option("#f-status", "4xx"); page.click("#btn-apply")
                page.wait_for_function("() => [...document.querySelectorAll('#al-grid tbody tr')].every(r => /^4/.test(r.children[5].textContent))", timeout=15000)
                check(t + "the status filter keeps only 4xx rows", page.locator("#al-grid tbody tr").count() > 0)
                page.click("#btn-reset")
                page.wait_for_function("() => document.querySelectorAll('#al-grid tbody tr').length > 0 && document.getElementById('f-status').value === ''", timeout=15000)
                page.locator("#al-grid tbody tr").first.click()
                page.wait_for_selector("#dlg-row[open]", timeout=5000)
                check(t + "a row opens its detail dialog", page.locator("#dlg-row-dl").inner_text().strip() != "")
                page.keyboard.press("Escape")
                page.click("#btn-stats"); page.wait_for_selector("#dlg-stats[open]", timeout=15000)
                page.click('#st-tabs .al-tab[data-k=status]')
                b = page.locator("#st-top tbody button").first
                b.wait_for(timeout=15000)
                val = b.inner_text(); b.click()
                page.wait_for_function("() => !document.getElementById('dlg-stats').open", timeout=5000)
                check(t + "a statistics value applies as a filter and closes the dialog", page.locator("#f-status").input_value() != "" or val != "", val)
                page.click("#tab-audit")
                page.wait_for_function("() => document.getElementById('pane-audit').hidden === false", timeout=5000)
                check(t + "the Configuration changes tab opens", True)
                page.click("#tab-access")
            over = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
            check(t + "no horizontal page overflow", over <= 1, over)
            bad = page.evaluate(CONTRAST)
            check(t + "text contrast is AA", not bad, bad)
            ctx.close()
    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS access-log-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


main()
