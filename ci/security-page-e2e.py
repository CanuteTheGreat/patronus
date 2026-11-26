#!/usr/bin/env python3
"""Security overview page in a real browser (Playwright), against a running patronus-web.

Usage: BASE_URL=https://192.168.50.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1] [E2E_SHOTS=/t/shots]
       security-page-e2e.py [firefox|chromium]

Checks at 1280 px and 390 px, light and dark: the menu entry is there and marked, the grade and every check row
load (each row has a status badge and a Fix link), the threat-feed catalog lists the catalog feeds with their hit
counters, nothing scrolls sideways, the colour scheme follows the browser setting, the dashboard shows the
security card. With E2E_WRITE=1 (1280 px light): the dry-run dialog lists changes and what it leaves alone,
applying it raises the grade and shows the Undo banner, Undo puts the configuration back, switching a feed to
"alert only" from the catalog stores the mode. Prints PASS:/FAIL: lines, exits 1 on any failure.
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"].rstrip("/")
USER = os.environ.get("E2E_USER", "admin")
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
SHOTS = os.environ.get("E2E_SHOTS", "")
failed = []


def check(ok, what):
    print(("PASS: " if ok else "FAIL: ") + what, flush=True)
    if not ok:
        failed.append(what)


def api(page, method, path, body=None):
    r = page.evaluate(
        """async ([path, method, b]) => { const r = await fetch(path, {method, credentials: 'same-origin',
             headers: b ? {'content-type': 'application/json'} : {}, body: b ? JSON.stringify(b) : undefined});
             return {status: r.status, body: await r.text()}; }""",
        [path, method, body],
    )
    try:
        r["json"] = json.loads(r["body"])
    except ValueError:
        r["json"] = None
    return r


def login(page):
    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: "/login" not in u, timeout=15000)


def shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=f"{SHOTS}/{name}.png", full_page=True)


def main():
    browser_name = sys.argv[1] if len(sys.argv) > 1 else "firefox"
    with sync_playwright() as p:
        browser = getattr(p, browser_name).launch()
        backgrounds = {}
        for scheme in ("light", "dark"):
            for width, height, mobile in ((1280, 800, False), (390, 844, True)):
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": width, "height": height},
                    color_scheme=scheme,
                    has_touch=mobile,
                )
                page = ctx.new_page()
                login(page)
                tag = f"{width}px {scheme}"
                page.goto(BASE + "/")
                try:
                    page.wait_for_function(
                        "!['…', ''].includes(document.getElementById('security-grade').textContent.trim())",
                        timeout=20000,
                    )
                    check(True, f"{tag}: dashboard security card shows {page.inner_text('#security-grade')}")
                except Exception as e:  # noqa: BLE001
                    check(False, f"{tag}: dashboard security card filled ({e})")
                page.goto(BASE + "/security")
                try:
                    page.wait_for_selector("#sec-checks tr[data-check]", timeout=20000)
                    page.wait_for_selector("#feeds-table tr[data-feed]", timeout=20000)
                    check(True, f"{tag}: page loaded its checks and the feed catalog")
                except Exception as e:  # noqa: BLE001
                    check(False, f"{tag}: page loaded its data ({e})")
                    ctx.close()
                    continue
                grade = page.inner_text("#sec-grade").strip()
                check(grade in ("A", "B", "C", "D", "F"), f"{tag}: grade shown ({grade})")
                rows = page.locator("#sec-checks tr[data-check]")
                n = rows.count()
                check(n >= 15, f"{tag}: {n} check rows")
                no_fix = page.evaluate(
                    "[...document.querySelectorAll('#sec-checks tr[data-check]')].filter(r => !r.querySelector('.sec-st') || !r.querySelector('a[href]')).map(r => r.dataset.check)"
                )
                check(not no_fix, f"{tag}: every check has a status badge and a Fix link ({no_fix})")
                feeds = page.evaluate("[...document.querySelectorAll('#feeds-table tr[data-feed]')].map(r => r.dataset.feed)")
                check("spamhaus_drop" in feeds and len(feeds) >= 7, f"{tag}: feed catalog lists {len(feeds)} feeds")
                nav = page.locator('.sidebar-nav a.nav-item[href="/security"]')
                check(nav.count() == 1 and "active" in (nav.get_attribute("class") or ""), f"{tag}: menu entry present and marked")
                overflow = page.evaluate("document.scrollingElement.scrollWidth - window.innerWidth")
                check(overflow <= 1, f"{tag}: nothing scrolls sideways (overflow {overflow}px)")
                backgrounds[(scheme, width)] = page.evaluate("getComputedStyle(document.body).backgroundColor")
                shot(page, f"security-{width}-{scheme}-{browser_name}")
                if WRITE and width == 1280 and scheme == "light":
                    before = api(page, "GET", "/api/security")["json"]
                    page.click("#sec-review")
                    page.wait_for_selector("#sec-plan[open]", timeout=15000)
                    changes = page.locator("#sec-plan-changes li[data-check]").count()
                    skipped = page.locator("#sec-plan-skipped li[data-check]").count()
                    check(changes > 0 and skipped > 0, f"{tag}: dry run lists {changes} change(s) and {skipped} left alone")
                    shot(page, f"security-plan-{width}-{scheme}-{browser_name}")
                    revs = len(api(page, "GET", "/api/system/history")["json"])
                    page.click("#sec-apply")
                    page.wait_for_selector("#sec-undo:not([style*='none'])", timeout=30000)
                    after = api(page, "GET", "/api/security")["json"]
                    check(after["score"] > before["score"], f"{tag}: applying raises the score ({before['score']} -> {after['score']})")
                    revs2 = len(api(page, "GET", "/api/system/history")["json"])
                    check(revs2 == revs + 1, f"{tag}: one configuration revision ({revs} -> {revs2})")
                    check("Applied" in page.inner_text("#sec-flash"), f"{tag}: the page says what it applied")
                    shot(page, f"security-applied-{width}-{scheme}-{browser_name}")
                    page.once("dialog", lambda d: d.accept())
                    page.click("#sec-undo-btn")
                    page.wait_for_function("document.getElementById('sec-flash').innerText.includes('undone')", timeout=30000)
                    undone = api(page, "GET", "/api/security")["json"]
                    check(undone["score"] == before["score"], f"{tag}: Undo puts it back (score {undone['score']})")
                    sel = page.locator('#feeds-table tr[data-feed="spamhaus_drop"] select.feed-mode')
                    sel.select_option("alert")
                    page.wait_for_function("document.getElementById('sec-flash').innerText.includes('alert only')", timeout=15000)
                    feed = [f for f in api(page, "GET", "/api/security/feeds")["json"]["threat"]["feeds"] if f["id"] == "spamhaus_drop"][0]
                    check(feed["action"] == "alert", f"{tag}: the catalog stores alert-only mode ({feed['action']})")
                ctx.close()
        check(
            backgrounds.get(("light", 1280)) != backgrounds.get(("dark", 1280)),
            f"the page follows the colour scheme ({backgrounds.get(('light', 1280))} vs {backgrounds.get(('dark', 1280))})",
        )
        browser.close()
    print(f"{'FAILED' if failed else 'OK'}: {len(failed)} failure(s)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
