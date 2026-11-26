#!/usr/bin/env python3
"""Brute-force protection page in a real browser (Playwright), against a running patronus-web.

Usage: BASE_URL=https://192.168.50.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1] [E2E_SHOTS=/t/shots]
       guard-page-e2e.py [firefox|chromium]

Checks at 1280 px and 390 px, light and dark: the menu entry is there and marked, the page loads its data (state pill,
the seeded ban 203.0.113.9 with its reason), nothing scrolls sideways, the colour scheme follows the browser setting.
With E2E_WRITE=1: a refused setting shows the error on the page, saving the form changes the stored setting, the
manual ban form bans an address, the Lift ban button lifts it. Prints PASS:/FAIL: lines, exits 1 on any failure.
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
        """async ([p, m, b]) => { const r = await fetch(p, {method: m, credentials: 'same-origin',
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
                page.goto(BASE + "/security/brute-force")
                tag = f"{width}px {scheme}"
                try:
                    page.wait_for_selector("#g-state .pill", timeout=15000)
                    check(True, f"{tag}: page loaded its data")
                except Exception as e:  # noqa: BLE001
                    check(False, f"{tag}: page loaded its data ({e})")
                    ctx.close()
                    continue
                check(page.inner_text("#g-state").strip() == "On", f"{tag}: state shows On")
                bans = page.inner_text("#g-bans")
                check("203.0.113.9" in bans and "seeded" in bans, f"{tag}: the seeded ban and its note are listed")
                nav = page.locator('.sidebar-nav a.nav-item[href="/security/brute-force"]')
                check(nav.count() == 1 and "active" in (nav.get_attribute("class") or ""), f"{tag}: menu entry present and marked")
                overflow = page.evaluate("document.scrollingElement.scrollWidth - window.innerWidth")
                check(overflow <= 1, f"{tag}: nothing scrolls sideways (overflow {overflow}px)")
                backgrounds[(scheme, width)] = page.evaluate("getComputedStyle(document.body).backgroundColor")
                if SHOTS:
                    os.makedirs(SHOTS, exist_ok=True)
                    page.screenshot(path=f"{SHOTS}/guard-{width}-{scheme}-{browser_name}.png", full_page=True)
                if WRITE and width == 1280 and scheme == "light":
                    # a refused value: the page shows why
                    page.fill('#g-form input[name=max_failures]', "0")
                    page.evaluate("document.querySelector('#g-form input[name=max_failures]').removeAttribute('min')")
                    page.click("#g-save")
                    page.wait_for_selector("#g-error:not([style*='none'])", timeout=10000)
                    check("Invalid" in page.inner_text("#g-error"), f"{tag}: a refused setting shows the error on the page")
                    page.fill('#g-form input[name=max_failures]', "7")
                    page.click("#g-save")
                    page.wait_for_function(
                        "document.getElementById('g-error').style.display === 'none'", timeout=10000
                    )
                    got = api(page, "GET", "/api/guard")["json"]["settings"]["max_failures"]
                    check(got == 7, f"{tag}: saving the form stores the setting (max_failures {got})")
                    page.fill('#g-ban-form input[name=address]', "198.51.100.66")
                    page.fill('#g-ban-form input[name=reason]', "from the page")
                    page.click('#g-ban-form button[type=submit]')
                    page.wait_for_function("document.getElementById('g-bans').innerText.includes('198.51.100.66')", timeout=10000)
                    check(True, f"{tag}: the ban form bans an address")
                    page.click('button[aria-label="Lift the ban of 198.51.100.66"]')
                    page.wait_for_function("!document.getElementById('g-bans').innerText.includes('198.51.100.66')", timeout=10000)
                    act = [b["address"] for b in api(page, "GET", "/api/guard")["json"]["active"]]
                    check("198.51.100.66" not in act, f"{tag}: Lift ban lifts it")
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
