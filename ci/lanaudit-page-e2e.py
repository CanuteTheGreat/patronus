#!/usr/bin/env python3
# The LAN security audit page (/security/lan-audit) driven in a real browser (Playwright +
# Firefox) against the shipped patronus-web, at 1280 and 390 px in light and dark: the menu
# entry, the stats loading, no sideways scrolling, the colour scheme, a scan started from the
# page, and (write mode) saving the settings form. The kernel/scan side is proven by
# lane-j-lanaudit.sh.
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"]
USER = os.environ.get("E2E_USER", "admin")
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
SHOTS = os.environ.get("E2E_SHOTS")

failed = []


def check(ok, msg):
    print(("PASS: " if ok else "FAIL: ") + msg)
    if not ok:
        failed.append(msg)


def api(page, method, path, body=None):
    r = page.evaluate(
        """async ([path, method, b]) => {
             const r = await fetch(path, {method, credentials: 'same-origin',
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
                page.goto(BASE + "/security/lan-audit")
                tag = f"{width}px {scheme}"
                try:
                    page.wait_for_selector("#la-stats", timeout=15000)
                    page.wait_for_function(
                        "document.getElementById('la-state').textContent !== '...'", timeout=15000
                    )
                    check(True, f"{tag}: page loaded its data")
                except Exception as e:  # noqa: BLE001
                    check(False, f"{tag}: page loaded its data ({e})")
                    ctx.close()
                    continue
                nav = page.locator('.sidebar-nav a.nav-item[href="/security/lan-audit"]')
                check(
                    nav.count() == 1 and "active" in (nav.get_attribute("class") or ""),
                    f"{tag}: menu entry present and marked",
                )
                tools = page.inner_text("#la-tools")
                check(len(tools) > 0, f"{tag}: the scanner in use is shown ({tools[:40]})")
                overflow = page.evaluate("document.scrollingElement.scrollWidth - window.innerWidth")
                check(overflow <= 1, f"{tag}: nothing scrolls sideways (overflow {overflow}px)")
                backgrounds[(scheme, width)] = page.evaluate(
                    "getComputedStyle(document.body).backgroundColor"
                )
                if SHOTS:
                    os.makedirs(SHOTS, exist_ok=True)
                    page.screenshot(
                        path=f"{SHOTS}/lanaudit-{width}-{scheme}-{browser_name}.png", full_page=True
                    )
                if WRITE and width == 1280 and scheme == "light":
                    # a refused value: the page shows the error
                    page.fill('#la-form input[name=interval_hours]', "100000")
                    page.evaluate(
                        "document.querySelector('#la-form input[name=interval_hours]').removeAttribute('max')"
                    )
                    page.click("#la-save")
                    page.wait_for_selector("#la-error:not([style*='none'])", timeout=10000)
                    check(
                        "Invalid" in page.inner_text("#la-error"),
                        f"{tag}: a refused setting shows the error on the page",
                    )
                    # a valid save stores it
                    page.fill('#la-form input[name=interval_hours]', "12")
                    page.click("#la-save")
                    page.wait_for_function(
                        "document.getElementById('la-error').style.display === 'none'", timeout=10000
                    )
                    got = api(page, "GET", "/api/lanaudit")["json"]["settings"]["interval_hours"]
                    check(got == 12, f"{tag}: saving the form stores the setting (interval_hours {got})")
                    # a scan can be started from the page
                    page.click("#la-scan")
                    page.wait_for_function(
                        "!!document.getElementById('la-running') && getComputedStyle(document.getElementById('la-running')).display !== 'none'"
                        "|| document.getElementById('la-latest').textContent.includes('Scan #')",
                        timeout=15000,
                    )
                    check(True, f"{tag}: a scan can be started from the page")
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
