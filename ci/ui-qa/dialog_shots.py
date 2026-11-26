#!/usr/bin/env python3
"""Screenshots of the forms that live in dialogs (the page crawl only sees closed dialogs).

  BASE_URL=... E2E_PASSWORD=... dialog_shots.py --shots DIR [--widths desktop,phone] [--schemes light,dark]

For every (page, opener) below that exists on this build, the dialog is opened with its button, checked to be
open and to hold focus, screenshotted (viewport, the dialog is modal) as <scheme>-<width>/<page>--<name>.png, and
closed with Escape. A dialog that does not open, or opens without focus inside it, is a failure (exit 1).
"""
import argparse
import os
import sys

from playwright.sync_api import sync_playwright

VIEWPORTS = {"desktop": (1280, 800), "phone": (390, 844)}
# page, name, how to open (a selector clicked after an optional tab button), dialog selector
DIALOGS = [
    ("/firewall", "rule", None, "#rule-add", "#rule-dialog"),
    ("/firewall", "port-forward", "[data-tab=tab-pf]", "[data-open=pf-form]", "#pf-form-dlg"),
    ("/firewall", "alias", "[data-tab=tab-aliases]", "[data-open=alias-form]", "#alias-form-dlg"),
    ("/firewall", "schedule", "[data-tab=tab-schedules]", "[data-open=schedule-form]", "#schedule-form-dlg"),
    ("/interfaces", "vlan", None, "[data-open=vlan-form]", "#vlan-form-dlg"),
    ("/interfaces", "bond", None, "[data-open=bond-form]", "#bond-form-dlg"),
    ("/interfaces", "overlay", None, "[data-open=overlay-form]", "#overlay-form-dlg"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", required=True)
    ap.add_argument("--widths", default="desktop,phone")
    ap.add_argument("--schemes", default="light,dark")
    ap.add_argument("--base", default=os.environ.get("BASE_URL", "https://localhost:8443"))
    a = ap.parse_args()
    base = a.base.rstrip("/")
    bad, n = [], 0
    with sync_playwright() as p:
        browser = getattr(p, os.environ.get("BROWSER", "firefox")).launch()
        for scheme in a.schemes.split(","):
            for vp in a.widths.split(","):
                ctx = browser.new_context(ignore_https_errors=True, viewport={"width": VIEWPORTS[vp][0], "height": VIEWPORTS[vp][1]}, color_scheme=scheme)
                page = ctx.new_page()
                page.goto(base + "/login", wait_until="load")
                page.fill("#username", os.environ.get("E2E_USER", "admin"))
                page.fill("#password", os.environ["E2E_PASSWORD"])
                page.click("button[type=submit]")
                page.wait_for_function("() => !location.pathname.startsWith('/login')", timeout=30000)
                d = os.path.join(a.shots, f"{scheme}-{vp}")
                os.makedirs(d, exist_ok=True)
                for route, name, tab, opener, dlg in DIALOGS:
                    page.goto(base + route, wait_until="load")
                    page.wait_for_timeout(700)
                    if tab:
                        if page.locator(tab).count() == 0:
                            continue
                        page.locator(tab).first.click()
                    o = page.locator(opener)
                    if o.count() == 0 or not o.first.is_visible():
                        continue  # not on this build / role
                    o.first.click()
                    try:
                        page.wait_for_selector(dlg + "[open]", timeout=5000)
                    except Exception:  # noqa: BLE001
                        bad.append(f"{route} {name} [{scheme}/{vp}]: dialog did not open")
                        continue
                    inside = page.evaluate(f"() => !!document.activeElement && !!document.activeElement.closest('{dlg}')")
                    if not inside:
                        bad.append(f"{route} {name} [{scheme}/{vp}]: focus is not inside the dialog")
                    page.add_style_tag(content="*, *::before, *::after { transition: none !important; animation: none !important; }")
                    page.wait_for_timeout(150)
                    page.screenshot(path=os.path.join(d, route.strip("/").replace("/", "-") + f"--{name}.png"))
                    n += 1
                    page.keyboard.press("Escape")
                ctx.close()
        browser.close()
    for b in bad:
        print("FAIL", b)
    print(f"dialog_shots: {n} dialog screenshots, {len(bad)} fail")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
