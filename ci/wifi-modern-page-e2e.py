#!/usr/bin/env python3
"""Browser check of the Wi-Fi generation controls (Segmentation > Wi-Fi, /segmentation#wifi), docs/WIFI-MODERN.md.

Signs in and requires, in each browser (Firefox by default):
  1. the Radios table names what the radio E2E_RADIO supports (E2E_EXPECT, e.g. "Wi-Fi 7" and "320 MHz") and the
     hostapd line says what the installed hostapd was built with;
  2. the add-network form offers only what the radio supports: the band picker lists the radio's bands, the width
     picker follows the band (2.4 GHz: 20/40 MHz only; 6 GHz: up to 320 MHz when the radio has it), the generation
     picker has no Wi-Fi 5 on 2.4 GHz and only Wi-Fi 6/7 on 6 GHz;
  3. choosing 6 GHz switches security to WPA3, disables WPA2 and shows why, inline next to the pickers;
  4. every existing network says which generation and width it runs (or why it is not running);
  5. no JavaScript error; screenshots go to E2E_SHOTS (default /t/wifi-modern-shots).

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... E2E_RADIO=wlan0 [E2E_EXPECT="Wi-Fi 7,320 MHz"] \\
       wifi-modern-page-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
SECRET = os.environ["E2E_PASSWORD"]
RADIO = os.environ.get("E2E_RADIO", "wlan0")
EXPECT = [x.strip() for x in os.environ.get("E2E_EXPECT", "Wi-Fi 7,320 MHz").split(",") if x.strip()]
SHOTS = os.environ.get("E2E_SHOTS", "/t/wifi-modern-shots")

failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


def options(page, sel):
    return page.eval_on_selector_all(
        sel + " option", "os => os.map(o => ({v: o.value, t: o.textContent, d: o.disabled}))"
    )


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 1400})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    tag = f"[{kind}] "
    os.makedirs(SHOTS, exist_ok=True)

    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", SECRET)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)

    page.goto(BASE + "/segmentation#wifi")
    page.wait_for_selector("#seg-wifi-radios-table", timeout=20000)

    # 1. radios
    row = page.locator("#seg-wifi-radios-table tbody tr", has_text=RADIO)
    check(tag + "the radio is listed", row.count() == 1, row.count())
    sup = row.locator(".wifi-supports").inner_text() if row.count() else ""
    check(tag + "the radio's capabilities are shown", all(e in sup for e in EXPECT), sup)
    hl = page.locator("#wifi-hostapd")
    check(tag + "the hostapd line names its build", hl.count() == 1 and "Wi-Fi 7" in hl.inner_text(), hl.inner_text() if hl.count() else "")
    page.screenshot(path=f"{SHOTS}/{kind}-radios.png", full_page=True)

    # 2./3. the add-network form follows the radio
    form = page.locator("form.lan-form:has(button:text('Add network'))")
    check(tag + "the add-network form is on the page", form.count() == 1, form.count())
    fsel = "form.lan-form:has(button:text('Add network'))"
    form.locator("[name=ifname]").fill(RADIO)
    form.locator("[name=ifname]").dispatch_event("change")
    bands = [o["v"] for o in options(page, fsel + " [name=band]") if not o["d"]]
    check(tag + "the band picker lists the radio's usable bands", "2g" in bands and "5g" in bands, bands)
    form.locator("[name=band]").select_option("2g")
    form.locator("[name=band]").dispatch_event("change")
    w2 = [o["v"] for o in options(page, fsel + " [name=width]")]
    s2 = [o["v"] for o in options(page, fsel + " [name=standard]")]
    check(tag + "2.4 GHz offers 20/40 MHz only", w2 == ["20", "40"], w2)
    check(tag + "2.4 GHz offers no Wi-Fi 5", "ac" not in s2 and "auto" in s2, s2)
    if "6g" in bands:
        form.locator("[name=band]").select_option("6g")
        form.locator("[name=band]").dispatch_event("change")
        w6 = [o["v"] for o in options(page, fsel + " [name=width]")]
        s6 = [o["v"] for o in options(page, fsel + " [name=standard]")]
        sec = options(page, fsel + " [name=security]")
        note = page.locator(fsel + " #wifi-gen-note").inner_text()
        check(tag + "6 GHz offers up to 320 MHz", w6[-1:] == ["320"] if "320 MHz" in EXPECT else bool(w6), w6)
        check(tag + "6 GHz offers Wi-Fi 6/7 only", [x for x in s6 if x != "auto"] in (["ax", "be"], ["ax"]), s6)
        check(tag + "6 GHz forces WPA3 and disables WPA2",
              form.locator("[name=security]").input_value() == "wpa3"
              and all(o["d"] for o in sec if o["v"] != "wpa3"), sec)
        check(tag + "the reason is shown next to the pickers", "WPA3 (SAE) only" in note and "Per-device" in note, note)
        page.screenshot(path=f"{SHOTS}/{kind}-add-6ghz.png", full_page=True)
        form.locator("[name=band]").select_option("5g")
        form.locator("[name=band]").dispatch_event("change")
        sec5 = options(page, fsel + " [name=security]")
        check(tag + "leaving 6 GHz enables WPA2 again", not any(o["d"] for o in sec5), sec5)
    else:
        check(tag + "6 GHz is shown as unavailable with the reason",
              "not available" in row.inner_text(), row.inner_text())

    # 4. existing networks say what they run
    boxes = page.locator("[id^=wifi-chan-]")
    texts = [boxes.nth(i).inner_text() for i in range(boxes.count())]
    check(tag + "every network says what it runs or why not",
          bool(texts) and all(("Runs Wi-Fi" in t) or ("Not running" in t) for t in texts), texts)
    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


with sync_playwright() as p:
    for k in (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(","):
        run(p, k)
print(("FAILED: " + ", ".join(failures)) if failures else "all checks passed")
sys.exit(1 if failures else 0)
