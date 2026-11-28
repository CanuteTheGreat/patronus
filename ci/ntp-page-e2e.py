#!/usr/bin/env python3
"""NTP page (access list + GPS/PPS source) driven in a real browser (Playwright). Claim C1304.

Checks, against a running patronus-web:
  1. the menu has the NTP entry and the page shows both cards with every field;
  2. the access list is saved THROUGH THE FORM and read back from the API; a /0 block is refused on the page
     ("Not applied: ...") and nothing is stored;
  3. the GPS form saves device, speed, pulse device and time correction (the GPS stays off: the daemons are
     proven by lane-j-ntp.sh), the page shows the saved values after a reload;
  4. at phone width, in the light and the dark scheme, the page does not scroll sideways;
  5. no JavaScript error.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... ntp-page-e2e.py [firefox,chromium]
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]

failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


def api(page, path, method="GET", body=None):
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


def no_sideways_scroll(page):
    return page.evaluate("() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 1000})
    page = ctx.new_page()
    errors = []
    dialogs = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
    tag = f"[{kind}] "

    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)

    page.goto(BASE + "/ntp")
    page.wait_for_selector("#ntp-gps-form", timeout=15000)
    link = page.locator('.sidebar-nav a.nav-item[href="/ntp"]')
    check(tag + "the menu has an NTP entry", link.count() == 1, link.count())
    acl = ["acl_mode", "acl_allow", "acl_deny", "ratelimit"]
    gps = ["gps_enabled", "gps_device", "gps_baud", "gps_pps_device", "gps_offset", "gps_prefer"]
    miss = [k for k in acl if page.locator(f"#ntp-acl-form [name={k}]").count() != 1]
    miss += [k for k in gps if page.locator(f"#ntp-gps-form [name={k}]").count() != 1]
    check(tag + "every access-list and GPS field is on the page", not miss, miss)
    check(tag + "the GPS card says whether gpsd is installed and the receiver present",
          "gpsd:" in page.locator("#gps-status").inner_text(), page.locator("#gps-status").inner_text())

    # access list through the form
    page.fill("#ntp-acl-form [name=acl_allow]", "10.9.0.0/24, 198.51.100.5")
    page.fill("#ntp-acl-form [name=acl_deny]", "10.9.0.99")
    page.select_option("#ntp-acl-form [name=acl_mode]", "explicit")
    page.check("#ntp-acl-form [name=ratelimit]")
    with page.expect_navigation(timeout=30000):
        page.click("#ntp-acl-form button[type=submit]")
    s = api(page, "/api/ntp")["json"]["settings"]
    check(tag + "the access list saved through the form is stored",
          s["acl_mode"] == "explicit" and s["acl_allow"] == ["10.9.0.0/24", "198.51.100.5"]
          and s["acl_deny"] == ["10.9.0.99"] and s["ratelimit"] is True, s)
    page.wait_for_selector("#ntp-acl-form")
    check(tag + "after the reload the form shows what was saved",
          page.input_value("#ntp-acl-form [name=acl_allow]") == "10.9.0.0/24, 198.51.100.5"
          and page.input_value("#ntp-acl-form [name=acl_mode]") == "explicit")

    # a /0 block is refused on the page
    dialogs.clear()
    page.fill("#ntp-acl-form [name=acl_allow]", "0.0.0.0/0")
    page.click("#ntp-acl-form button[type=submit]")
    page.wait_for_timeout(1500)
    check(tag + "a /0 block is refused on the page with the reason",
          any("Not applied" in d and "/0" in d for d in dialogs), dialogs)
    s = api(page, "/api/ntp")["json"]["settings"]
    check(tag + "the refused block was not stored", s["acl_allow"] == ["10.9.0.0/24", "198.51.100.5"], s["acl_allow"])

    # GPS form (stays off)
    page.goto(BASE + "/ntp")
    page.wait_for_selector("#ntp-gps-form")
    page.fill("#ntp-gps-form [name=gps_device]", "/dev/ttyAMA0")
    page.select_option("#ntp-gps-form [name=gps_baud]", "115200")
    page.fill("#ntp-gps-form [name=gps_pps_device]", "/dev/pps1")
    page.fill("#ntp-gps-form [name=gps_offset]", "0.12")
    with page.expect_navigation(timeout=30000):
        page.click("#ntp-gps-form button[type=submit]")
    g = api(page, "/api/ntp")["json"]["settings"]["gps"]
    check(tag + "the GPS settings saved through the form are stored",
          g["device"] == "/dev/ttyAMA0" and g["baud"] == 115200 and g["pps_device"] == "/dev/pps1"
          and abs(g["offset"] - 0.12) < 1e-9 and g["enabled"] is False, g)
    page.wait_for_selector("#ntp-gps-form")
    check(tag + "after the reload the GPS form shows what was saved",
          page.input_value("#ntp-gps-form [name=gps_baud]") == "115200"
          and page.input_value("#ntp-gps-form [name=gps_pps_device]") == "/dev/pps1")
    dialogs.clear()
    page.fill("#ntp-gps-form [name=gps_device]", "/dev/sda")
    page.click("#ntp-gps-form button[type=submit]")
    page.wait_for_timeout(1500)
    check(tag + "a device that is not a serial port is refused on the page",
          any("Not applied" in d for d in dialogs), dialogs)

    # phone width, both schemes
    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(BASE + "/ntp")
        page.wait_for_selector("#ntp-gps-form")
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
    page.emulate_media(color_scheme=None)

    # put the settings back
    api(page, "/api/ntp", "PUT", {"acl_mode": "interfaces", "acl_allow": "", "acl_deny": "", "ratelimit": False,
                                  "gps_device": "/dev/ttyUSB0", "gps_baud": 9600, "gps_pps_device": "", "gps_offset": 0})
    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS ntp-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
