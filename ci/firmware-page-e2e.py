#!/usr/bin/env python3
"""Browser check of System > Firmware: upload an image file through the page, require the check verdict, then (with
E2E_INSTALL=1) press Install, accept the dialog and require the page to report the restart. Exit 0 = passed.
Usage: BASE_URL=https://192.0.2.10 E2E_USER=... E2E_PASSWORD=... firmware-page-e2e.py IMAGE.tar [BAD.tar]
BAD.tar (optional) must be refused with the tool's reason before the good image is uploaded."""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"].rstrip("/")
fails = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:500]), flush=True)
    if not ok:
        fails.append(name)


with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    page = b.new_context(ignore_https_errors=True).new_page()
    errs = []
    page.on("pageerror", lambda e: errs.append(str(e)))
    page.goto(BASE + "/login")
    page.fill("#username", os.environ["E2E_USER"])
    page.fill("#password", os.environ["E2E_PASSWORD"])
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
    page.goto(BASE + "/system")
    page.wait_for_selector("#firmware-card", state="visible", timeout=30000)
    check("firmware card shows the running build", "Running " in page.inner_text("#fw-state"), page.inner_text("#fw-state"))

    def upload(path):
        page.set_input_files("#fw-file", path)
        page.click("#fw-upload")
        page.wait_for_function("() => !document.querySelector('#fw-out').textContent.startsWith('Uploading')", timeout=240000)
        return page.inner_text("#fw-out")

    if len(sys.argv) > 2:
        out = upload(sys.argv[2])
        check("bad image refused with the tool's reason", out.startswith("Not accepted:") and "patronus-flash" in out, out)
        check("no Install button after a refusal", not page.is_visible("#fw-install"))
    out = upload(sys.argv[1])
    check("good image passes the check", "OK:" in out, out)
    check("Install button offered", page.is_visible("#fw-install"))
    if os.environ.get("E2E_INSTALL") == "1":
        page.once("dialog", lambda d: d.accept())
        page.click("#fw-install")
        page.wait_for_function("() => document.querySelector('#fw-out').textContent.includes('Restarting to install')", timeout=120000)
        check("install staged, restart announced", "Restarting to install" in page.inner_text("#fw-out"), page.inner_text("#fw-out"))
    else:
        page.click("#fw-discard")
        page.wait_for_function("() => document.querySelector('#fw-out').textContent === 'Discarded.'", timeout=30000)
        check("discard", not page.is_visible("#fw-install"))
    check("no JavaScript errors", not errs, errs)
    b.close()
print("FAILED: " + (", ".join(fails) if fails else "none"))
sys.exit(1 if fails else 0)
