#!/usr/bin/env python3
"""Browser check of System > Import: choose a pfSense config.xml, map its ports, Preview (the plan, nothing written),
then (with E2E_APPLY=1) Import and apply, accept the dialog and require the page's verdict; with E2E_EXPECT=applied the
LAN address must then be in the configuration (GET /api/interfaces); with E2E_EXPECT=moved (the file moves the LAN address the
browser uses) the page must name the new address. Exit 0 = passed.
Usage: BASE_URL=https://192.0.2.10 E2E_USER=... E2E_PASSWORD=... [E2E_BROWSER=chromium|firefox] import-page-e2e.py CONFIG.xml MAPS
MAPS like "em0=eth0,em1=eth1"; E2E_LAN = the LAN address in CONFIG.xml (checked in the preview and after the import)."""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"].rstrip("/")
LAN = os.environ.get("E2E_LAN", "192.168.7.1")
fails = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        fails.append(name)


with sync_playwright() as p:
    b = getattr(p, os.environ.get("E2E_BROWSER", "chromium")).launch(headless=True)
    ctx = b.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    errs = []
    page.on("pageerror", lambda e: errs.append(str(e)))
    page.goto(BASE + "/login")
    page.fill("#username", os.environ["E2E_USER"])
    page.fill("#password", os.environ["E2E_PASSWORD"])
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
    page.goto(BASE + "/system")
    check("System page links the import page", page.locator("#import-card a[href='/import']").count() == 1)
    page.goto(BASE + "/import")
    page.wait_for_selector("#imp-file", state="visible", timeout=30000)
    check("Import button waits for a preview", page.is_disabled("#imp-apply"))
    page.click("#imp-preview")
    check("no file: the page asks for one", "Choose the configuration file" in page.inner_text("#imp-state"), page.inner_text("#imp-state"))
    page.select_option("#imp-kind", "pfsense")
    page.set_input_files("#imp-file", sys.argv[1])
    page.fill("#imp-maps", "nonsense")
    page.click("#imp-preview")
    page.wait_for_function("() => !document.querySelector('#imp-state').textContent.startsWith('Reading')", timeout=60000)
    check("a bad port mapping is refused with the reason", "mapping" in page.inner_text("#imp-state"), page.inner_text("#imp-state"))
    page.fill("#imp-maps", sys.argv[2])
    page.click("#imp-preview")
    page.wait_for_function("() => document.querySelector('#imp-state').textContent.startsWith('Preview ready')", timeout=60000)
    plan = page.inner_text("#imp-out")
    check("preview shows the plan with the mapped LAN port and address", LAN in plan and sys.argv[2].split(",")[-1].split("=")[1] in plan, plan)
    check("Import button enabled after the preview", page.is_enabled("#imp-apply"))
    if os.environ.get("E2E_APPLY") == "1":
        page.once("dialog", lambda d: d.accept())
        page.click("#imp-apply")
        page.wait_for_function("() => !document.querySelector('#imp-state').textContent.startsWith('Importing')", timeout=180000)
        verdict = page.inner_text("#imp-state")
        print("verdict: " + verdict, flush=True)
        if os.environ.get("E2E_EXPECT", "applied") == "applied":
            check("imported and applied", verdict == "Imported and applied.", verdict + " " + page.inner_text("#imp-out"))
            r = ctx.request.get(BASE + "/api/interfaces")
            check("the LAN address is in the configuration", LAN in r.text(), r.text()[:400])
        elif os.environ.get("E2E_EXPECT") == "moved":
            # the import moved the LAN address this browser used: the answer is lost, the page says where to go
            check("a moved LAN address: the page names the new address", "open https://" + LAN + "/" in verdict, verdict)
        else:
            check("a refused import is undone and says why", "undone" in verdict, verdict)
    check("no JavaScript errors", not errs, errs)
    b.close()
print("FAILED: " + (", ".join(fails) if fails else "none"))
sys.exit(1 if fails else 0)
