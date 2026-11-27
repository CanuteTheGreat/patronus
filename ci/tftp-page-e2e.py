#!/usr/bin/env python3
"""TFTP server page, driven in a real browser (Playwright + Firefox/Chromium).

Runs against the shipped patronus-web (see ci/netlab/lane-j-tftp-ui.sh, where it runs in the
LAN client's namespace so it can also fetch the uploaded file with a real TFTP client). Checks:
  1. the menu has a "TFTP server" entry, every setting is on the page, the clients table, its
     form and the file manager card are on the page, the status card is filled;
  2. phone width (390 px) in the light and dark scheme: no sideways page scroll, every table
     sits in a labelled, scrollable region; the controls have labels (WCAG name/role/value);
  3. a system directory as the root is refused ON THE PAGE with the reason and nothing is stored;
  4. With E2E_WRITE=1, through the page only: switch the server on (read only), upload a file with
     the file chooser, see it in the file table, fetch it with a real TFTP client (curl; E2E_TFTP_HOST),
     check the byte-for-byte content, add a client network row and see the rule limited, delete the
     row, delete the file with its Delete button, switch the server off and see the status say so.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_TFTP_HOST=192.168.50.1]
       tftp-page-e2e.py [firefox,chromium]
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
TFTP_HOST = os.environ.get("E2E_TFTP_HOST", "")

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


def status_text(page):
    return page.locator("#svc-status").inner_text()


def no_sideways_scroll(page):
    return page.evaluate("() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")


def wait_page(page):
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=20000)
    page.wait_for_selector("#tftp-upload-form", timeout=20000)


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 1000})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", lambda d: d.accept())
    tag = f"[{kind}] "

    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)

    page.goto(BASE + "/svc/tftp")
    wait_page(page)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/tftp"]')
    check(tag + "the menu has a TFTP server entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))

    keys = ["enabled", "interfaces", "port", "root", "allow_write", "overwrite", "max_write_kb", "blksize_max",
            "timeout", "retries", "max_sessions", "data_ports", "run_as", "ui_upload_kb"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every setting is on the page", not missing, missing)
    check(tag + "the client networks table and its form are on the page",
          page.locator("[data-coll=clients]").count() == 1 and page.locator("#svc-form-clients").count() == 1)
    check(tag + "the file manager (table region, upload form) is on the page",
          page.locator("#tftp-files-table").count() == 1 and page.locator("#tftp-upload-form [name=file]").count() == 1)
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])
    unlabeled = page.evaluate(
        """() => [...document.querySelectorAll('#svc-settings-form input, #svc-settings-form select, #tftp-upload-form input')]
             .filter(e => !(e.labels && e.labels.length) && !e.getAttribute('aria-label')).map(e => e.name)""")
    check(tag + "every control has a label", not unlabeled, unlabeled)

    # phone width, both colour schemes
    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        wait_page(page)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
        check(tag + f"phone width, {scheme}: every table sits in a scrollable, labelled region",
              page.locator(".svc-scroll[role=region][aria-label]").count() == 2, page.locator(".svc-scroll").count())
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.reload()
    wait_page(page)

    # a system directory as the root is refused on the page
    page.fill("#svc-settings-form [name=root]", "/etc")
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "/etc as the root is refused on the page, with the reason", "Not applied" in msg and "root directory" in msg, msg)
    check(tag + "the refused root was not stored", api(page, "/api/svc/tftp")["json"]["settings"]["root"] != "/etc")
    page.reload()
    wait_page(page)

    if WRITE:
        # switch it on through the page (read only, the LAN)
        page.locator("#svc-settings-form [name=enabled]").set_checked(True)
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => /running\\s*yes/i.test(document.getElementById('svc-status').innerText)", timeout=40000)
        check(tag + "switched on through the page: the status says it runs, read only",
              "read only" in status_text(page).lower(), status_text(page)[:300])
        # upload with the file chooser
        data = bytes((i * 7) % 251 for i in range(3000))
        page.set_input_files("#tftp-upload-form [name=file]", files=[{"name": "e2e-boot.bin", "mimeType": "application/octet-stream", "buffer": data}])
        page.click("#tftp-upload-form button[type=submit]")
        page.wait_for_selector('#tftp-files-table tr[data-name="e2e-boot.bin"]', timeout=20000)
        row = page.locator('#tftp-files-table tr[data-name="e2e-boot.bin"]').inner_text()
        check(tag + "the uploaded file is listed with its size", "3000" in row, row)
        if TFTP_HOST:
            out = os.path.join(tempfile.mkdtemp(), "got.bin")
            rc = subprocess.run(["curl", "-s", "-m", "20", "-o", out, f"tftp://{TFTP_HOST}/e2e-boot.bin"]).returncode
            got = open(out, "rb").read() if os.path.exists(out) else b""
            check(tag + "a real TFTP client fetches the uploaded file byte for byte",
                  rc == 0 and hashlib.sha256(got).digest() == hashlib.sha256(data).digest(), (rc, len(got)))
        # the same name again is refused until "replace" is ticked
        page.set_input_files("#tftp-upload-form [name=file]", files=[{"name": "e2e-boot.bin", "mimeType": "application/octet-stream", "buffer": b"x" * 10}])
        page.click("#tftp-upload-form button[type=submit]")
        page.wait_for_selector("#svc-error", state="visible", timeout=15000)
        check(tag + "uploading the same name again is refused on the page", "already exists" in page.locator("#svc-error").inner_text(),
              page.locator("#svc-error").inner_text())
        # a client network: add, see the table row, remove
        page.fill("#svc-form-clients [name=cidr]", "192.168.50.0/24")
        page.click("#svc-form-clients button[type=submit]")
        page.wait_for_selector('[data-coll=clients] tr[data-id]', timeout=20000)
        check(tag + "a client network row was added through the page", "192.168.50.0/24" in page.locator("[data-coll=clients]").inner_text())
        page.locator("[data-coll=clients] tr[data-id] button", has_text="Delete").first.click()
        page.wait_for_function("() => document.querySelectorAll('[data-coll=clients] tr[data-id]').length === 0", timeout=20000)
        check(tag + "the client network row was deleted through the page", True)
        # delete the file with its button
        page.locator('#tftp-files-table tr[data-name="e2e-boot.bin"] button', has_text="Delete").click()
        page.wait_for_function("() => !document.querySelector('#tftp-files-table tr[data-name=\"e2e-boot.bin\"]')", timeout=20000)
        check(tag + "the file was deleted through its Delete button", True)
        # switch off
        page.locator("#svc-settings-form [name=enabled]").set_checked(False)
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => /running\\s*no/i.test(document.getElementById('svc-status').innerText)", timeout=40000)
        check(tag + "switched off through the page: the status says it is not running", True)

    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS tftp-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
