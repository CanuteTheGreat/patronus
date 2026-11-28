#!/usr/bin/env python3
"""Kea DDNS page, driven in a real browser (Playwright + Firefox/Chromium).

Runs against the shipped patronus-web (see ci/netlab/lane-j-kea-ddns-ui.sh). Checks:
  1. the menu has a "DHCP client DNS (Kea DDNS)" entry, every setting is on the page, the registered
     names card (a labelled, scrollable table region) and the status card are filled, every control has a label;
  2. phone width (390 px) in the light and dark scheme: no sideways page scroll, the table sits in a
     labelled scrollable region;
  3. refusals show ON THE PAGE with the reason and nothing is stored (a bad zone, a secret that is not base64);
  4. the secret field is write-only: an empty password input with the "unchanged" hint once a key exists;
  5. With E2E_WRITE=1, through the page only: switch Kea DDNS on (local mode), see the status say that D2 and the
     receiver run, change a setting (generated name prefix), see it persist, get a lease from a real DHCP
     client (E2E_LEASE_CMD, run from the LAN client's namespace) and see its name in the registered names
     table, then switch it off and see the status say so.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_LEASE_CMD=...] kea-ddns-page-e2e.py [firefox,chromium]
"""
import json
import os
import subprocess
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
LEASE_CMD = os.environ.get("E2E_LEASE_CMD", "")
LEASE_NAME = os.environ.get("E2E_LEASE_NAME", "")

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
    page.wait_for_selector("#kea-ddns-table", timeout=20000)


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

    page.goto(BASE + "/svc/kea-ddns")
    wait_page(page)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/kea-ddns"]')
    check(tag + "the menu has a Kea DDNS entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))

    keys = ["enabled", "mode", "forward_zone", "reverse", "server", "server_port", "key_name", "algorithm", "secret",
            "local_port", "d2_port", "override_client_update", "replace_client_name", "generated_prefix",
            "update_on_renew", "unbound_socket", "max_records"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every setting is on the page", not missing, missing)
    check(tag + "the registered names table is on the page", page.locator("#kea-ddns-table").count() == 1)
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])
    unlabeled = page.evaluate(
        """() => [...document.querySelectorAll('#svc-settings-form input, #svc-settings-form select')]
             .filter(e => !(e.labels && e.labels.length) && !e.getAttribute('aria-label')).map(e => e.name)""")
    check(tag + "every control has a label", not unlabeled, unlabeled)
    check(tag + "the secret is a password field", page.locator("#svc-settings-form [name=secret]").get_attribute("type") == "password")

    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        wait_page(page)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
        check(tag + f"phone width, {scheme}: the table sits in a scrollable, labelled region",
              page.locator(".svc-scroll[role=region][aria-label]").count() >= 1, page.locator(".svc-scroll").count())
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.reload()
    wait_page(page)

    # refusals are shown on the page, nothing is stored
    page.fill("#svc-settings-form [name=forward_zone]", "bad zone;x")
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "a bad zone is refused on the page, with the reason", "Not applied" in msg and "zone" in msg, msg)
    check(tag + "the refused zone was not stored", api(page, "/api/svc/kea-ddns")["json"]["settings"]["forward_zone"] != "bad zone;x")
    page.reload()
    wait_page(page)
    page.fill("#svc-settings-form [name=secret]", "this is not base64!")
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "a secret that is not base64 is refused on the page", "Not applied" in msg and "TSIG" in msg or "secret" in msg.lower() or "base64" in msg, msg)
    page.reload()
    wait_page(page)

    if WRITE:
        page.locator("#svc-settings-form [name=enabled]").set_checked(True)
        page.fill("#svc-settings-form [name=forward_zone]", "lan.example")
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function(
            "() => /daemon running\\s*yes/i.test(document.getElementById('svc-status').innerText) && /receiver running\\s*yes/i.test(document.getElementById('svc-status').innerText)",
            timeout=60000)
        check(tag + "switched on through the page: the status says D2 and the receiver run", True)
        page.reload()
        wait_page(page)
        sec = page.locator("#svc-settings-form [name=secret]")
        check(tag + "the generated secret is never shown: the field is empty with an 'unchanged' hint",
              sec.input_value() == "" and (sec.get_attribute("placeholder") or "") == "unchanged",
              (sec.input_value(), sec.get_attribute("placeholder")))
        # a setting changes through the page and persists
        page.fill("#svc-settings-form [name=generated_prefix]", "e2ehost")
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => document.querySelector('#svc-settings-form [name=generated_prefix]').value === 'e2ehost'", timeout=20000)
        check(tag + "a changed setting is saved",
              api(page, "/api/svc/kea-ddns")["json"]["settings"]["generated_prefix"] == "e2ehost")
        if LEASE_CMD:
            rc = subprocess.run(LEASE_CMD, shell=True, timeout=120).returncode
            check(tag + "a real DHCP client got a lease", rc == 0, rc)
            page.reload()
            wait_page(page)
            page.wait_for_function(
                "(n) => [...document.querySelectorAll('#kea-ddns-table tr[data-name]')].some(r => r.dataset.name.startsWith(n))",
                arg=LEASE_NAME, timeout=60000)
            row = page.locator(f'#kea-ddns-table tr[data-name^="{LEASE_NAME}"]').first.inner_text()
            check(tag + "the client's name is in the registered names table", LEASE_NAME in row and "192.168.50." in row, row)
        page.locator("#svc-settings-form [name=enabled]").set_checked(False)
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => /daemon running\\s*no/i.test(document.getElementById('svc-status').innerText)", timeout=40000)
        check(tag + "switched off through the page: the status says D2 is not running", True)

    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS kea-ddns-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
