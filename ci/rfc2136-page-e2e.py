#!/usr/bin/env python3
"""Browser check of the RFC 2136 dynamic DNS page (Dynamic DNS (RFC 2136) in the menu, /svc/rfc2136).

Signs in, then requires, in each browser (Firefox by default; Chromium when installed):
  1. the menu has a "Dynamic DNS (RFC 2136)" entry that is not marked unavailable;
  2. the page shows every setting, the clients table with its form (the TSIG secret is a password field),
     and a filled status card; no JavaScript error;
  3. at phone width (390 px) the page does not scroll sideways, in the light and the dark colour scheme;
  4. a client added through the form with a secret that is not base64 is refused ON THE PAGE when the service is
     switched on (nothing is running afterwards), and the secret is never shown back.
With E2E_WRITE=1 (a real DNS server answers at E2E_SERVER with the key E2E_KEY_NAME / E2E_KEY_SECRET for zone
E2E_ZONE) it also, through the page only:
  5. adds a good client through the form, the row is listed with the secret shown only as "set";
  6. switches the service on (interval 5 s); the status card reports the client ok with the WAN address;
  7. a wrong secret in a second client is reported as FAILED on the page while the first stays ok;
  8. deleting both clients through the table and switching the service off leaves the status saying it is not running.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_SERVER=198.51.100.53
       E2E_ZONE=example.net E2E_KEY_NAME=ddns-key E2E_KEY_SECRET=... E2E_WRONG_SECRET=...] rfc2136-page-e2e.py [firefox,chromium]
"""
import json
import os
import re
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
SERVER = os.environ.get("E2E_SERVER", "198.51.100.53")
ZONE = os.environ.get("E2E_ZONE", "example.net")
KEY_NAME = os.environ.get("E2E_KEY_NAME", "ddns-key")
KEY_SECRET = os.environ.get("E2E_KEY_SECRET", "")
WRONG_SECRET = os.environ.get("E2E_WRONG_SECRET", "")

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


def on_dialog(d):
    if "Delete this entry" in d.message:
        d.accept()
    else:
        d.dismiss()


def status_text(page):
    return page.locator("#svc-status").inner_text()


def no_sideways_scroll(page):
    return page.evaluate("() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")


def fill_client(page, host, secret):
    f = "#svc-form-clients"
    page.fill(f + " [name=hostname]", host)
    page.fill(f + " [name=zone]", ZONE)
    page.fill(f + " [name=server]", SERVER)
    page.fill(f + " [name=key_name]", KEY_NAME)
    page.fill(f + " [name=key_secret]", secret)
    page.fill(f + " [name=iface]", "@wan")
    page.click(f + " button[type=submit]")


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 1000})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", on_dialog)
    tag = f"[{kind}] "

    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)

    page.goto(BASE + "/svc/rfc2136")
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/rfc2136"]')
    check(tag + "the menu has a Dynamic DNS (RFC 2136) entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))
    keys = ["enabled", "interval", "refresh", "timeout"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every setting is on the page", not missing, missing)
    fields = ["hostname", "zone", "server", "port", "tcp", "key_name", "key_algo", "key_secret", "iface", "family", "ttl", "enabled"]
    missing = [k for k in fields if page.locator(f"#svc-form-clients [name={k}]").count() != 1]
    check(tag + "the clients table and its form have every field", page.locator("[data-coll=clients]").count() == 1 and not missing, missing)
    check(tag + "the TSIG secret is a password field",
          page.locator("#svc-form-clients [name=key_secret]").get_attribute("type") == "password")
    check(tag + "the status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])

    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
        check(tag + f"phone width, {scheme}: the table sits in a scrollable, labelled region",
              page.locator(".svc-scroll[role=region][aria-label]").count() == 1, page.locator(".svc-scroll").count())
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.reload()
    page.wait_for_selector("#svc-form-clients [name=hostname]", timeout=15000)

    # a secret that is not base64: stored, but switching the service on is refused on the page with the reason
    fill_client(page, "e2e-bad." + ZONE, "not-base64-secret!")
    page.wait_for_selector("[data-coll=clients] tr[data-id]", timeout=15000)
    page.fill("#svc-settings-form [name=interval]", "5")
    page.locator("#svc-settings-form [name=enabled]").set_checked(True)
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "a secret that is not base64 is refused on the page, with the reason",
          "Not applied" in msg and "base64" in msg, msg)
    d = api(page, "/api/svc/rfc2136")["json"]
    check(tag + "the service is still off after the refusal", d["settings"]["enabled"] is False, d["settings"])
    check(tag + "the API never returns a secret", "not-base64-secret" not in json.dumps(d), d)
    row_text = page.locator("[data-coll=clients]").inner_text()
    check(tag + "the table shows the secret only as 'set'", "not-base64-secret" not in row_text and "set" in row_text, row_text)
    for r in d["collections"]["clients"]:
        api(page, f"/api/svc/rfc2136/clients/{r['id']}", "DELETE")

    if WRITE:
        page.reload()
        page.wait_for_selector("#svc-form-clients [name=hostname]")
        fill_client(page, "e2e." + ZONE, KEY_SECRET)
        page.wait_for_function("() => document.querySelectorAll('[data-coll=clients] tr[data-id]').length === 1", timeout=15000)
        check(tag + "the good client is listed", "e2e." + ZONE in page.locator("[data-coll=clients]").inner_text())
        check(tag + "its secret is not in the page", KEY_SECRET not in page.content())
        page.fill("#svc-settings-form [name=interval]", "5")
        page.locator("#svc-settings-form [name=enabled]").set_checked(True)
        page.click("#svc-settings-form button[type=submit]")
        try:
            page.wait_for_function(
                "() => /e2e\\.[^ ]+: ok/.test(document.getElementById('svc-status').innerText)", timeout=60000)
            check(tag + "the status card reports the client ok", True)
        except Exception:
            check(tag + "the status card reports the client ok", False, status_text(page))
            browser.close()
            return
        check(tag + "the status says the service runs", re.search(r"running\s*yes", status_text(page), re.I) is not None, status_text(page)[:300])
        page.fill("#svc-form-clients [name=hostname]", "e2e-wrong." + ZONE)
        fill_client(page, "e2e-wrong." + ZONE, WRONG_SECRET)
        page.wait_for_function("() => document.querySelectorAll('[data-coll=clients] tr[data-id]').length === 2", timeout=15000)
        try:
            page.wait_for_function(
                "() => /e2e-wrong\\.[^ ]+: FAILED/.test(document.getElementById('svc-status').innerText)", timeout=90000)
            check(tag + "the wrong secret shows as FAILED on the page", True)
        except Exception:
            page.reload()
            check(tag + "the wrong secret shows as FAILED on the page", False, status_text(page))
        # the status card refreshes on load only: reload to see the current state
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]")
        st = status_text(page)
        check(tag + "the good client is still ok next to the failing one", "e2e." + ZONE + ": ok" in st, st[:400])
        for r in api(page, "/api/svc/rfc2136")["json"]["collections"]["clients"]:
            page.locator(f"[data-coll=clients] tr[data-id='{r['id']}'] button", has_text="Delete").click()
            page.wait_for_function(f"() => !document.querySelector(\"[data-coll=clients] tr[data-id='{r['id']}']\")", timeout=30000)
        check(tag + "both clients were deleted through the page", True)
        page.locator("#svc-settings-form [name=enabled]").set_checked(False)
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => /running\\s*no/i.test(document.getElementById('svc-status').innerText)", timeout=30000)
        check(tag + "switched off through the page: the status says it is not running", True)

    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS rfc2136-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
