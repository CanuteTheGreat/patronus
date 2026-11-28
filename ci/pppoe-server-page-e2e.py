#!/usr/bin/env python3
"""Browser check of the PPPoE server page (Services -> PPPoE server, /svc/pppoe-server).

Signs in, then requires, in each browser (Firefox by default; Chromium when installed):
  1. the menu has a "PPPoE server" entry that is not marked unavailable (the build has the feature);
  2. the page shows every setting, the users table and its form and the buttons' status card, never a password,
     and no JavaScript error;
  3. at phone width in the light and dark scheme the page does not scroll sideways;
  4. a refused change (a pool that contains the server address) shows the refusal ON THE PAGE and stores nothing;
  5. a user added through the form is listed with its password as "set" and the password is in no page text.
With E2E_WRITE=1 (the netlab router) it also, through the page only:
  6. switches the server on for E2E_IFACES with a small pool (Save), and requires the status card to say it runs
     and GET /api/svc/pppoe-server to carry the saved values and no password;
  7. switches it off again and requires the status card to say it does not run.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_IFACES=@lan] \
       pppoe-server-page-e2e.py [firefox,chromium]
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
IFACES = os.environ.get("E2E_IFACES", "@lan")
SECRET = "e2e-subscriber-secret-9"

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


def ready(page):
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)


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

    page.goto(BASE + "/svc/pppoe-server")
    ready(page)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/pppoe-server"]')
    check(tag + "the menu has a PPPoE server entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))

    keys = ["enabled", "interfaces", "ac_name", "service_name", "local_ip", "range_start", "range_end", "max_sessions",
            "per_mac_limit", "auth", "dns1", "dns2", "mtu", "lcp_interval", "lcp_failures", "idle_timeout", "mode",
            "unit_base", "internet", "internet_interface", "nat", "lan_access", "router_ports", "radius_enabled",
            "radius_server", "radius_auth_port", "radius_acct_port", "radius_secret", "radius_accounting",
            "radius_timeout", "radius_retries", "radius_source"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every setting is on the page", not missing, missing)
    check(tag + "the users table and its form are on the page",
          page.locator("[data-coll=users]").count() == 1 and page.locator("#svc-form-users").count() == 1)
    check(tag + "the RADIUS secret and the user password are password inputs",
          page.locator("#svc-settings-form [name=radius_secret]").get_attribute("type") == "password"
          and page.locator("#svc-form-users [name=password]").get_attribute("type") == "password")
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])

    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        ready(page)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.reload()
    ready(page)

    # a refused change is shown on the page and stores nothing
    page.fill("#svc-settings-form [name=range_start]", "10.70.0.1")
    page.fill("#svc-settings-form [name=range_end]", "10.70.0.20")
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "a pool containing the server address is refused on the page, with the reason",
          "Not applied" in msg and "outside the client pool" in msg, msg)
    st = api(page, "/api/svc/pppoe-server")["json"]["settings"]
    check(tag + "the refused pool was not stored", st["range_start"] != "10.70.0.1", st)
    page.reload()
    ready(page)

    # a user through the form
    page.fill("#svc-form-users [name=username]", "e2e-user")
    page.fill("#svc-form-users [name=password]", SECRET)
    page.click("#svc-form-users button[type=submit]")
    page.wait_for_function("() => document.querySelector('[data-coll=users]').innerText.includes('e2e-user')", timeout=15000)
    row = page.locator("[data-coll=users] tr[data-id]").first.inner_text()
    check(tag + "the user is listed and the password shows as 'set'", "e2e-user" in row and "set" in row and SECRET not in row, row)
    check(tag + "the password is in no text of the page", SECRET not in page.content() and SECRET not in page.inner_text("body"))
    check(tag + "the API never returns the password", SECRET not in api(page, "/api/svc/pppoe-server")["body"])

    if WRITE:
        page.fill("#svc-settings-form [name=interfaces]", IFACES)
        page.fill("#svc-settings-form [name=local_ip]", "10.70.0.1")
        page.fill("#svc-settings-form [name=range_start]", "10.70.0.10")
        page.fill("#svc-settings-form [name=range_end]", "10.70.0.19")
        page.locator("#svc-settings-form [name=enabled]").set_checked(True)
        page.click("#svc-settings-form button[type=submit]")
        try:
            page.wait_for_function("() => /running\\s*yes/i.test(document.getElementById('svc-status').innerText)", timeout=40000)
        except Exception:
            check(tag + "switching on through the page", False, page.locator("#svc-error").inner_text() + status_text(page))
            browser.close()
            return
        d = api(page, "/api/svc/pppoe-server")
        check(tag + "switched on through the page: the status says it runs, with the saved values",
              d["json"]["settings"]["enabled"] is True and d["json"]["settings"]["range_end"] == "10.70.0.19"
              and d["json"]["status"]["pool_size"] == 10 and SECRET not in d["body"], d["body"][:300])
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
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS pppoe-server-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
