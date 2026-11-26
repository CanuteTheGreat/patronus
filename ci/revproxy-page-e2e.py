#!/usr/bin/env python3
"""Browser check of the reverse proxy page (Reverse proxy in the menu, /svc/revproxy).

Signs in, then requires, in each browser (Firefox by default; Chromium when installed):
  1. the menu has a "Reverse proxy" entry that is not marked unavailable;
  2. the page shows every setting, the four tables (frontends, backends, servers, rules) with their forms, and the
     Publish / Check / Live statistics buttons; no JavaScript error;
  3. at phone width (390 px) the page does not scroll sideways (wide tables scroll inside their own region), in the
     light and the dark colour scheme;
  4. a frontend on the web UI's own port is refused ON THE PAGE with the explanation (nothing stored).
With E2E_WRITE=1 it also, through the page only:
  5. "Publish a LAN service" (E2E_SERVER = the LAN server address:port) creates the service, the page lists the
     frontend, backend and server, switches the feature on, and the live statistics table shows the server;
  6. "Check the configuration" reports the configuration valid;
  7. deleting the frontend through the table and switching the feature off leaves the status card saying so.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_SERVER=192.168.50.13:8080
       E2E_WEB_PORT=8443] revproxy-page-e2e.py [firefox,chromium]
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
SERVER = os.environ.get("E2E_SERVER", "192.168.50.13:8080")
WEB_PORT = os.environ.get("E2E_WEB_PORT", "8443")

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
    m = d.message
    host, port = SERVER.rsplit(":", 1)
    if "Name for the published" in m:
        d.accept("e2e-site")
    elif "LAN address" in m:
        d.accept(host)
    elif "Port of the service" in m:
        d.accept(port)
    elif "Host name clients use" in m:
        d.accept("e2e.example.test")
    elif "Public port" in m:
        d.accept("8081")
    elif "Delete this entry" in m:
        d.accept()
    else:
        d.dismiss()


def status_text(page):
    return page.locator("#svc-status").inner_text()


def no_sideways_scroll(page):
    return page.evaluate("() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")


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

    page.goto(BASE + "/svc/revproxy")
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/revproxy"]')
    check(tag + "the menu has a Reverse proxy entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))

    keys = ["enabled", "max_conn", "timeout_connect", "timeout_client", "timeout_server", "tls_min", "stats"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every setting is on the page", not missing, missing)
    for coll in ["frontends", "backends", "servers", "rules"]:
        check(tag + f"the {coll} table and its form are on the page",
              page.locator(f"[data-coll={coll}]").count() == 1 and page.locator(f"#svc-form-{coll}").count() == 1)
    labels = [b.inner_text() for b in page.locator("#svc-action-buttons button").all()]
    check(tag + "the buttons are on the page", all(any(w in l for l in labels) for w in ["Publish", "Check", "statistics"]), labels)
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])

    # phone width, both colour schemes: no sideways page scroll, wide tables scroll inside their own region
    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
        check(tag + f"phone width, {scheme}: every table sits in a scrollable, labelled region",
              page.locator(".svc-scroll[role=region][aria-label]").count() == 4, page.locator(".svc-scroll").count())
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.reload()
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)

    # a clash with the web UI port is refused on the page (the backend must exist first for the row to be complete)
    api(page, "/api/svc/revproxy/backends", "POST", {"name": "e2e-clash-be"})
    api(page, "/api/svc/revproxy/servers", "POST", {"backend": "e2e-clash-be", "name": "s", "address": "192.0.2.9", "port": 80})
    page.reload()
    page.wait_for_selector("#svc-form-frontends [name=name]")
    page.fill("#svc-form-frontends [name=name]", "e2e-clash")
    page.fill("#svc-form-frontends [name=port]", WEB_PORT)
    page.fill("#svc-form-frontends [name=default_backend]", "e2e-clash-be")
    page.click("#svc-form-frontends button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "a listener on the web UI's port is refused on the page, with the reason",
          "Not applied" in msg and "web UI" in msg and WEB_PORT in msg, msg)
    fe = api(page, "/api/svc/revproxy")["json"]["collections"]["frontends"]
    check(tag + "the refused frontend was not stored", all(r["name"] != "e2e-clash" for r in fe), fe)
    for r in api(page, "/api/svc/revproxy")["json"]["collections"]["servers"]:
        api(page, f"/api/svc/revproxy/servers/{r['id']}", "DELETE")
    for r in api(page, "/api/svc/revproxy")["json"]["collections"]["backends"]:
        api(page, f"/api/svc/revproxy/backends/{r['id']}", "DELETE")

    if WRITE:
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]")
        page.locator("#svc-action-buttons button", has_text="Publish").click()
        page.wait_for_function("() => /published/.test(document.getElementById('svc-action-result').textContent)", timeout=30000)
        d = api(page, "/api/svc/revproxy")["json"]
        check(tag + "Publish: frontend, backend and server exist and the feature is on",
              d["settings"]["enabled"] is True and len(d["collections"]["frontends"]) == 1
              and d["collections"]["backends"][0]["name"] == "e2e-site" and d["collections"]["servers"][0]["address"] == SERVER.rsplit(":", 1)[0], d)
        check(tag + "the new rows are listed in the tables on the page",
              "e2e-site" in page.locator("[data-coll=frontends]").inner_text() and "e2e-site" in page.locator("[data-coll=backends]").inner_text())
        page.wait_for_selector("#rp-stats-table", timeout=30000)
        check(tag + "live statistics: the server is in the table with a status",
              "e2e-site-1" in page.locator("#rp-stats-table").inner_text(), page.locator("#rp-stats").inner_text())
        check(tag + "the status card says the proxy runs", "running" in status_text(page).lower() and "yes" in status_text(page).lower(), status_text(page)[:300])
        page.locator("#svc-action-buttons button", has_text="Check the configuration").click()
        page.wait_for_function("() => /valid/.test(document.getElementById('svc-action-result').textContent)", timeout=30000)
        check(tag + "Check the configuration: haproxy accepts it", True)
        # delete through the table, then switch off
        page.locator("[data-coll=frontends] tr[data-id] button", has_text="Delete").first.click()
        page.wait_for_function("() => document.querySelectorAll('[data-coll=frontends] tr[data-id]').length === 0", timeout=30000)
        check(tag + "the frontend was deleted through the page", True)
        set_enabled = page.locator("#svc-settings-form [name=enabled]")
        set_enabled.set_checked(False)
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
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS revproxy-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
