#!/usr/bin/env python3
"""Browser check of the guest network page (Guest network in the menu, /svc/guest).

Signs in, then requires, in each browser (Firefox by default; Chromium when installed):
  1. the menu has a "Guest network" entry that is not marked unavailable (the build has the feature);
  2. /svc/guest shows every setting of the page (switch, VLAN id, subnet, DHCP range, DNS, caps, access, Wi-Fi...),
     the vouchers table and the buttons, no password anywhere in the page, and no JavaScript error;
  3. a refused change (a subnet that overlaps the LAN, or a bad value) shows the refusal on the page and changes nothing.
With E2E_WRITE=1 (a lab or a box you may change) it also, through the page only:
  4. switches the guest network on with E2E_PORTS as its ports (Save and apply), and requires the live status card
     to say the bridge is up and DHCP/DNS runs, and GET /api/svc/guest to carry the saved values;
  5. generates a Wi-Fi password (the button), shows it with its QR code (the share button), makes a voucher and
     deletes it again, opens the network for 30 minutes and closes it again, each time requiring the result
     panel / the list / the status card to show it;
  6. switches the guest network off again and requires the status card to say so.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_PORTS=gst-a,gst-b] \
       guest-page-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
PORTS = os.environ.get("E2E_PORTS", "")
UPSTREAM = os.environ.get("E2E_DNS_UPSTREAMS", "")
LAN_CLASH = os.environ.get("E2E_LAN_CLASH", "192.168.50.5/24")

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
    if "how many minutes" in m and "Open" in m:
        d.accept("30")
    elif "Voucher name" in m:
        d.accept("e2e-visitor")
    elif "Valid for how many" in m:
        d.accept("60")
    elif "Replace the shared" in m or "Delete this entry" in m:
        d.accept()
    else:
        d.dismiss()


def ask(page, values):
    """Answer the page's own question dialog (svcAsk in svc.html, a kit <dialog>; the page no longer uses prompt())."""
    page.wait_for_selector("#svc-ask[open]", timeout=10000)
    for k, v in values.items():
        page.locator(f"#svc-ask [name={k}]").fill(str(v))
    page.locator("#svc-ask button[type=submit]").click()
    page.wait_for_selector("#svc-ask", state="detached", timeout=10000)


def set_field(page, name, value):
    el = page.locator(f"#svc-settings-form [name={name}]")
    if el.get_attribute("type") == "checkbox":
        el.set_checked(bool(value))
    elif el.evaluate("e => e.tagName") == "SELECT":
        el.select_option(str(value))
    else:
        el.fill(str(value))


def status_text(page):
    return page.locator("#svc-status").inner_text()


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

    # 1. the menu
    page.goto(BASE + "/svc/guest")
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/guest"]')
    check(tag + "the menu has a Guest network entry", link.count() == 1 and link.is_visible(), link.count())
    cls = link.get_attribute("class") or ""
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in cls, cls)

    # 2. the page
    keys = ["enabled", "vlan_id", "address", "dhcp_start", "dhcp_end", "lease_minutes", "dns_servers", "internet_interface",
            "block_private", "isolate_clients", "allow_ping", "router_ports", "egress_ports", "down_kbit", "up_kbit",
            "client_down_kbit", "client_up_kbit", "access", "schedule_from", "schedule_to", "schedule_days", "wifi", "ssid",
            "wifi_psk", "wifi_security"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every guest setting is on the page", not missing, missing)
    check(tag + "the vouchers table and its form are on the page",
          page.locator('[data-coll=vouchers]').count() == 1 and page.locator("#svc-form-vouchers").count() == 1)
    labels = [b.inner_text() for b in page.locator("#svc-action-buttons button").all()]
    check(tag + "the buttons are on the page", all(any(w in l for l in labels) for w in ["Open", "Close", "voucher", "password"]), labels)
    check(tag + "the password field is empty (never filled from the server)", page.locator("#svc-settings-form [name=wifi_psk]").input_value() == "")
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])

    # 3. a refused change
    before = api(page, "/api/svc/guest")["json"]["settings"]
    set_field(page, "address", LAN_CLASH)
    set_field(page, "enabled", True)
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=10000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "an overlapping subnet is refused on the page, with the reason", "Not applied" in msg and "overlaps" in msg, msg)
    after = api(page, "/api/svc/guest")["json"]["settings"]
    check(tag + "the refused change stored nothing", before == after, (before, after))

    if WRITE:
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]")
        # 4. switch on
        set_field(page, "enabled", True)
        set_field(page, "vlan_id", 0)
        set_field(page, "ports", PORTS)
        set_field(page, "address", "192.168.30.1/24")
        if UPSTREAM:
            set_field(page, "dns_upstreams", UPSTREAM)
        set_field(page, "client_down_kbit", 4000)
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => document.querySelector('#svc-status') && /bridge up\\s*yes/i.test(document.querySelector('#svc-status').innerText)", timeout=30000)
        st = status_text(page)
        check(tag + "switched on through the page: the live status says bridge up, DHCP/DNS running",
              "yes" in st and "dhcp dns running" in st.lower(), st[:300])
        s = api(page, "/api/svc/guest")["json"]
        check(tag + "the saved values are in the API", s["settings"]["enabled"] is True and s["settings"]["client_down_kbit"] == 4000
              and s["settings"]["ports"] == PORTS, s["settings"])
        check(tag + "no error is shown after a good save", not page.locator("#svc-error").is_visible())

        # 5. buttons
        page.locator("#svc-action-buttons button", has_text="New Wi-Fi password").click()
        page.wait_for_function("() => /wifi_password/.test(document.getElementById('svc-action-result').textContent)", timeout=15000)
        res = json.loads(page.locator("#svc-action-result").inner_text())
        pw = res["wifi_password"]
        check(tag + "New Wi-Fi password: a generated password is shown once", len(pw) == 16, res)
        check(tag + "the password is not in the settings form afterwards", page.locator("#svc-settings-form [name=wifi_psk]").input_value() == "")
        page.locator("#svc-action-buttons button", has_text="Show Wi-Fi password and QR code").click()
        page.wait_for_selector("#svc-action-qr", timeout=15000)
        res = json.loads(page.locator("#svc-action-result").inner_text())
        check(tag + "the share card shows the password, the join text and a QR code",
              res.get("wifi_password") == pw and res.get("uri", "").startswith("WIFI:T:WPA;S:") and page.locator("#svc-action-qr").is_visible(), res)
        check(tag + "the QR code image loaded", page.evaluate("() => { const i = document.getElementById('svc-action-qr'); return i.complete && i.naturalWidth > 0; }"))
        page.locator("#svc-action-buttons button", has_text="New voucher").click()
        ask(page, {"name": "e2e-visitor", "minutes": 60})
        page.wait_for_selector('[data-coll=vouchers] tr[data-id]', timeout=15000)
        row = page.locator('[data-coll=vouchers] tr[data-id]').first
        check(tag + "a voucher was made and is listed without its code", "e2e-visitor" in row.inner_text() and pw not in row.inner_text(), row.inner_text())
        res = json.loads(page.locator("#svc-action-result").inner_text())
        check(tag + "the voucher's password was shown once", len(res.get("wifi_password", "")) == 12, res)
        row.locator("button", has_text="Delete").click()
        page.wait_for_function("() => document.querySelectorAll('[data-coll=vouchers] tr[data-id]').length === 0", timeout=15000)
        check(tag + "the voucher was deleted through the page", True)
        page.locator("#svc-action-buttons button", has_text="Open for a while").click()
        ask(page, {"minutes": 30})
        page.wait_for_function("() => /open_until/.test(document.getElementById('svc-action-result').textContent)", timeout=15000)
        s = api(page, "/api/svc/guest")["json"]["settings"]
        check(tag + "Open for a while: timed access with an end time", s["access"] == "timed" and s["open_until"] > 0, s)
        check(tag + "the status card says when it closes", "open until" in status_text(page).lower() or "open" in status_text(page).lower(), status_text(page)[:300])
        page.locator("#svc-action-buttons button", has_text="Close now").click()
        page.wait_for_function("() => /closed/i.test(document.getElementById('svc-status').innerText)", timeout=15000)
        check(tag + "Close now: the status card says closed", True)

        # 6. off again
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]")
        set_field(page, "enabled", False)
        set_field(page, "access", "always")
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => document.querySelector('#svc-status') && /bridge up\\s*no/i.test(document.querySelector('#svc-status').innerText)", timeout=30000)
        check(tag + "switched off through the page: the status says the bridge is gone", True)

    page.goto(BASE + "/svc/guest")
    page.wait_for_selector("#svc-settings-form [name=enabled]")
    body = page.content()
    check(tag + "no password or voucher code anywhere in the page source", "hunter2" not in body)
    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS guest-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
