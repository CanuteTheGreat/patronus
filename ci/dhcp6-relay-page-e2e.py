#!/usr/bin/env python3
"""DHCPv6 relay page e2e (Playwright, Firefox/Chromium) against the shipped patronus-web.

Drives the page like a user and checks the result in the page and through the API:
  1. the menu has a "DHCPv6 relay" entry; every setting and the rules table and form are on the page;
  2. phone width (390 px), light and dark scheme: no sideways page scroll, the rules table sits in a labelled region;
  3. a rule with an address that is not IPv6 is refused ON THE PAGE with a reason and not stored;
  4. switching the relay on without a rule is refused on the page and the setting stays off;
  5. a good rule (clients' interface + server) is saved through the form and listed in the table;
  6. a multicast rule without the upstream interface is stored but refuses to apply, and says why;
  7. the relay is switched on through the settings form, the live status says it runs, the rule count is right;
  8. removing the last rule while the relay is on is refused on the page (the row stays), then the relay is switched
     off through the page (status: not running) and the rule deleted through the table.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... dhcp6-relay-page-e2e.py [firefox,chromium]
"""
import json
import os
import re
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
SERVER = os.environ.get("E2E_SERVER", "2001:db8:60::2")
CLIENT_IFACE = os.environ.get("E2E_IFACE", "@lan")

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


def load_page(page):
    page.goto(BASE + "/svc/dhcp6-relay")
    page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
    page.wait_for_function("() => !/Loading/.test(document.getElementById('svc-status').innerText)", timeout=15000)


def fill_rule(page, iface, server, upstream="", description=""):
    f = "#svc-form-rules "
    page.fill(f + "[name=iface]", iface)
    page.fill(f + "[name=server]", server)
    page.fill(f + "[name=upstream]", upstream)
    page.fill(f + "[name=description]", description)
    page.click(f + "button[type=submit]")


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

    load_page(page)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/dhcp6-relay"]')
    check(tag + "the menu has a DHCPv6 relay entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))
    missing = [k for k in ["enabled", "hop_limit", "interface_id", "rate_limit"]
               if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every setting is on the page", not missing, missing)
    check(tag + "the rules table and its form are on the page",
          page.locator("[data-coll=rules]").count() == 1 and page.locator("#svc-form-rules").count() == 1)
    rule_fields = [k for k in ["iface", "server", "upstream", "enabled", "description"]
                   if page.locator(f"#svc-form-rules [name={k}]").count() != 1]
    check(tag + "every rule field is in the form", not rule_fields, rule_fields)
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in status_text(page), status_text(page)[:80])
    check(tag + "the defaults are shown (hop limit 32, Interface-Id on, 500/s)",
          page.locator("#svc-settings-form [name=hop_limit]").input_value() == "32"
          and page.locator("#svc-settings-form [name=interface_id]").is_checked()
          and page.locator("#svc-settings-form [name=rate_limit]").input_value() == "500")

    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        page.wait_for_selector("#svc-settings-form [name=enabled]", timeout=15000)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
        check(tag + f"phone width, {scheme}: the rules table sits in a scrollable, labelled region",
              page.locator(".svc-scroll[role=region][aria-label]").count() == 1, page.locator(".svc-scroll").count())
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    load_page(page)

    # 3: a bad server address is refused on the page
    fill_rule(page, CLIENT_IFACE, "192.0.2.1", description="e2e-bad")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "an IPv4 server address is refused on the page, with the reason",
          "Not applied" in msg and "IPv6" in msg, msg)
    rows = api(page, "/api/svc/dhcp6-relay")["json"]["collections"]["rules"]
    check(tag + "the refused rule was not stored", all(r["description"] != "e2e-bad" for r in rows), rows)

    # 4: enabling with no rule is refused and does not stick
    load_page(page)
    page.locator("#svc-settings-form [name=enabled]").set_checked(True)
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "switching on with no rule is refused on the page, with the reason",
          "Not applied" in msg and "at least one" in msg, msg)
    check(tag + "the refused switch-on was not stored",
          api(page, "/api/svc/dhcp6-relay")["json"]["settings"]["enabled"] is False)

    # 5: a good rule through the form
    load_page(page)
    fill_rule(page, CLIENT_IFACE, SERVER, description="e2e-rule")
    page.wait_for_function("() => document.querySelectorAll('[data-coll=rules] tr[data-id]').length === 1", timeout=15000)
    table = page.locator("[data-coll=rules]").inner_text()
    check(tag + "the new rule is listed in the table", SERVER in table and "e2e-rule" in table, table)

    # 6: a multicast rule without an upstream interface stores, but cannot be applied
    fill_rule(page, CLIENT_IFACE, "ff02::1:2", description="e2e-mcast")
    page.wait_for_function("() => document.querySelectorAll('[data-coll=rules] tr[data-id]').length === 2", timeout=15000)
    page.locator("#svc-settings-form [name=enabled]").set_checked(True)
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "a multicast rule without the upstream interface is refused at apply, naming the missing field",
          "Not applied" in msg and "upstream" in msg, msg)
    load_page(page)
    for tr in page.locator("[data-coll=rules] tr[data-id]").all():
        if "e2e-mcast" in tr.inner_text():
            tr.locator("button", has_text="Delete").click()
    page.wait_for_function("() => document.querySelectorAll('[data-coll=rules] tr[data-id]').length === 1", timeout=15000)

    # 7: switch the relay on through the settings form
    load_page(page)
    page.locator("#svc-settings-form [name=enabled]").set_checked(True)
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_function("() => /running\\s*yes/i.test(document.getElementById('svc-status').innerText)", timeout=30000)
    st = status_text(page)
    check(tag + "the status says the relay is enabled and running with one rule",
          re.search(r"enabled\s*yes", st, re.I) and re.search(r"rules\s*1", st, re.I), st[:300])

    # 8: the last rule cannot be removed while the relay is on
    page.locator("[data-coll=rules] tr[data-id] button", has_text="Delete").first.click()
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "deleting the last rule of a running relay is refused on the page",
          "Not applied" in msg and "at least one" in msg, msg)
    check(tag + "the rule is still in the table", page.locator("[data-coll=rules] tr[data-id]").count() == 1)
    page.locator("#svc-settings-form [name=enabled]").set_checked(False)
    page.click("#svc-settings-form button[type=submit]")
    page.wait_for_function("() => /running\\s*no/i.test(document.getElementById('svc-status').innerText)", timeout=30000)
    check(tag + "switched off through the page: the status says it is not running", True)
    page.locator("[data-coll=rules] tr[data-id] button", has_text="Delete").first.click()
    page.wait_for_function("() => document.querySelectorAll('[data-coll=rules] tr[data-id]').length === 0", timeout=30000)
    check(tag + "the rule was deleted through the page", True)

    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS dhcp6-relay-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
