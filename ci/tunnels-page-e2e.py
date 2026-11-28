#!/usr/bin/env python3
"""IP tunnels page (IPIP / 6in4 / GIF), driven in a real browser (Playwright + Firefox/Chromium).

Runs against the shipped patronus-web (see ci/netlab/lane-j-tunnels-ui.sh, where it runs in the LAN
client's namespace; the lane hands it two shell commands that look at the router and the far end of
the tunnel, so what the page does is checked in the kernel, not only on the page). Checks:
  1. the menu has an "IP tunnels" entry, every setting and every field of the tunnel and route forms
     is on the page, the live status card is filled, every control has a label;
  2. phone width (390 px) in the light and dark scheme: no sideways page scroll, every table sits in a
     labelled, scrollable region;
  3. a refused entry (uppercase name, IPv6 address on an IPIP tunnel) is explained ON THE PAGE and
     stores nothing;
  4. With E2E_WRITE=1, through the page only: add an IPIP tunnel with the form, see it in the table and
     in the live status (present, up, in sync), have the far end ping the router through it
     (E2E_FAR_CHECK), edit its MTU with the Edit button (E2E_LINK_CHECK shows the kernel MTU), add a
     route, untick "Enabled" and see the link go, delete the route and the tunnel with their Delete
     buttons.

Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_FAR=198.51.100.10
       E2E_LOCAL=203.0.113.2 E2E_FAR_CHECK='...' E2E_LINK_CHECK='...'] tunnels-page-e2e.py [firefox,chromium]
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
FAR = os.environ.get("E2E_FAR", "198.51.100.10")
LOCAL = os.environ.get("E2E_LOCAL", "")
FAR_CHECK = os.environ.get("E2E_FAR_CHECK", "")
LINK_CHECK = os.environ.get("E2E_LINK_CHECK", "")

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


def sh(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr)


def no_sideways_scroll(page):
    return page.evaluate("() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")


def wait_page(page):
    page.wait_for_selector("#svc-settings-form [name=clamp_mss]", timeout=20000)
    page.wait_for_selector("#svc-form-tunnels", timeout=20000)
    page.wait_for_selector("#svc-form-routes", timeout=20000)


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

    page.goto(BASE + "/svc/tunnels")
    wait_page(page)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/tunnels"]')
    check(tag + "the menu has an IP tunnels entry", link.count() == 1 and link.is_visible(), link.count())
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in (link.get_attribute("class") or ""))
    check(tag + "the clamp setting is on the page", page.locator("#svc-settings-form [name=clamp_mss]").count() == 1)
    tf = ["name", "kind", "remote", "local", "address", "address2", "mtu", "ttl", "default_route", "metric", "enabled", "description"]
    missing = [k for k in tf if page.locator(f"#svc-form-tunnels [name={k}]").count() != 1]
    check(tag + "every tunnel field is on the form", not missing, missing)
    rf = ["tunnel", "destination", "description"]
    missing = [k for k in rf if page.locator(f"#svc-form-routes [name={k}]").count() != 1]
    check(tag + "every route field is on the form", not missing, missing)
    kinds = page.eval_on_selector("#svc-form-tunnels [name=kind]", "e => [...e.options].map(o => o.value)")
    check(tag + "the types offered are ipip, sit and gif", sorted(kinds) == ["gif", "ipip", "sit"], kinds)
    check(tag + "the live status card is filled, not 'Loading'", "Loading" not in page.locator("#svc-status").inner_text())
    unlabeled = page.evaluate(
        """() => [...document.querySelectorAll('#svc-settings-form input, #svc-settings-form select, #svc-form-tunnels input, #svc-form-tunnels select, #svc-form-routes input')]
             .filter(e => !(e.labels && e.labels.length) && !e.getAttribute('aria-label')).map(e => e.name)""")
    check(tag + "every control has a label", not unlabeled, unlabeled)

    for scheme in ["light", "dark"]:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload()
        wait_page(page)
        check(tag + f"phone width, {scheme}: the page does not scroll sideways", no_sideways_scroll(page))
        n = page.locator(".svc-scroll[role=region][aria-label]").count()
        check(tag + f"phone width, {scheme}: every table sits in a scrollable, labelled region", n >= 2 and n == page.locator(".svc-scroll").count(), n)
    page.emulate_media(color_scheme=None)
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.reload()
    wait_page(page)

    # refused entries are explained on the page and store nothing
    page.fill("#svc-form-tunnels [name=name]", "Bad")
    page.select_option("#svc-form-tunnels [name=kind]", "ipip")
    page.fill("#svc-form-tunnels [name=remote]", FAR)
    page.click("#svc-form-tunnels button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "an uppercase name is refused on the page, with the reason", "Not applied" in msg and "lowercase" in msg, msg)
    page.reload()
    wait_page(page)
    page.fill("#svc-form-tunnels [name=name]", "bad")
    page.select_option("#svc-form-tunnels [name=kind]", "ipip")
    page.fill("#svc-form-tunnels [name=remote]", FAR)
    page.fill("#svc-form-tunnels [name=address]", "2001:db8::2/64")
    page.click("#svc-form-tunnels button[type=submit]")
    page.wait_for_selector("#svc-error", state="visible", timeout=15000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "an IPv6 address on an IPIP tunnel is refused on the page", "IPv4 only" in msg, msg)
    check(tag + "nothing was stored", api(page, "/api/svc/tunnels")["json"]["collections"]["tunnels"] == [])
    page.reload()
    wait_page(page)

    if WRITE:
        page.fill("#svc-form-tunnels [name=name]", "site")
        page.select_option("#svc-form-tunnels [name=kind]", "ipip")
        page.fill("#svc-form-tunnels [name=remote]", FAR)
        if LOCAL:
            page.fill("#svc-form-tunnels [name=local]", LOCAL)
        page.fill("#svc-form-tunnels [name=address]", "10.99.0.1/30")
        page.fill("#svc-form-tunnels [name=description]", "made on the page")
        page.click("#svc-form-tunnels button[type=submit]")
        page.wait_for_selector('[data-coll=tunnels] tr[data-id]', timeout=30000)
        check(tag + "the tunnel is in the table", "site" in page.locator("[data-coll=tunnels]").inner_text())
        page.wait_for_selector('#svc-status-tunnels tr[data-name="site"]', timeout=30000)
        st = page.locator('#svc-status-tunnels tr[data-name="site"]').inner_text()
        check(tag + "the live status lists it: link, present, up, in sync", "tn-site" in st and st.lower().count("yes") >= 3, st)
        if FAR_CHECK:
            rc, out = sh(FAR_CHECK)
            check(tag + "the far end pings the router through the tunnel the page made", rc == 0, out)
        if LINK_CHECK:
            rc, out = sh(LINK_CHECK)
            check(tag + "the kernel has the link with the stored endpoints", rc == 0 and FAR in out and "ipip" in out, out)
        # edit with the Edit button: MTU
        page.locator("[data-coll=tunnels] tr[data-id] button", has_text="Edit").first.click()
        page.fill("#svc-form-tunnels [name=mtu]", "1400")
        page.click("#svc-form-tunnels button[type=submit]")
        page.wait_for_function("() => document.querySelector('[data-coll=tunnels]').innerText.includes('1400')", timeout=30000)
        if LINK_CHECK:
            rc, out = sh(LINK_CHECK)
            check(tag + "the edited MTU is in the kernel", rc == 0 and "mtu 1400" in out, out)
        # a route
        page.fill("#svc-form-routes [name=tunnel]", "site")
        page.fill("#svc-form-routes [name=destination]", "10.77.0.0/24")
        page.click("#svc-form-routes button[type=submit]")
        page.wait_for_selector('[data-coll=routes] tr[data-id]', timeout=30000)
        check(tag + "the route is in the table", "10.77.0.0/24" in page.locator("[data-coll=routes]").inner_text())
        # untick Enabled -> the link goes
        page.locator("[data-coll=tunnels] tr[data-id] button", has_text="Edit").first.click()
        page.locator("#svc-form-tunnels [name=enabled]").set_checked(False)
        page.click("#svc-form-tunnels button[type=submit]")
        page.wait_for_function("async () => { const r = await fetch('/api/svc/tunnels', {credentials: 'same-origin'}); const j = await r.json(); return j.collections.tunnels.length === 1 && j.collections.tunnels[0].enabled === false; }", timeout=30000)
        if LINK_CHECK:
            page.wait_for_timeout(1500)
            rc, out = sh(LINK_CHECK)
            check(tag + "a disabled tunnel has no link in the kernel", rc != 0, out)
        # delete route and tunnel
        page.locator("[data-coll=routes] tr[data-id] button", has_text="Delete").first.click()
        page.wait_for_function("() => document.querySelectorAll('[data-coll=routes] tr[data-id]').length === 0", timeout=30000)
        page.locator("[data-coll=tunnels] tr[data-id] button", has_text="Delete").first.click()
        page.wait_for_function("() => document.querySelectorAll('[data-coll=tunnels] tr[data-id]').length === 0", timeout=30000)
        check(tag + "route and tunnel deleted through their Delete buttons", True)

    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS tunnels-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
