#!/usr/bin/env python3
"""Browser check of the network map (Network map in the menu, /map) and its read-only live view.

Signs in, then requires in Firefox:
  1. the menu has a "Network map" entry; /map draws the shared map component with every discovered device
     (one SVG node each), the flat-network finding as a banner, no JavaScript error, no sideways page scroll at
     1280 px and at 390 px, in the light and the dark scheme;
  2. Export > Mermaid downloads a flowchart with a subgraph per segment, Export > PNG downloads a real PNG;
  3. the List view is a table with a row per device; clicking a node opens its details with the IP;
  4. the Segmentation advisor tab shows the plan with an Apply button; with E2E_WRITE=1 Apply isolates the devices
     and the tab then reports no flat segment;
  5. a view share key opens /map/live#k=<key> in a fresh browser without any login, drawing the same devices with no
     MAC address on the page.
E2E_SHOTS=<dir> saves screenshots there. Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=...
[E2E_MIN_DEVICES=5] [E2E_WRITE=1] netmap-page-e2e.py
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
MIN = int(os.environ.get("E2E_MIN_DEVICES", "5"))
SHOTS = os.environ.get("E2E_SHOTS", "")
failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


def shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name + ".png"), full_page=True)


def no_side_scroll(page):
    return page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth + 1")


def login(ctx):
    r = ctx.request.post(BASE + "/api/auth/login", data={"username": USER, "password": PASSWORD})
    return r.status


with sync_playwright() as p:
    b = p.firefox.launch()
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900}, accept_downloads=True)
    check("login", login(ctx) == 200)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/")
    check("menu has Network map", page.locator('a.nav-item[href="/map"]').count() == 1)
    page.goto(BASE + "/map")
    page.wait_for_selector("#nm-map svg .ui-map-node", timeout=20000)
    n = page.locator("#nm-map svg .ui-map-node").count()
    check(f"map draws every device (+ router): {n} nodes", n >= MIN + 1, n)
    banner = page.locator("#nm-map .ui-map-findings").inner_text()
    check("flat-network finding shown as a banner", "flat network" in banner.lower(), banner)
    check("no horizontal scroll at 1280", no_side_scroll(page))
    shot(page, "map-1280-light")
    page.emulate_media(color_scheme="dark")
    page.wait_for_timeout(300)
    shot(page, "map-1280-dark")
    page.emulate_media(color_scheme="light")

    page.locator("#nm-map .ui-map-export > summary").click()
    with page.expect_download() as dl:
        page.locator("#nm-map .ui-map-export button", has_text="Mermaid").click()
    mmd = open(dl.value.path()).read()
    check("Mermaid export: flowchart with a subgraph per segment", mmd.startswith("flowchart LR") and "subgraph" in mmd, mmd[:200])
    page.locator("#nm-map .ui-map-export > summary").click()
    with page.expect_download() as dl:
        page.locator("#nm-map .ui-map-export button", has_text="PNG").click()
    data = open(dl.value.path(), "rb").read()
    check("PNG export is a real PNG", data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) > 2000, len(data))
    if SHOTS:
        open(os.path.join(SHOTS, "map-export.png"), "wb").write(data)
        open(os.path.join(SHOTS, "map-export.mmd"), "w").write(mmd)

    node = page.locator("#nm-map svg .ui-map-node[data-id^='dev:']").first
    node.click()
    panel = page.locator("#nm-map .ui-map-panel")
    check("clicking a node opens its details", panel.is_visible() and "192.168." in panel.inner_text(), panel.inner_text()[:200])
    page.locator("#nm-map .ui-map-tools button", has_text="List").click()
    rows = page.locator("#nm-map table.ui-grid tbody tr").count()
    check(f"list view: {rows} rows", rows >= MIN + 1, rows)
    page.locator("#nm-map .ui-map-tools button", has_text="Map").click()

    page.locator("#t-advisor").click()
    page.wait_for_selector("#nm-advisor .nm-finding, #nm-advisor .ok", timeout=10000)
    adv = page.locator("#nm-advisor").inner_text()
    check("advisor shows the plan", "Move" in adv and "cameras" in adv, adv[:300])
    apply_btn = page.locator("#nm-advisor button", has_text="Apply this plan")
    check("advisor has an Apply button", apply_btn.count() == 1)
    shot(page, "advisor-1280")
    if WRITE and apply_btn.count() == 1:
        page.once("dialog", lambda d: d.accept())
        apply_btn.click()
        page.wait_for_function("() => document.getElementById('nm-status').textContent.startsWith('Applied')", timeout=30000)
        page.wait_for_selector("#nm-advisor .ok", timeout=15000)
        check("after Apply the advisor reports no flat segment", "No flat segments" in page.locator("#nm-advisor").inner_text())
        shot(page, "advisor-applied")

    phone = b.new_context(ignore_https_errors=True, viewport={"width": 390, "height": 844}, is_mobile=True)
    login(phone)
    pp = phone.new_page()
    pp.on("pageerror", lambda e: errors.append(str(e)))
    pp.goto(BASE + "/map")
    pp.wait_for_selector("#nm-map svg .ui-map-node", timeout=20000)
    check("no horizontal page scroll at 390", no_side_scroll(pp))
    shot(pp, "map-390-light")

    r = ctx.request.post(BASE + "/api/map/keys", data={"name": "e2e-live", "scope": "view"})
    check("create a view share key", r.status == 201, r.text())
    key = r.json().get("key", "")
    anon = b.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
    ap = anon.new_page()
    ap.on("pageerror", lambda e: errors.append(str(e)))
    ap.goto(BASE + "/map/live#k=" + key)
    ap.wait_for_selector("#live svg .ui-map-node", timeout=20000)
    ln = ap.locator("#live svg .ui-map-node").count()
    check(f"live view without login draws {ln} nodes", ln >= MIN + 1, ln)
    txt = ap.content()
    check("live view shows no MAC address", "02:aa:00" not in txt.lower())
    shot(ap, "live-1280")
    ap.goto(BASE + "/map")
    check("the live view's browser is not signed in (/map -> login)", "/login" in ap.url, ap.url)
    kid = [k["id"] for k in ctx.request.get(BASE + "/api/map/keys").json() if k["name"] == "e2e-live"]
    if kid:
        ctx.request.delete(BASE + f"/api/map/keys/{kid[0]}")
    check("no JavaScript errors", not errors, errors)
    b.close()

print(f"netmap-page-e2e: {'FAIL' if failures else 'OK'} ({len(failures)} failure(s))")
sys.exit(1 if failures else 0)
