#!/usr/bin/env python3
"""Browser check of an access point's web UI: the Wi-Fi page and the access-point menu.

Signs in, then requires, in each browser (Firefox and Chromium by default):
  1. the menu shows Wi-Fi and hides the router-only entries (Routing, DHCP, DNS, Device segmentation, Traffic
     insights) on a unit whose /api/features says role "ap";
  2. /wifi shows both radios, every network of GET /api/wifi in the table (name, bands, security), no password in
     the page, and the clients table filled from /api/wifi/clients (rows or the empty state, never "Loading...");
  3. the dashboard shows the access-point uplink card (address, gateway) and System lists "Not available on this
     device" with a reason per entry;
  4. /dhcp answers with the access-point explanation, not DHCP controls;
  5. the channel plan form (channel and width per band, automatic channel lists, DFS, survey rounds) shows exactly
     GET /api/wifi's settings, and each radio card shows the channel and width the radio really runs (from hostapd),
     marked "picked automatically" when the band's channel is auto;
  6. no JavaScript error on any of these pages.
With E2E_WRITE=1 it also adds a network through the page (Add network, name, password, 5 GHz only, Save), requires
the page to report success and GET /api/wifi to list it, then removes it again through the page and requires the
original network list back. That restarts the unit's radios twice (clients reconnect within seconds). E2E_CHAN=1 changes the channel plan through
the page (2.4 GHz automatic channels "1 6", 4 survey rounds), requires the API to show it and the 2.4 GHz radio to come
back on channel 1 or 6, refuses a malformed channel list without saving, then restores the original plan (two more
radio restarts).

Usage: BASE_URL=https://192.0.2.10 E2E_USER=admin E2E_PASSWORD=... wifi-page-e2e.py [firefox,chromium]
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
CHAN = os.environ.get("E2E_CHAN") == "1"
TEST_SSID = os.environ.get("E2E_TEST_SSID", "pat-e2e-test")
TEST_KEY = os.environ.get("E2E_TEST_KEY", "e2e-test-key-123")
ROUTER_ONLY = ["/routing", "/dhcp", "/dns", "/segmentation", "/insights"]

failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


def api(page, path, method="GET", body=None):
    return page.evaluate(
        """async ([p, m, b]) => { const r = await fetch(p, {method: m, credentials: 'same-origin',
             headers: b ? {'content-type': 'application/json'} : {}, body: b ? JSON.stringify(b) : undefined});
             return {status: r.status, body: await r.text()}; }""",
        [path, method, body],
    )


def visible_nav(page):
    return page.evaluate(
        """() => [...document.querySelectorAll('.sidebar-nav a.nav-item')]
              .filter(a => a.offsetParent !== null).map(a => a.getAttribute('href'))"""
    )


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
    feats = json.loads(api(page, "/api/features")["body"])
    ap = feats.get("role") == "ap"
    check(f"{kind}: /api/features has a Wi-Fi backend", feats.get("wifi_backend") is True, feats)

    page.goto(BASE + "/wifi")
    page.wait_for_selector("#wifi-main", state="visible", timeout=30000)
    page.wait_for_function("() => !document.querySelector('#wifi-clients tbody').innerText.includes('Loading')", timeout=60000)
    nav = visible_nav(page)
    check(f"{kind}: menu shows Wi-Fi", "/wifi" in nav, nav)
    if ap:
        check(f"{kind}: menu hides the router-only entries on an access point", not any(r in nav for r in ROUTER_ONLY), nav)
    cfg = json.loads(api(page, "/api/wifi")["body"])
    rows = page.evaluate("""() => [...document.querySelectorAll('#wifi-networks tbody tr.wifi-net')].map(tr => ({
        ssid: tr.querySelector('[name=ssid]').value, bands: tr.querySelector('[name=bands]').value,
        security: tr.querySelector('[name=security]').value, enabled: tr.querySelector('[name=enabled]').checked}))""")
    want = [{"ssid": n["ssid"], "bands": n["bands"], "security": n["security"], "enabled": n["enabled"]} for n in cfg["config"]["networks"]]
    check(f"{kind}: networks table = GET /api/wifi", rows == want, {"page": rows, "api": want})
    radios = page.locator("#wifi-radios .card").count()
    check(f"{kind}: both radios shown", radios == 2, radios)
    html = page.content()
    check(f"{kind}: no password in the page", "KEY_" not in html and "wpa_passphrase" not in html)
    form = page.evaluate("""() => { const f = document.getElementById('wifi-radio-form'); const l = v => v.split(/\s+/).filter(x => x).map(Number);
        return {chan24: f.chan24.value, chan5: f.chan5.value, width24: Number(f.width24.value), width5: Number(f.width5.value),
                dfs: f.dfs.checked, chanlist24: l(f.chanlist24.value), chanlist5: l(f.chanlist5.value), acs_scans: Number(f.acs_scans.value)}; }""")
    c = cfg["config"]
    want_plan = {k: c.get(k) for k in ("chan24", "chan5", "width24", "width5", "dfs", "chanlist24", "chanlist5", "acs_scans")}
    check(f"{kind}: channel plan form = GET /api/wifi", form == want_plan, {"page": form, "api": want_plan})
    cards = page.evaluate("() => [...document.querySelectorAll('#wifi-radios .radio-chan')].map(d => [d.dataset.band, d.innerText])")
    ok_cards = len(cards) == 2
    for band, text in cards:
        r = next((x for x in cfg["radios"] if x["band"] == band), {})
        auto = c["chan5" if band == "5" else "chan24"] == "auto"
        if r.get("state") == "ENABLED":
            ok_cards &= f"channel {r['channel']} " in text and f"{r.get('width_mhz')} MHz wide" in text \
                and (("picked automatically" in text) == auto)
    check(f"{kind}: radio cards show the live channel and width (auto marked)", ok_cards, {"cards": cards, "radios": cfg["radios"]})
    clients = page.locator("#wifi-clients tbody tr").count()
    check(f"{kind}: clients table filled", clients >= 1, clients)
    page.screenshot(path=f"wifi-{kind}.png", full_page=True)

    if ap:
        page.goto(BASE + "/")
        page.wait_for_selector("#ap-uplink", state="visible", timeout=30000)
        summ = page.inner_text("#ap-uplink-summary")
        check(f"{kind}: dashboard uplink card (address + gateway)", "Address" in summ and "gateway" in summ, summ)
        page.goto(BASE + "/dhcp")
        check(f"{kind}: /dhcp explains the access point", "This unit is an access point" in page.content())
    page.goto(BASE + "/system")
    page.wait_for_selector("#not-available", state="visible", timeout=30000)
    n = page.locator("#not-available-list tr").count()
    check(f"{kind}: System lists what is not available, with reasons", n == len(feats.get("absent", [])) and n > 0, n)

    if WRITE:
        before = [x["ssid"] for x in cfg["config"]["networks"]]
        page.goto(BASE + "/wifi")
        page.wait_for_selector("#wifi-main", state="visible", timeout=30000)
        page.click("text=Add network")
        last = page.locator("#wifi-networks tbody tr.wifi-net").last
        last.locator("[name=ssid]").fill(TEST_SSID)
        last.locator("[name=key]").fill(TEST_KEY)
        last.locator("[name=bands]").select_option("5")
        last.locator("[name=hidden]").check()
        page.click("#wifi-save")
        page.wait_for_function("() => document.querySelector('#wifi-save').textContent.startsWith('Save')", timeout=120000)
        msg = page.inner_text("#wifi-msg")
        check(f"{kind}: add network through the page", "Saved" in msg or "saved" in msg, msg)
        after = [x["ssid"] for x in json.loads(api(page, "/api/wifi")["body"])["config"]["networks"]]
        check(f"{kind}: new network listed by the API", after == before + [TEST_SSID], after)
        page.reload()
        page.wait_for_selector("#wifi-main", state="visible", timeout=30000)
        page.locator("#wifi-networks tbody tr.wifi-net").last.locator("text=Remove").click()
        page.click("#wifi-save")
        page.wait_for_function("() => document.querySelector('#wifi-save').textContent.startsWith('Save')", timeout=120000)
        final = [x["ssid"] for x in json.loads(api(page, "/api/wifi")["body"])["config"]["networks"]]
        check(f"{kind}: removed again, original networks back", final == before, final)
    if CHAN:
        orig = json.loads(api(page, "/api/wifi")["body"])["config"]
        page.goto(BASE + "/wifi")
        page.wait_for_selector("#wifi-main", state="visible", timeout=30000)
        page.fill("[name=chanlist24]", "1 x")
        page.click("#wifi-save")
        msg = page.inner_text("#wifi-msg")
        same = json.loads(api(page, "/api/wifi")["body"])["config"]
        check(f"{kind}: a malformed channel list is refused, nothing saved", "channel numbers" in msg and same == orig, msg)

        def save_plan(ch24, list24, scans):
            page.goto(BASE + "/wifi")
            page.wait_for_selector("#wifi-main", state="visible", timeout=30000)
            page.select_option("[name=chan24]", ch24)
            page.fill("[name=chanlist24]", list24)
            page.fill("[name=acs_scans]", str(scans))
            page.click("#wifi-save")
            page.wait_for_function("() => document.querySelector('#wifi-save').textContent.startsWith('Save')", timeout=180000)
            return page.inner_text("#wifi-msg")

        msg = save_plan("auto", "1 6", 4)
        got = json.loads(api(page, "/api/wifi")["body"])
        r24 = next((x for x in got["radios"] if x["band"] == "24"), {})
        check(f"{kind}: channel plan saved through the page", "Saved" in msg and got["config"]["chanlist24"] == [1, 6]
              and got["config"]["acs_scans"] == 4 and got["config"]["chan24"] == "auto", {"msg": msg, "config": got["config"]})
        check(f"{kind}: 2.4 GHz radio came back on a channel from the list (ACS)", r24.get("state") == "ENABLED" and r24.get("channel") in ("1", "6"), r24)
        msg = save_plan(orig["chan24"], " ".join(str(x) for x in orig["chanlist24"]), orig["acs_scans"])
        back = json.loads(api(page, "/api/wifi")["body"])["config"]
        check(f"{kind}: original channel plan restored", back == orig and "Saved" in msg, {"msg": msg, "back": back, "orig": orig})
    check(f"{kind}: no JavaScript errors", not errors, errors)
    browser.close()


with sync_playwright() as p:
    for k in (sys.argv[1] if len(sys.argv) > 1 else "firefox,chromium").split(","):
        run(p, k)
print("FAILED: " + (", ".join(failures) if failures else "none"))
sys.exit(1 if failures else 0)
