#!/usr/bin/env python3
"""Browser check of the router-tier device settings: the Wi-Fi page's additions and the Device page.

Signs in, then requires, in each browser (Firefox and Chromium by default):
  1. /wifi shows the crash-protection state from GET /api/wifi (wifi-guard: normal / safe mode), the guest-filter
     availability sentence, a Guest column whose boxes match each network's `guest` flag, the transmit-power selects
     with the stored values, the "Blocked devices" table matching the unit-wide + per-network block lists, a Name
     column in the clients table, and the channel-survey card filled (radios or the "nothing to survey" note);
  2. the menu shows "Device" on a router-tier unit; /device shows the SSH-key table per login account (fingerprints
     as in GET /api/device/ssh-keys), the lights state (or "Not available on this device" with the reason), the
     scheduled-restart state with the unit's real enabled/active state, and (access point) the address card;
  3. System > Firmware has the online update check with the release-key fingerprint;
  4. no JavaScript error on these pages.
With E2E_WRITE=1 (test units only, never a house access point) it also, through the pages:
  - blocks a test MAC on every network (form), requires it in the table and GET /api/wifi, unblocks it (button);
  - adds a test SSH key to root, requires it in the table, removes it again (confirm dialog);
  - sets a weekly restart, requires the unit shown enabled, switches it off again and requires it disabled.
None of these restart the radios.

Usage: BASE_URL=https://192.0.2.10 E2E_USER=admin E2E_PASSWORD=... device-page-e2e.py [firefox,chromium]
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
TEST_MAC = os.environ.get("E2E_TEST_MAC", "02:e2:e0:00:00:01")
TEST_KEY = os.environ.get(
    "E2E_TEST_KEY",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZCN3GeRyG77PKWc5YUW/XNmwrh e2e-device-page",
)

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


def wait_text(page, sel, timeout=30000):
    page.wait_for_function(
        """(s) => { const e = document.querySelector(s); return e && e.textContent.trim() && !/Loading|checking/.test(e.textContent); }""",
        arg=sel,
        timeout=timeout,
    )
    return page.text_content(sel).strip()


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", lambda d: d.accept())
    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
    tag = f"[{kind}] "

    feats = api(page, "/api/features")["json"] or {}
    embedded = feats.get("tier") == "embedded"
    ap = feats.get("role") == "ap"

    # ---- 1. Wi-Fi page
    if feats.get("wifi_backend"):
        page.goto(BASE + "/wifi")
        page.wait_for_selector("#wifi-main", state="visible", timeout=30000)
        w = api(page, "/api/wifi")["json"]
        cfg = w["config"]
        guard = w.get("guard")
        gtxt = wait_text(page, "#wifi-guard")
        if guard is None:
            check(tag + "Wi-Fi: no crash protection in this firmware -> said so", "not part of this firmware" in gtxt, gtxt)
        elif guard.get("mode") == "safe-mode":
            check(tag + "Wi-Fi: safe mode shown with what is off", "Safe mode" in gtxt and "first network" in gtxt, gtxt)
        else:
            mode = page.get_attribute("#wifi-guard-mode", "data-mode")
            check(tag + "Wi-Fi: crash protection mode shown as the API reports it", mode == guard.get("mode") and "Crash protection" in gtxt, (mode, gtxt, guard))
        gf = w.get("guest_filter") or {}
        how = page.text_content("#wifi-guest-how")
        check(tag + "Wi-Fi: guest-filter availability explained", ("filters guest traffic" in how) if gf.get("available") else ("NOT available" in how and (gf.get("reason") or "") in how), (how, gf))
        rows = page.eval_on_selector_all(
            "#wifi-networks tbody tr.wifi-net",
            "rs => rs.map(r => ({id: r.dataset.id, guest: r.querySelector('[name=guest]').checked}))",
        )
        want = [{"id": n["id"], "guest": bool(n.get("guest"))} for n in cfg["networks"]]
        check(tag + "Wi-Fi: Guest column matches each network's guest flag", rows == want, (rows, want))
        tx = (page.input_value("[name=txpower24]"), page.input_value("[name=txpower5]"))
        check(tag + "Wi-Fi: transmit power selects show the stored values", tx == (str(cfg.get("txpower24", "auto")), str(cfg.get("txpower5", "auto"))), (tx, cfg.get("txpower24"), cfg.get("txpower5")))
        blocked = page.eval_on_selector_all("#wifi-blocked tbody tr.wifi-blocked td.mono", "es => es.map(e => e.textContent)")
        wantb = sorted(cfg.get("blocked", []) + [m for n in cfg["networks"] for m in n.get("blocked", [])])
        check(tag + "Wi-Fi: Blocked devices table = unit-wide + per-network lists", sorted(blocked) == wantb, (blocked, wantb))
        heads = page.eval_on_selector_all("#wifi-clients thead th", "es => es.map(e => e.textContent)")
        check(tag + "Wi-Fi: clients table has a Name column", heads[:1] == ["Name"], heads)
        page.wait_for_function("() => !/Loading/.test(document.querySelector('#wifi-clients tbody').textContent)", timeout=30000)
        cl = api(page, "/api/wifi/clients")["json"].get("clients", [])
        shown = page.eval_on_selector_all("#wifi-clients tbody tr.wifi-client", "rs => rs.map(r => [r.children[1].textContent, r.children[0].textContent])")
        names = {c["mac"]: c.get("hostname", "") for c in cl}
        bad = [s for s in shown if names.get(s[0], "") != s[1]]
        check(tag + "Wi-Fi: each client's name is the API's (blank when unknown, never invented)", not bad, bad)
        sv = wait_text(page, "#wifi-survey", 60000)
        s = api(page, "/api/wifi/survey")["json"]
        ok = (("nothing to survey" in sv) if not s["radios"] else all(("now channel" in sv or "GHz" in sv) for _ in s["radios"]))
        check(tag + "Wi-Fi: channel survey card filled from the API", ok, (sv[:300], s))
        if WRITE:
            page.fill("#wifi-block-form [name=mac]", TEST_MAC)
            page.select_option("#wifi-block-form [name=network]", "")
            page.click("#wifi-block-form button")
            page.wait_for_function("(m) => [...document.querySelectorAll('#wifi-blocked td.mono')].some(e => e.textContent === m)", arg=TEST_MAC, timeout=30000)
            g = api(page, "/api/wifi")["json"]["config"]
            check(tag + "Wi-Fi (write): block through the form -> listed and in GET /api/wifi", TEST_MAC in g.get("blocked", []), g.get("blocked"))
            page.click(f"#wifi-blocked tr.wifi-blocked:has(td.mono:text-is('{TEST_MAC}')) button")
            page.wait_for_function("(m) => ![...document.querySelectorAll('#wifi-blocked td.mono')].some(e => e.textContent === m)", arg=TEST_MAC, timeout=30000)
            g = api(page, "/api/wifi")["json"]["config"]
            check(tag + "Wi-Fi (write): Unblock button removes it", TEST_MAC not in g.get("blocked", []), g.get("blocked"))
        check(tag + "Wi-Fi page: no JavaScript error", not errors, errors)
        errors.clear()

    # ---- 2. Device page
    page.goto(BASE + "/")
    page.wait_for_load_state("networkidle")
    vis = page.evaluate("() => { const a = document.getElementById('nav-device'); return !!a && a.offsetParent !== null; }")
    check(tag + "menu: Device shown on a router-tier unit (and only there)", vis == embedded, (vis, feats.get("tier")))
    dg = page.evaluate("() => [...document.querySelectorAll('.sidebar-nav a.nav-item')].some(a => a.getAttribute('href') === '/diagnostics' && a.offsetParent !== null)")
    check(tag + "menu: Diagnostics visible (also on an access point)", dg, feats.get("role"))
    page.goto(BASE + "/device")
    page.wait_for_load_state("networkidle")
    keys = api(page, "/api/device/ssh-keys")["json"]
    try:
        page.wait_for_selector("#keys table.keys", timeout=30000)
    except Exception as e:  # an older firmware has no Device page
        check(tag + "Device page: SSH key tables shown", False, e)
        browser.close()
        return
    fps = page.eval_on_selector_all("#keys table.keys", "ts => ts.map(t => [t.dataset.user, [...t.querySelectorAll('td.dev-key')].map(e => e.textContent)])")
    # every key line is a row, also one the page does not manage (no fingerprint, shown with the reason, no Remove)
    want = [[u["user"], [k["fingerprint"] for k in u["keys"]]] for u in keys["users"]]
    check(tag + "Device: SSH keys per account as the API lists them", fps == want, (fps, want))
    leds = api(page, "/api/device/leds")["json"]
    lt = wait_text(page, "#leds-state")
    check(tag + "Device: lights state (or why not available)", ("Not available on this device" in lt and leds["reason"] in lt) if not leds["available"] else ("Lights are " + leds["setting"]) in lt, (lt, leds))
    rs = api(page, "/api/device/restart-schedule")["json"]
    rt = wait_text(page, "#rs-state")
    u = rs.get("unit", {})
    check(tag + "Device: scheduled restart shows the unit's real state", (u.get("enabled", "?") in rt and u.get("active", "?") in rt and (rs["mode"] == "off") == rt.startswith("Off")), (rt, rs))
    check(tag + "Device: address card on an access point (only there)", page.is_visible("#addr-card") == ap, ap)
    if WRITE:
        page.select_option("#key-form [name=user]", "root")
        page.fill("#key-form [name=key]", TEST_KEY)
        page.click("#key-form button")
        page.wait_for_function("() => /Key added/.test(document.getElementById('dev-msg').textContent)", timeout=30000)
        k = [x for x in api(page, "/api/device/ssh-keys")["json"]["users"] if x["user"] == "root"][0]["keys"]
        mine = [x for x in k if x["comment"] == TEST_KEY.split()[-1]]
        check(tag + "Device (write): key added through the page", len(mine) == 1, k)
        if mine:
            fp = mine[0]["fingerprint"]
            page.click(f"#keys table.keys[data-user=root] tr.key-row:has(td.dev-key:text-is('{fp}')) button")
            page.wait_for_function("() => /Key removed|Not removed/.test(document.getElementById('dev-msg').textContent)", timeout=30000)
            k = [x for x in api(page, "/api/device/ssh-keys")["json"]["users"] if x["user"] == "root"][0]["keys"]
            check(tag + "Device (write): key removed through the page", all(x["fingerprint"] != fp for x in k), k)
        if rs.get("available"):
            page.select_option("#rs-form [name=mode]", "weekly")
            page.select_option("#rs-form [name=day]", "wed")
            page.fill("#rs-form [name=time]", "03:17")
            page.click("#restart-card button.btn-primary")
            page.wait_for_function("() => /On: every wed/.test(document.getElementById('rs-state').textContent)", timeout=30000)
            r2 = api(page, "/api/device/restart-schedule")["json"]
            check(tag + "Device (write): weekly restart -> unit enabled and active", r2["unit"].get("enabled") == "enabled" and r2["unit"].get("active") == "active", r2)
            page.select_option("#rs-form [name=mode]", "off")
            page.click("#restart-card button.btn-primary")
            page.wait_for_function("() => /^Off/.test(document.getElementById('rs-state').textContent)", timeout=30000)
            r3 = api(page, "/api/device/restart-schedule")["json"]
            check(tag + "Device (write): off -> unit disabled", r3["mode"] == "off" and r3["unit"].get("enabled") == "disabled", r3)
    check(tag + "Device page: no JavaScript error", not errors, errors)
    errors.clear()

    # ---- 3. System > Firmware: online check
    if embedded:
        page.goto(BASE + "/system")
        page.wait_for_selector("#firmware-card", state="visible", timeout=30000)
        txt = page.text_content("#firmware-card")
        check(tag + "System: online update check with the release-key fingerprint", "Check for updates" in txt and "AC0A 6506" in txt, txt[:300])
        check(tag + "System page: no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox,chromium").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print("FAILED: " + (", ".join(failures) if failures else "none"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
