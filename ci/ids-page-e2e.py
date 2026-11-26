#!/usr/bin/env python3
"""Browser check of the intrusion detection pages (/svc/ids and /svc/ids/alerts).

Signs in, then requires, in each browser (Firefox by default; Chromium when installed):
  1. the menu has an "Intrusion detection" entry that is not marked unavailable;
  2. /svc/ids shows every setting (mode, interface, protected networks, update window, retention), the collections
     (rule sets, policy, overrides, suppress/threshold, interfaces, own rules), the seeded rule sets with their
     licence, the "Update rule sets now" button, the rule-set status table and the link to the alert browser;
  3. a refused entry (an ftp:// source URL) shows the refusal on the page and stores nothing;
  4. /svc/ids/alerts shows the filter form, the top lists and the (maybe empty) alert table, and at 390 px wide, in the
     light and the dark scheme, neither page scrolls sideways.
With E2E_WRITE=1 (a netlab router with Suricata and a local rule source: E2E_SOURCE_URL, E2E_PROBE_URL) it also,
through the pages only:
  5. adds a rule set (form), presses "Update rule sets now" and requires the status table to say it was downloaded;
  6. adds a policy (form) and changes a setting (retention) and requires both in the API;
  7. makes matching traffic, finds the alert in the alert browser by SID, shows it in the top lists, and suppresses
     the rule with one click; the entry shows up on the settings page and is deleted there again.

Usage: BASE_URL=https://192.0.2.1 E2E_USER=admin E2E_PASSWORD=... [E2E_WRITE=1 E2E_SOURCE_URL=... E2E_PROBE_URL=...] \
       ids-page-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import json
import os
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
WRITE = os.environ.get("E2E_WRITE") == "1"
SOURCE_URL = os.environ.get("E2E_SOURCE_URL", "")
PROBE_URL = os.environ.get("E2E_PROBE_URL", "")
SID = os.environ.get("E2E_SID", "2900001")

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
    d.accept()


def login(page):
    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)


def fill_form(page, form_sel, values):
    for k, v in values.items():
        el = page.locator(f"{form_sel} [name={k}]")
        if el.get_attribute("type") == "checkbox":
            el.set_checked(bool(v))
        elif el.evaluate("e => e.tagName") == "SELECT":
            el.select_option(str(v))
        else:
            el.fill(str(v))


def sideways(page):
    return page.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")


def luminance_of_background(page):
    return page.evaluate(
        """() => { const c = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number);
                   return (c[0] + c[1] + c[2]) / 3; }"""
    )


def responsive(browser, kind):
    tag = f"[{kind}] "
    for scheme in ("light", "dark"):
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 390, "height": 844}, color_scheme=scheme)
        page = ctx.new_page()
        errs = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        login(page)
        for path, sel, ready in (
            ("/svc/ids", "#svc-settings-form [name=mode]", "() => !/Loading/.test(document.getElementById('svc-status').innerText)"),
            ("/svc/ids/alerts", "#ids-filter", "() => !/Loading/.test(document.getElementById('ids-rows').innerText)"),
        ):
            page.goto(BASE + path)
            page.wait_for_selector(sel, timeout=15000)
            page.wait_for_function(ready, timeout=15000)
            over = sideways(page)
            check(tag + f"{path} at 390 px ({scheme}): the page does not scroll sideways", over <= 1, over)
            lum = luminance_of_background(page)
            check(tag + f"{path} ({scheme}): the page follows the device scheme", (lum < 100) == (scheme == "dark"), lum)
        check(tag + f"no JavaScript error at 390 px ({scheme})", not errs, errs)
        ctx.close()


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 1000})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", on_dialog)
    tag = f"[{kind}] "
    login(page)

    # 1. menu
    page.goto(BASE + "/svc/ids")
    page.wait_for_selector("#svc-settings-form [name=mode]", timeout=15000)
    link = page.locator('.sidebar-nav a.nav-item[href="/svc/ids"]')
    check(tag + "the menu has an Intrusion detection entry", link.count() == 1 and link.is_visible(), link.count())
    cls = link.get_attribute("class") or ""
    check(tag + "the entry is not marked unavailable", "nav-unavailable" not in cls, cls)

    # 2. the page
    keys = ["enabled", "mode", "interface", "home_net", "distro_rules", "update_enabled", "update_hour",
            "update_window_hours", "update_interval_hours", "alert_retention_days", "alert_max_rows"]
    missing = [k for k in keys if page.locator(f"#svc-settings-form [name={k}]").count() != 1]
    check(tag + "every IDS setting is on the page", not missing, missing)
    colls = ["sources", "policies", "overrides", "suppress", "interfaces", "rules"]
    miss = [c for c in colls if page.locator(f"[data-coll={c}]").count() != 1]
    check(tag + "every collection is on the page (rule sets, policy, overrides, suppress, interfaces, own rules)", not miss, miss)
    src_text = page.locator("[data-coll=sources]").inner_text()
    check(tag + "the rule sets are listed with name and licence", "Emerging Threats Open" in src_text and "CC0-1.0" in src_text, src_text[:300])
    btn = [b.inner_text() for b in page.locator("#svc-action-buttons button").all()]
    check(tag + "the Update rule sets now button is on the page", any("Update rule sets" in b for b in btn), btn)
    check(tag + "the alert browser is linked", page.locator("#ids-alerts-link").get_attribute("href") == "/svc/ids/alerts")
    page.wait_for_function("() => document.querySelector('#svc-status') && !/Loading/.test(document.querySelector('#svc-status').innerText)", timeout=15000)
    st = page.locator("#svc-status").inner_text()
    check(tag + "the status shows the rule-set table", "Rule set" in st and "Licence" in st, st[:300])

    # 3. a refused entry
    before = api(page, "/api/svc/ids")["json"]["collections"]["sources"]
    fill_form(page, "#svc-form-sources", {"key": "bad1", "name": "Bad", "url": "ftp://nowhere.example/x.tar.gz"})
    page.locator("#svc-form-sources button[type=submit]").click()
    page.wait_for_selector("#svc-error", state="visible", timeout=10000)
    msg = page.locator("#svc-error").inner_text()
    check(tag + "an ftp:// URL is refused on the page, with the reason", "Not applied" in msg and "http" in msg, msg)
    after = api(page, "/api/svc/ids")["json"]["collections"]["sources"]
    check(tag + "the refused entry stored nothing", before == after, (before, after))

    # 4. the alert browser
    page.goto(BASE + "/svc/ids/alerts")
    page.wait_for_selector("#ids-filter", timeout=15000)
    page.wait_for_function("() => !/Loading/.test(document.getElementById('ids-rows').innerText)", timeout=15000)
    check(tag + "the alert browser has its filters", all(page.locator(f"#ids-filter [name={k}]").count() == 1 for k in ["window", "src", "dst", "sid", "q", "action"]))
    check(tag + "the top lists are filled, not 'Loading'", "Loading" not in page.locator(".ids-top").inner_text())

    if WRITE:
        # 5. a rule set through the page
        page.goto(BASE + "/svc/ids")
        page.wait_for_selector("#svc-form-sources")
        fill_form(page, "#svc-form-sources", {"key": "netlab-ui", "name": "Netlab UI rules", "url": SOURCE_URL, "format": "tar.gz",
                                              "licence": "test", "enabled": True, "max_mb": 8})
        page.locator("#svc-form-sources button[type=submit]").click()
        page.wait_for_selector("[data-coll=sources] tr[data-id]:has-text('Netlab UI rules')", timeout=20000)
        check(tag + "the rule set was added through the page", True)
        page.locator("#svc-action-buttons button", has_text="Update rule sets now").click()
        page.wait_for_function(
            "() => /Netlab UI rules \\(netlab-ui\\)[\\s\\S]*?ok/.test(document.getElementById('svc-status').innerText)", timeout=120000)
        rs = [r for r in api(page, "/api/svc/ids")["json"]["status"]["rule_sets"] if r["key"] == "netlab-ui"][0]
        check(tag + "Update rule sets now: the rule set was downloaded, checked and loaded", rs["status"] == "ok" and rs["rules"] >= 1, rs)

        # 6. a policy and a setting through the page
        fill_form(page, "#svc-form-policies", {"scope": "ruleset", "target": "netlab-ui", "action": "alert", "note": "e2e"})
        page.locator("#svc-form-policies button[type=submit]").click()
        page.wait_for_selector("[data-coll=policies] tr[data-id]:has-text('netlab-ui')", timeout=30000)
        pol = api(page, "/api/svc/ids")["json"]["collections"]["policies"]
        check(tag + "the policy was saved", any(r["target"] == "netlab-ui" and r["action"] == "alert" for r in pol), pol)
        page.locator("#svc-settings-form [name=alert_retention_days]").fill("14")
        page.click("#svc-settings-form button[type=submit]")
        page.wait_for_function("() => document.querySelector('#svc-status') && !/Loading/.test(document.querySelector('#svc-status').innerText)")
        time.sleep(1)
        check(tag + "the retention setting was saved", api(page, "/api/svc/ids")["json"]["settings"]["alert_retention_days"] == 14)

        # 7. an alert, found and suppressed in the browser
        # Suricata restarts after every change above and needs a few seconds before it sees traffic:
        # keep sending until the alert is listed
        deadline = time.time() + 90
        while time.time() < deadline:
            req = urllib.request.Request(PROBE_URL, headers={"X-Probe": "evil-set"})
            try:
                urllib.request.urlopen(req, timeout=5).read()
            except Exception:
                pass
            time.sleep(3)
            if api(page, f"/api/svc/ids/alerts?sid={SID}")["json"]["total"] >= 1:
                break
        page.goto(BASE + "/svc/ids/alerts")
        page.wait_for_selector("#ids-filter")
        page.locator("#ids-filter [name=sid]").fill(SID)
        page.locator("#ids-filter button[type=submit]").click()
        page.wait_for_selector("#ids-rows tr[data-id]", timeout=20000)
        row = page.locator("#ids-rows tr[data-id]").first
        check(tag + "the alert is found by its SID and shows rule, source and destination",
              "Netlab" in row.inner_text() and SID in row.inner_text() and "80" in row.inner_text(), row.inner_text())
        page.wait_for_function("() => /Netlab/.test(document.getElementById('top-sid').innerText)", timeout=15000)
        check(tag + "the top rules list names the rule", True)
        page.locator("#ids-filter [name=src]").fill("not an address")
        page.locator("#ids-filter button[type=submit]").click()
        page.wait_for_selector("#ids-error", state="visible", timeout=10000)
        check(tag + "a bad address filter is refused on the page", "Invalid" in page.locator("#ids-error").inner_text(), page.locator("#ids-error").inner_text())
        page.locator("#ids-filter [name=src]").fill("")
        page.locator("#ids-filter button[type=submit]").click()
        page.wait_for_selector("#ids-rows tr[data-id]", timeout=20000)
        page.locator("#ids-rows tr[data-id]").first.locator("button", has_text="Suppress rule").click()
        page.wait_for_function("() => /Entry added/.test(document.getElementById('ids-page').innerText)", timeout=60000)
        sup = api(page, "/api/svc/ids")["json"]["collections"]["suppress"]
        check(tag + "one click on the alert made a suppress entry for its rule", any(str(r["sid"]) == SID and r["kind"] == "suppress" for r in sup), sup)
        page.goto(BASE + "/svc/ids")
        page.wait_for_selector("[data-coll=suppress] tr[data-id]", timeout=15000)
        page.locator("[data-coll=suppress] tr[data-id]").first.locator("button", has_text="Delete").click()
        page.wait_for_function("() => document.querySelectorAll('[data-coll=suppress] tr[data-id]').length === 0", timeout=60000)
        check(tag + "the suppress entry was deleted through the page", True)

    check(tag + "no JavaScript error", not errors, errors)
    ctx.close()
    responsive(browser, kind)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(("FAILED: " + ", ".join(failures)) if failures else "PASS ids-page-e2e", flush=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
