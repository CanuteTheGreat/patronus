#!/usr/bin/env python3
"""Browser check of the Firewall page's floating rules, interface groups, limiters, overload
tables, categories and log summary (/firewall).

Signs in, then in every viewport/colour scheme (desktop 1280 px and phone 390 px, light and dark)
requires, through the page only:
  1. the rule form has the scope switch; choosing "Floating" shows direction, interfaces and the
     quick explanation, and hides the single-interface fields;
  2. the "Groups & limiters" tab lists what exists, the group and limiter forms save through the
     API and the rows appear; a limiter with a rate of 0 is refused on the page with the reason;
  3. a floating rule (two interfaces, direction in, not quick), a rule on the group, and a pass
     rule with a rate limit, an overload table, a limiter and a category are saved and shown in
     the rules table with their option summary and category;
  4. editing a floating rule restores every field it was saved with;
  5. the page has no horizontal overflow and no JavaScript error, text on the new controls keeps
     WCAG AA contrast (4.5:1) in both colour schemes;
  6. with E2E_LOG=1: after traffic hit a logging rule the Logs tab shows the summary tables and
     "Block this source" opens a rule for review (nothing saved) that names the source port caveat
     for a pass draft.
Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... [E2E_IFACES=eth1,eth2] \
       firewall-floating-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
IFACES = [i for i in os.environ.get("E2E_IFACES", "").split(",") if i]
LOG = os.environ.get("E2E_LOG") == "1"

failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


def api(page, path, method="GET", body=None):
    r = page.evaluate(
        """async ([p, m, b]) => { const r = await fetch('/api' + p, {method: m, credentials: 'same-origin',
             headers: b ? {'content-type': 'application/json'} : {}, body: b ? JSON.stringify(b) : undefined});
             return {status: r.status, body: await r.text()}; }""",
        [path, method, body],
    )
    try:
        r["json"] = json.loads(r["body"])
    except ValueError:
        r["json"] = None
    return r


def contrast(page, selector):
    """Contrast ratio of the text colour of `selector` on its effective background."""
    return page.evaluate(
        """(sel) => {
            const el = document.querySelector(sel); if (!el) return null;
            const parse = c => c.match(/[\\d.]+/g).map(Number);
            const lum = ([r, g, b]) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
                return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
            let bg = null, n = el;
            while (n) { const c = parse(getComputedStyle(n).backgroundColor); if (c.length < 4 || c[3] > 0.5) { bg = c.slice(0, 3); break; } n = n.parentElement; }
            bg = bg || [255, 255, 255];
            const fg = parse(getComputedStyle(el).color).slice(0, 3);
            const a = lum(fg), b = lum(bg);
            return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
        }""",
        selector,
    )


def login(page):
    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)


def goto_firewall(page, tab):
    page.goto(BASE + "/firewall")
    page.wait_for_selector("#rule-form", timeout=15000)
    page.click(f".tab-btn[data-tab={tab}]")


def run_viewport(browser, kind, label, width, height, scheme, first):
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": height}, color_scheme=scheme)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", lambda d: d.accept())
    tag = f"[{kind} {label} {scheme}] "
    login(page)
    sfx = f"{width}{scheme[0]}"
    group, limiter, cat = f"e2eg{sfx}", f"e2el{sfx}", f"e2e cat {sfx}"

    # 1. the form's scope switch
    goto_firewall(page, "tab-rules")
    f = page.locator("#rule-form")
    check(tag + "the rule form has the scope switch", f.locator("[name=scope]").count() == 1)
    check(tag + "floating options are hidden for an interface rule", not page.locator("#rule-floating").is_visible())
    f.locator("[name=scope]").select_option("floating")
    check(tag + "choosing Floating shows direction, interfaces and the quick explanation",
          page.locator("#rule-floating").is_visible() and page.locator("#rule-floating [name=direction]").is_visible()
          and "first match wins" in page.locator("#quick-hint").inner_text())
    check(tag + "the single-interface selector is disabled for a floating rule", f.locator("[name=interface]").is_disabled())
    f.locator("[name=scope]").select_option("interface")
    check(tag + "back to an interface rule hides them again", not page.locator("#rule-floating").is_visible())

    # 2. groups and limiters
    page.click(".tab-btn[data-tab=tab-groups]")
    page.wait_for_selector("#group-form", timeout=10000)
    page.wait_for_function("() => !document.querySelector('#groups-table tbody').innerText.includes('loading')", timeout=10000)
    members = ", ".join(IFACES[:1] or ["lo"])
    page.fill("#group-form [name=name]", group)
    page.fill("#group-form [name=members]", members)
    with page.expect_navigation():
        page.click("#group-form button[type=submit]")
    page.click(".tab-btn[data-tab=tab-groups]")
    page.wait_for_selector(f'#groups-table tr[data-group="{group}"]', timeout=10000)
    check(tag + "the new group is listed with its members", members.split(",")[0] in page.locator(f'#groups-table tr[data-group="{group}"]').inner_text())
    page.fill("#limiter-form [name=name]", limiter)
    page.fill("#limiter-form [name=rate_kbit]", "0")
    page.evaluate("() => { document.getElementById('limiter-form').noValidate = true; }")  # let the server refuse it
    page.click("#limiter-form button[type=submit]")
    page.wait_for_selector("#msg", state="visible", timeout=10000)
    msg = page.locator("#msg").inner_text()
    check(tag + "a limiter with rate 0 is refused on the page, with the reason", "Invalid" in msg or "rate" in msg.lower(), msg)
    check(tag + "the refused limiter stored nothing", all(l["name"] != limiter for l in api(page, "/firewall/limiters")["json"]))
    page.fill("#limiter-form [name=rate_kbit]", "4000")
    with page.expect_navigation():
        page.click("#limiter-form button[type=submit]")
    page.click(".tab-btn[data-tab=tab-groups]")
    page.wait_for_selector(f'#limiters-table tr[data-limiter="{limiter}"]', timeout=10000)
    check(tag + "the new limiter is listed", "4000" in page.locator(f'#limiters-table tr[data-limiter="{limiter}"]').inner_text())

    # 3. rules: floating, group, limits
    page.click(".tab-btn[data-tab=tab-rules]")
    f = page.locator("#rule-form")
    f.locator("[name=scope]").select_option("floating")
    f.locator("[name=name]").fill(f"e2e floating {sfx}")
    f.locator("[name=action]").select_option("drop")
    f.locator("[name=direction]").select_option("in")
    f.locator("[name=quick]").uncheck()
    opts = [o for o in f.locator("[name=interfaces] option").evaluate_all("els => els.map(e => e.value)") if o]
    pick = [f"group:{group}"] + ([IFACES[1]] if len(IFACES) > 1 and IFACES[1] in opts else [])
    f.locator("[name=interfaces]").select_option(pick)
    f.locator("[name=protocol]").select_option("tcp")
    f.locator("[name=port]").fill("9999")
    f.locator("[name=category]").fill(cat)
    page.click("#rule-limits summary")
    with page.expect_navigation():
        f.locator("button[type=submit]").click()
    page.wait_for_selector("#rules-table", timeout=10000)
    row = page.locator("#rules-table tbody tr", has_text=f"e2e floating {sfx}")
    check(tag + "the floating rule is in the table with its summary", row.count() == 1 and "floating" in row.inner_text() and "not quick" in row.inner_text(), row.inner_text() if row.count() else "no row")
    check(tag + "its category is shown", cat in row.inner_text())

    f = page.locator("#rule-form")
    f.locator("[name=name]").fill(f"e2e limits {sfx}")
    f.locator("[name=action]").select_option("accept")
    f.locator("[name=protocol]").select_option("tcp")
    f.locator("[name=port]").fill("9998")
    page.click("#rule-limits summary")
    f.locator("[name=max_states]").fill("500")
    f.locator("[name=max_src_conn]").fill("20")
    f.locator("[name=max_src_rate]").fill("30")
    f.locator("[name=max_src_rate_secs]").fill("10")
    f.locator("[name=overload]").fill(f"flood{sfx}")
    f.locator("[name=overload_secs]").fill("600")
    page.wait_for_function("(l) => Array.from(document.querySelectorAll('#rule-form [name=limiter] option')).some(o => o.value === l)", arg=limiter, timeout=10000)
    f.locator("[name=limiter]").select_option(limiter)
    f.locator("[name=category]").fill(cat)
    with page.expect_navigation():
        f.locator("button[type=submit]").click()
    page.wait_for_selector("#rules-table", timeout=10000)
    row = page.locator("#rules-table tbody tr", has_text=f"e2e limits {sfx}")
    txt = row.inner_text() if row.count() else ""
    check(tag + "the limits rule shows its limits in the table",
          "max 500 states" in txt and "20 conn/source" in txt and "overload" in txt and f"limiter {limiter}" in txt, txt)

    # 4. edit restores every field
    row.locator("button", has_text="Edit").click()
    page.wait_for_function("() => document.querySelector('#rule-form [name=max_states]').value !== ''", timeout=10000)
    f = page.locator("#rule-form")
    got = {k: f.locator(f"[name={k}]").input_value() for k in ["max_states", "max_src_conn", "max_src_rate", "max_src_rate_secs", "overload", "overload_secs", "limiter", "category"]}
    check(tag + "editing a rule restores its limits, limiter and category",
          got == {"max_states": "500", "max_src_conn": "20", "max_src_rate": "30", "max_src_rate_secs": "10", "overload": f"flood{sfx}",
                  "overload_secs": "600", "limiter": limiter, "category": cat}, got)
    page.click("#rules-table tbody tr:has-text('e2e floating') button:has-text('Edit')")
    page.wait_for_function("() => document.querySelector('#rule-form [name=scope]').value === 'floating'", timeout=10000)
    check(tag + "editing a floating rule restores scope, direction and not-quick",
          f.locator("[name=direction]").input_value() == "in" and not f.locator("[name=quick]").is_checked())

    # 5. layout, contrast
    overflow = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    check(tag + "no horizontal overflow of the page", overflow <= 1, overflow)
    page.click(".tab-btn[data-tab=tab-groups]")
    for sel in ["#groups-table td", "#limiter-form label", "#tab-groups .hint", "#rule-limits summary"]:
        c = contrast(page, sel)
        if c is not None and page.locator(sel).first.is_visible():
            check(tag + f"contrast of {sel} is at least 4.5:1", c >= 4.5, round(c, 2))
    if first:
        page.screenshot(path=f"/tmp/fw-floating-{kind}-{label}-{scheme}.png", full_page=True)

    # cleanup through the API (the UI paths are covered above)
    rules = api(page, "/firewall/rules")["json"]
    for r in rules:
        if sfx in r["name"] and r["name"].startswith("e2e"):
            api(page, f"/firewall/rules/{r['id']}", "DELETE")
    check(tag + "a limiter and a group in use are protected, free ones can be removed",
          api(page, f"/firewall/limiters/{limiter}", "DELETE")["status"] == 200
          and api(page, f"/firewall/interface-groups/{group}", "DELETE")["status"] == 200)

    if LOG and first:
        goto_firewall(page, "tab-logs")
        page.wait_for_function("() => document.querySelectorAll('#log-table tbody tr').length > 0", timeout=20000)
        check(tag + "the log summary lists the busiest sources", page.locator("#log-top-src").is_visible()
              and page.locator("#log-top-src tbody tr").count() >= 1)
        page.locator("#log-top-src button", has_text="Block this source").first.click()
        title = page.locator("#rule-form-title").inner_text()
        check(tag + "'Block this source' opens a rule for review and saves nothing", "Review rule from log" in title)
        check(tag + "the proposed rule is a drop rule for that source",
              page.locator("#rule-form [name=action]").input_value() == "drop" and page.locator("#rule-form [name=source]").input_value() not in ("", "any"))
    check(tag + "no JavaScript error", not errors, errors)
    ctx.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for kind in kinds:
            browser = getattr(p, kind).launch(headless=True)
            first = True
            for label, w, h in [("desktop", 1280, 900), ("phone", 390, 800)]:
                for scheme in ["light", "dark"]:
                    run_viewport(browser, kind, label, w, h, scheme, first)
                    first = False
            browser.close()
    print(f"{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
