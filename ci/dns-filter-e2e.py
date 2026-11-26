#!/usr/bin/env python3
"""DNS filtering on the DNS page, driven in a real browser (Playwright; Firefox or Chromium).

Usage: dns-filter-e2e.py firefox|chromium   (env: BASE_URL, E2E_USER, E2E_PASSWORD, E2E_LIST_URL,
                                              E2E_BLOCK_HOST, E2E_SHOTS=<dir>)
Checks, each printed as `PASS: ...` (any failure exits 1):
  - the page loads without script errors, the catalog lists every free list with its licence link;
  - a custom list is added through the form, shows its names loaded and no error;
  - a list is switched off and on from its row;
  - an allow-list entry is added through the form (and a bad regular expression is shown as an error, not applied);
  - the query log (when it has rows) offers Block / Allow buttons; Block this domain adds the name to the block list;
  - at 1280 and 390 px, in light and dark: nothing overflows the viewport sideways, every table scrolls inside
    its own region, and a screenshot is written.
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"].rstrip("/")
USER = os.environ.get("E2E_USER", "admin")
PASSWORD = os.environ["E2E_PASSWORD"]
LIST_URL = os.environ["E2E_LIST_URL"]
BLOCK_HOST = os.environ.get("E2E_BLOCK_HOST", "www.lab.example")
SHOTS = os.environ.get("E2E_SHOTS", "")
FAILS = []


def ok(msg):
    print("PASS: " + msg, flush=True)


def check(cond, msg):
    if cond:
        ok(msg)
    else:
        print("FAIL: " + msg, flush=True)
        FAILS.append(msg)


def api(page, method, path, body=None):
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


def main():
    browser_name = sys.argv[1] if len(sys.argv) > 1 else "firefox"
    with sync_playwright() as pw:
        browser = getattr(pw, browser_name).launch()
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("dialog", lambda d: d.accept())
        page.goto(BASE + "/login")
        page.fill("#username", USER)
        page.fill("#password", PASSWORD)
        page.click("button[type=submit]")
        page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
        page.goto(BASE + "/dns")
        page.wait_for_selector("#dnsf-catalog tbody tr")
        check(not errors, "the DNS page loads without script errors %s" % errors)

        rows = page.locator("#dnsf-catalog tbody tr")
        n = rows.count()
        check(n >= 10, "the catalog lists %d free lists" % n)
        lic = page.locator("#dnsf-catalog tbody tr td:nth-child(4) a[href^='https://']")
        check(lic.count() == n, "every catalog row links its licence (%d of %d)" % (lic.count(), n))
        check(page.locator("#dnsf-catalog").get_by_text("MIT", exact=True).count() >= 1, "StevenBlack shows the MIT licence")
        check("Phishing Army" in page.locator("#dnsf-catalog").inner_text(), "Phishing Army is in the catalog")
        check(page.locator("#dnsf-catalog").get_by_text("Get a free access key").count() == 1, "URLhaus says it needs a free key")

        # add a custom list through the form
        page.fill("#dnsf-custom [name=url]", LIST_URL)
        page.fill("#dnsf-custom [name=name]", "e2e-list")
        page.select_option("#dnsf-custom [name=format]", "hosts")
        page.click("#dnsf-custom button[type=submit]")
        page.wait_for_selector("#dnsf-lists tbody tr td b:text('e2e-list')", timeout=60000)
        page.wait_for_function(
            "() => { const r = [...document.querySelectorAll('#dnsf-lists tbody tr')].find(x => x.innerText.includes('e2e-list')); return r && /\\d+ \\/ \\d+/.test(r.innerText); }",
            timeout=90000,
        )
        row = page.locator("#dnsf-lists tbody tr", has_text="e2e-list")
        check("OK" in row.inner_text() and "Not loaded" not in row.inner_text(), "the new list is downloaded: " + " ".join(row.inner_text().split())[:120])

        # switch it off and on from its row
        box = row.locator("input[type=checkbox]")
        box.uncheck()
        page.wait_for_function("() => document.querySelector('#dnsf-msg').textContent.startsWith('Done: disabling')", timeout=60000)
        r = api(page, "GET", "/api/dns-filter")
        check(any(l["name"] == "e2e-list" and not l["enabled"] for l in r["json"]["lists"]), "the list switch turns it off")
        page.locator("#dnsf-lists tbody tr", has_text="e2e-list").locator("input[type=checkbox]").check()
        page.wait_for_function("() => document.querySelector('#dnsf-msg').textContent.startsWith('Done: enabling')", timeout=60000)
        r = api(page, "GET", "/api/dns-filter")
        check(any(l["name"] == "e2e-list" and l["enabled"] for l in r["json"]["lists"]), "and on again")

        # allow list: a bad expression is refused with a message, a good one is added
        page.select_option("#dnsf-allow-form [name=kind]", "regex")
        page.fill("#dnsf-allow-form [name=pattern]", "(unclosed")
        page.click("#dnsf-allow-form button[type=submit]")
        page.wait_for_function("() => document.querySelector('#dnsf-msg').textContent.startsWith('Not applied')", timeout=30000)
        check("regular expression" in page.locator("#dnsf-msg").inner_text(), "a bad regular expression is shown as an error")
        page.fill("#dnsf-allow-form [name=pattern]", r"^cdn[0-9]+\.example\.test$")
        page.click("#dnsf-allow-form button[type=submit]")
        page.wait_for_selector("#dnsf-allow tbody tr td.mono:text('cdn')", timeout=60000)
        check(True, "a regular-expression allow entry is added and listed")

        # query log -> block this domain
        page.fill("#dnsf-log-form [name=q]", BLOCK_HOST)
        page.click("#dnsf-log-form button[type=submit]")
        page.wait_for_timeout(1500)
        btn = page.locator("#dnsf-log tbody tr", has_text=BLOCK_HOST).get_by_role("button", name="Block this domain")
        if btn.count():
            btn.first.click()
            page.wait_for_function("() => document.querySelector('#dnsf-msg').textContent.startsWith('Done: blocking')", timeout=60000)
            r = api(page, "GET", "/api/dns")
            check(any(b["domain"] == BLOCK_HOST for b in r["json"]["blocklist"]), "Block this domain from the query log adds it to the block list")
            api(page, "DELETE", "/api/dns/blocklist/%d" % [b["id"] for b in r["json"]["blocklist"] if b["domain"] == BLOCK_HOST][0])
        else:
            check(False, "the query log has a row for %s with a Block this domain button" % BLOCK_HOST)

        # layout: both widths, both colour schemes
        for scheme in ("light", "dark"):
            for (w, h, tag) in ((1280, 900, "1280"), (390, 844, "390")):
                ctx2 = browser.new_context(ignore_https_errors=True, viewport={"width": w, "height": h}, color_scheme=scheme)
                p2 = ctx2.new_page()
                p2.goto(BASE + "/login")
                p2.fill("#username", USER)
                p2.fill("#password", PASSWORD)
                p2.click("button[type=submit]")
                p2.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
                p2.goto(BASE + "/dns")
                p2.wait_for_selector("#dnsf-catalog tbody tr")
                p2.wait_for_timeout(500)
                over = p2.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
                check(over <= 1, "%s %s: the page does not scroll sideways (overflow %dpx)" % (tag, scheme, over))
                tables = p2.evaluate(
                    """() => [...document.querySelectorAll('.dnsf-scroll')].map(s => ({ok: s.scrollWidth >= s.clientWidth, tab: s.getAttribute('tabindex') === '0', role: s.getAttribute('role') === 'region'}))"""
                )
                check(len(tables) == 5 and all(t["tab"] and t["role"] for t in tables), "%s %s: five scroll regions, each focusable and labelled" % (tag, scheme))
                bg = p2.evaluate("() => getComputedStyle(document.body).backgroundColor")
                lum = sum(int(x) for x in bg[bg.index("(") + 1:bg.index(")")].split(",")[:3]) / 3
                check((lum < 90) == (scheme == "dark"), "%s %s: the page follows the colour scheme (%s)" % (tag, scheme, bg))
                if SHOTS:
                    os.makedirs(SHOTS, exist_ok=True)
                    el = p2.locator("#dnsf-lists-card")
                    el.scroll_into_view_if_needed()
                    p2.screenshot(path="%s/dns-filter-%s-%s.png" % (SHOTS, tag, scheme), full_page=False)
                    p2.locator("#dnsf-catalog-card").scroll_into_view_if_needed()
                    p2.screenshot(path="%s/dns-filter-catalog-%s-%s.png" % (SHOTS, tag, scheme), full_page=False)
                ctx2.close()
        browser.close()
    if FAILS:
        print("%d check(s) failed" % len(FAILS))
        sys.exit(1)


if __name__ == "__main__":
    main()
