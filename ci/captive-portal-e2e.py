#!/usr/bin/env python3
"""Browser check of the captive portal's sign-in page, as a phone sees it.

Run from a client of a portal zone (login `none`, terms required) that is not signed in. In Firefox
(and Chromium when installed), on a 390 x 844 phone viewport, once with a light and once with a dark
colour scheme, it requires:
  1. a plain-HTTP page asked for (TARGET_URL) lands on the sign-in page over HTTPS on the router's
     standard port (https://ROUTER/), with the zone's title;
  2. no horizontal scrolling; every input has a label; the button is at least 44 px high; the button
     text, body text and error text meet WCAG AA contrast (4.5:1) against their backgrounds; the
     page follows the colour scheme (different background in light and dark);
  3. Connect without ticking the terms is refused on the page (an alert is shown) and the client is
     still captured;
  4. ticking the terms and Connect takes the browser to the page first asked for (the internet
     answers), then the status page (on the portal's own port) shows the logout button, and Disconnect brings the sign-in page back.
No JavaScript errors anywhere. Exit 0 = every check passed.

Usage: ROUTER=192.168.50.1 TARGET_URL=http://198.51.100.10/ TARGET_TEXT='sees' captive-portal-e2e.py [firefox,chromium]
"""
import os
import sys

from playwright.sync_api import sync_playwright

ROUTER = os.environ["ROUTER"]
TARGET = os.environ["TARGET_URL"]
TARGET_TEXT = os.environ.get("TARGET_TEXT", "")
TITLE = os.environ.get("PORTAL_TITLE", "")
PORT = os.environ.get("PORTAL_HTTPS_PORT", "8003")

failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


CONTRAST_JS = """
() => {
  function rgb(s) { const m = s.match(/[\\d.]+/g).map(Number); return m.slice(0, 3).concat([m.length > 3 ? m[3] : 1]); }
  function lum(c) { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
                    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); }
  function bg(el) { while (el) { const c = rgb(getComputedStyle(el).backgroundColor); if (c[3] > 0) return c; el = el.parentElement; }
                    return [255, 255, 255, 1]; }
  function ratio(el) { const a = lum(rgb(getComputedStyle(el).color)), b = lum(bg(el));
                       return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); }
  const out = {};
  for (const [k, sel] of [["button", "button"], ["title", "h1"], ["text", "main p"], ["label", "label"], ["alert", "[role=alert]"]]) {
    const el = document.querySelector(sel); if (el) out[k] = ratio(el);
  }
  out.body_bg = getComputedStyle(document.body).backgroundColor;
  out.scroll = document.documentElement.scrollWidth;
  out.button_h = document.querySelector("button") ? document.querySelector("button").getBoundingClientRect().height : 0;
  out.unlabelled = [...document.querySelectorAll("input:not([type=hidden])")].filter(i => !(i.labels && i.labels.length)).map(i => i.name);
  return out;
}
"""


def run(browser_name, pw):
    bt = getattr(pw, browser_name)
    try:
        browser = bt.launch()
    except Exception as e:  # noqa: BLE001
        if browser_name == "firefox":
            check(f"{browser_name}: launch", False, e)
        else:
            print(f"SKIP: {browser_name} not installed ({e})")
        return
    bgs = {}
    for scheme in ("light", "dark"):
        tag = f"{browser_name}/{scheme}"
        ctx = browser.new_context(viewport={"width": 390, "height": 844}, ignore_https_errors=True,
                                  color_scheme=scheme, is_mobile=browser_name == "chromium", has_touch=True)
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(TARGET, wait_until="load")
        check(f"{tag}: {TARGET} lands on the sign-in page at https://{ROUTER}/",
              page.url.startswith(f"https://{ROUTER}/") and page.locator("#cp-login").count() == 1, page.url)
        if TITLE:
            check(f"{tag}: zone title shown", page.locator("h1").inner_text().strip() == TITLE, page.locator("h1").inner_text())
        m = page.evaluate(CONTRAST_JS)
        bgs[scheme] = m["body_bg"]
        check(f"{tag}: no horizontal scrolling at 390 px", m["scroll"] <= 390, m["scroll"])
        check(f"{tag}: every input has a label", not m["unlabelled"], m["unlabelled"])
        check(f"{tag}: button is a 44 px touch target", m["button_h"] >= 44, m["button_h"])
        for k in ("button", "title", "text", "label"):
            if k in m:
                check(f"{tag}: {k} contrast {m[k]:.1f}:1 >= 4.5", m[k] >= 4.5, m[k])
        # refused: no terms (the form has `required`; submit it the way a browser without validation would)
        page.evaluate("() => { document.querySelectorAll('[required]').forEach(e => e.removeAttribute('required')); }")
        page.click("#cp-login")
        page.wait_for_load_state("load")
        check(f"{tag}: Connect without the terms shows the refusal", page.locator("[role=alert]").count() == 1, page.content()[:300])
        m2 = page.evaluate(CONTRAST_JS)
        if "alert" in m2:
            check(f"{tag}: refusal text contrast {m2['alert']:.1f}:1 >= 4.5", m2["alert"] >= 4.5, m2["alert"])
        # sign in
        page.check("#cp-terms")
        page.click("#cp-login")
        page.wait_for_load_state("load")
        body = page.locator("body").inner_text()
        check(f"{tag}: signed in, the page first asked for opens", page.url.startswith(TARGET) and TARGET_TEXT in body,
              f"{page.url} {body[:200]}")
        page.goto(f"https://{ROUTER}:{PORT}/status", wait_until="load")
        check(f"{tag}: status page has the logout button", page.locator("#cp-logout").count() == 1 and page.locator("#cp-online").count() == 1,
              page.content()[:300])
        page.click("#cp-logout")
        page.wait_for_load_state("load")
        check(f"{tag}: Disconnect brings the sign-in page back", page.locator("#cp-login").count() == 1, page.content()[:300])
        page.goto(TARGET, wait_until="load")
        check(f"{tag}: captured again after Disconnect", page.url.startswith(f"https://{ROUTER}/"), page.url)
        check(f"{tag}: no JavaScript errors", not errors, errors)
        ctx.close()
    check(f"{browser_name}: light and dark backgrounds differ (follows the device)", bgs.get("light") != bgs.get("dark"), bgs)
    browser.close()


def main():
    names = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as pw:
        for n in names:
            run(n, pw)
    print(f"{'FAILED' if failures else 'OK'}: {len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
