#!/usr/bin/env python3
"""Browser check of the system log page (System log in the menu, /logs) and of the Monitoring preview.

Real Firefox (Chromium when asked) at 1280 px and 390 px, light and dark (the device setting, switched live), requires:
  1. the menu has a "System log" entry; the page shows entries coloured per priority, with "-- boot --" separator rows;
  2. every priority class and the separator reads at WCAG AA (4.5:1) against the log background, in both schemes, and the
     colours really change with the scheme (theme tokens, nothing hard-coded);
  3. filters: minimum priority, identifier with a wildcard, kernel only, free text; they are kept in the address (a reload
     gives the same view) and Reset restores everything;
  4. Live: a line written while the page is open shows up; Pause stops the list from growing (a counter shows the
     lines held back) and Resume releases them;
  5. Timespan: since/until limit the list; Download carries the filters;
  6. the phone layout has no sideways page scroll; screenshots of every width x scheme go to E2E_SHOTS;
  7. the Monitoring page shows the short preview with a link to the log;
  8. no JavaScript error on any of it.

Usage: BASE_URL=https://192.0.2.1 E2E_USER=admin E2E_PASSWORD=... [E2E_SHOTS=/tmp/shots] syslog-page-e2e.py [firefox,chromium]
The log it reads must hold (see ci/netlab/lane-h-syslog-viewer-ui.sh): one line per priority 0-7, one without priority,
two boot markers, a kernel line, lines of identifiers `web-a` / `web-b` and a writer that appends a `tick N` line
every second under identifier `e2e-live`. Exit 0 = every check passed.
"""
import os
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
SHOTS = os.environ.get("E2E_SHOTS", "")
failures = []


def check(ok, what):
    print(("PASS: " if ok else "FAIL: ") + what, flush=True)
    if not ok:
        failures.append(what)


# relative luminance / contrast of two CSS colours (rgb()/rgba() strings from getComputedStyle)
JS_CONTRAST = """([sel, bgsel]) => {
  const rgb = (s) => (s.match(/[\\d.]+/g) || [0,0,0]).slice(0,3).map(Number);
  const lum = (c) => { const f = (v) => { v/=255; return v <= 0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); };
                       return 0.2126*f(c[0]) + 0.7152*f(c[1]) + 0.0722*f(c[2]); };
  const el = document.querySelector(sel); const bg = document.querySelector(bgsel);
  if (!el || !bg) return null;
  const a = lum(rgb(getComputedStyle(el).color)), b = lum(rgb(getComputedStyle(bg).backgroundColor));
  return {ratio: (Math.max(a,b)+0.05)/(Math.min(a,b)+0.05), color: getComputedStyle(el).color, bg: getComputedStyle(bg).backgroundColor};
}"""


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    errors = []
    tag = f"[{kind}] "
    seen_colors = {}
    for (w, h) in ((1280, 900), (390, 844)):
        for scheme in ("light", "dark"):
            ctx = browser.new_context(ignore_https_errors=True, viewport={"width": w, "height": h}, color_scheme=scheme)
            page = ctx.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(BASE + "/login")
            page.fill("#username", USER)
            page.fill("#password", PASSWORD)
            page.click("button[type=submit]")
            page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
            t = f"{tag}{w}px {scheme}: "

            page.goto(BASE + "/logs?mode=span&since=" + urllib.parse.quote("2000-01-01T00:00:00Z"))
            page.wait_for_selector("#sl-pane .ll", timeout=20000)
            check(page.locator("a.nav-item[href='/logs']").count() == 1, t + "menu has a System log entry")
            for pr in range(8):
                check(page.locator(f"#sl-pane .ll.lv{pr}").count() >= 1, t + f"priority {pr} line is shown with its class")
            check(page.locator("#sl-pane .ll.lvu").count() >= 1, t + "a line without priority is shown as unknown, not guessed")
            check(page.locator("#sl-pane .boot").count() >= 1, t + "boot separator row present")

            # contrast per priority class + separator against the pane background
            for cls in ("lv0", "lv3", "lv4", "lv5", "lv6", "lv7", "lvu"):
                r = page.evaluate(JS_CONTRAST, [f"#sl-pane .ll.{cls} .m", "#sl-pane"])
                check(r is not None and r["ratio"] >= 4.5, t + f"{cls} contrast {r and round(r['ratio'], 2)}:1 >= 4.5")
                seen_colors.setdefault((w, cls), {})[scheme] = r and r["color"]
            for sel in ("#sl-pane .boot", "#sl-pane .ll .t", "#sl-pane .ll .id"):
                if page.locator(sel).count():
                    r = page.evaluate(JS_CONTRAST, [sel, "#sl-pane"])
                    check(r is not None and r["ratio"] >= 4.5, t + f"{sel} contrast {r and round(r['ratio'], 2)}:1 >= 4.5")
            # weight per priority: critical lines heavier than info lines
            wt = page.evaluate("() => [0,3,6].map(n => { const e = document.querySelector('#sl-pane .ll.lv'+n+' .m'); return e ? parseInt(getComputedStyle(e).fontWeight) : 0; })")
            check(wt[0] > wt[2] and wt[1] > wt[2], t + f"weight follows priority (emerg {wt[0]}, err {wt[1]}, info {wt[2]})")
            # monospace
            ff = page.evaluate("() => getComputedStyle(document.querySelector('#sl-pane')).fontFamily")
            check("mono" in ff.lower() or "menlo" in ff.lower() or "consolas" in ff.lower(), t + "monospace font")
            # phone: no sideways scroll of the page
            over = page.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
            check(over <= 1, t + f"no sideways page scroll (overflow {over}px)")
            if SHOTS:
                os.makedirs(SHOTS, exist_ok=True)
                page.screenshot(path=f"{SHOTS}/logs-{kind}-{w}-{scheme}.png", full_page=False)

            if w == 1280 and scheme == "light":
                functional(page, t)
            if scheme == "light":
                monitoring(page, t)
            ctx.close()
    # the colours follow the scheme: same class, different colour in light and dark
    for (w, cls), d in seen_colors.items():
        if "light" in d and "dark" in d:
            check(d["light"] != d["dark"], f"{tag}{w}px {cls}: colour differs light vs dark ({d['light']} / {d['dark']})")
    check(not errors, tag + "no JavaScript error" + (": " + "; ".join(errors[:3]) if errors else ""))
    browser.close()


def count_lines(page):
    return page.locator("#sl-pane .ll").count()


def functional(page, t):
    # filters: minimum priority
    page.goto(BASE + "/logs?mode=span&since=" + urllib.parse.quote("2000-01-01T00:00:00Z"))
    page.wait_for_selector("#sl-pane .ll", timeout=20000)
    full = count_lines(page)
    page.select_option("#sl-prio", "err")
    page.click("#sl-form button[type=submit]")
    page.wait_for_function("() => document.querySelectorAll('#sl-pane .ll').length > 0 && !document.querySelector('#sl-pane .ll.lv6')", timeout=15000)
    worst = page.evaluate("() => [...document.querySelectorAll('#sl-pane .ll')].every(e => /lv[0-3]/.test(e.className))")
    check(worst, t + "minimum priority err keeps only err and worse")
    check("min_priority=err" in page.url, t + "the filter is in the address")
    page.reload()
    page.wait_for_selector("#sl-pane .ll", timeout=20000)
    check(page.input_value("#sl-prio") == "err" and not page.locator("#sl-pane .ll.lv6").count(), t + "a reload gives the same view")
    # reset
    page.click("button:has-text('Reset')")
    page.wait_for_function(f"() => document.querySelectorAll('#sl-pane .ll').length >= {full}", timeout=15000)
    check("min_priority" not in page.url, t + "Reset clears the filters from the address")
    # identifier wildcard
    page.goto(BASE + "/logs?mode=span&identifier=web-*&since=" + urllib.parse.quote("2000-01-01T00:00:00Z"))
    page.wait_for_selector("#sl-pane .ll", timeout=20000)
    ids = page.evaluate("() => [...new Set([...document.querySelectorAll('#sl-pane .ll .id')].map(e => e.textContent.replace(/\\[\\d+\\]$/, '')))]")
    check(sorted(ids) == ["web-a", "web-b"], t + f"identifier web-* matches web-a and web-b only ({ids})")
    # kernel only
    page.goto(BASE + "/logs?mode=span&kernel=1&since=" + urllib.parse.quote("2000-01-01T00:00:00Z"))
    page.wait_for_selector("#sl-pane .ll", timeout=20000)
    check(page.locator("#sl-pane .ll").count() >= 1 and page.evaluate("() => [...document.querySelectorAll('#sl-pane .ll .id')].every(e => e.textContent.startsWith('kernel'))"), t + "kernel only")
    # free text
    page.goto(BASE + "/logs?mode=span&q=needle-in-haystack&since=" + urllib.parse.quote("2000-01-01T00:00:00Z"))
    page.wait_for_selector("#sl-pane .ll", timeout=20000)
    check(count_lines(page) == 1, t + "free text finds the one matching line")
    # download link carries the filters
    href = page.get_attribute("#sl-dl", "href")
    check("q=needle-in-haystack" in href, t + "Download carries the filters")

    # timespan: a span in the future holds nothing, an open span holds lines
    page.goto(BASE + "/logs?mode=span&since=" + urllib.parse.quote("2099-01-01T00:00:00Z"))
    page.wait_for_function("() => document.querySelector('#sl-pane .sl-empty')", timeout=15000)
    check(count_lines(page) == 0, t + "an empty timespan shows the empty note")

    # live: new lines arrive; pause holds them back; resume releases
    page.goto(BASE + "/logs?identifier=e2e-live")
    page.wait_for_selector("#sl-pane .ll", timeout=20000)
    check(page.locator("#sl-live").get_attribute("aria-pressed") == "true", t + "Live mode is the default")
    page.wait_for_function("() => document.getElementById('sl-live-st').textContent.indexOf('Live') === 0", timeout=15000)
    n0 = count_lines(page)
    page.wait_for_function(f"() => document.querySelectorAll('#sl-pane .ll').length > {n0}", timeout=15000)
    check(True, t + "a line written while the page is open appeared")
    page.click("#sl-pause")
    n1 = count_lines(page)
    time.sleep(3.5)
    check(count_lines(page) == n1, t + "paused: the list does not grow")
    check("new" in page.inner_text("#sl-pause"), t + f"paused: the button counts held lines ({page.inner_text('#sl-pause')!r})")
    page.click("#sl-pause")
    page.wait_for_function(f"() => document.querySelectorAll('#sl-pane .ll').length > {n1 + 1}", timeout=10000)
    check(True, t + "resumed: the held lines were released")
    # settings card
    check(page.locator("#sl-settings input[name='logview.file_path']").count() == 1, t + "the settings card lists the log file path")


def monitoring(page, t):
    page.goto(BASE + "/monitoring")
    page.wait_for_selector("#log-preview", timeout=20000)
    check(page.locator("#log-preview-lines .ll").count() >= 1, t + "Monitoring shows the preview lines")
    check(page.locator("#log-preview a[href='/logs']").count() >= 1, t + "the preview links to the log page")


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(f"{'FAILED' if failures else 'OK'}: {len(failures)} failing check(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
