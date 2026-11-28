#!/usr/bin/env python3
"""Browser check of schema-driven plugin settings on the Packages page (/packages).

A signed test plugin carries a `settings` schema (see crates/patronus-network/src/plugin_settings.rs);
ci/netlab/lane-n-plugin-settings.sh installs it and runs this script (Playwright + Firefox) against the
shipped patronus-web. In every combination of 1280 px / 390 px and light / dark (the page follows the
device setting) it requires:
  1. the plugin row has a "settings" button and opening it draws one field per schema entry, with the
     right control type (number, select, checkbox, textarea, password) and the schema's limits as text;
  2. the hint of a field shows on hover AND on keyboard focus (and is wired by aria-describedby);
  3. every text node passes WCAG AA contrast (4.5:1, 3:1 large) and the page has no horizontal overflow;
  4. no JavaScript error.
At 1280 light (E2E_WRITE=1) it also, through the page only:
  5. an out-of-range number is refused on the page with the reason, and nothing is stored;
  6. a value that breaks the pattern is refused, naming the field;
  7. a valid save is accepted, the page says so, a reload shows the saved values, and the secret is NEVER in
     the page text, the form values or any /api/packages response after saving (only "a value is saved");
  8. the plugin's settings file on disk (E2E_SETTINGS_FILE) holds the saved values, mode 0600, and the
     plugin's own service serves them (E2E_PLUGIN_URL).
At 390 dark it saves a second, different valid set and requires the same file/service result.

Usage: BASE_URL=https://192.0.2.1 E2E_USER=admin E2E_PASSWORD=... E2E_PLUGIN=setdemo [E2E_WRITE=1 \\
       E2E_SETTINGS_FILE=/var/lib/patronus/plugins/setdemo.settings.json E2E_PLUGIN_URL=http://192.0.2.1:18081/] \\
       [E2E_SHOTS=/dir] plugin-settings-e2e.py [firefox]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import json
import os
import stat
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
PLUGIN = os.environ.get("E2E_PLUGIN", "setdemo")
WRITE = os.environ.get("E2E_WRITE") == "1"
SETTINGS_FILE = os.environ.get("E2E_SETTINGS_FILE", "")
PLUGIN_URL = os.environ.get("E2E_PLUGIN_URL", "")
SHOTS = os.environ.get("E2E_SHOTS", "")
SECRET1 = "tok-S3CRET-first-7731"
SECRET2 = "tok-S3CRET-second-9042"

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


# every text node, WCAG AA; hidden things (the closed hint tooltips) are skipped like a screen would
CONTRAST_JS = """(() => {
  const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return {r:p[0],g:p[1],b:p[2],a:p.length>3?p[3]:1}; };
  const over = (f,b) => ({r:f.r*f.a+b.r*(1-f.a),g:f.g*f.a+b.g*(1-f.a),b:f.b*f.a+b.b*(1-f.a),a:1});
  const lin = v => { v/=255; return v<=0.03928? v/12.92 : Math.pow((v+0.055)/1.055,2.4); };
  const L = c => 0.2126*lin(c.r)+0.7152*lin(c.g)+0.0722*lin(c.b);
  const ratio = (a,b) => { const x=L(a),y=L(b); return (Math.max(x,y)+0.05)/(Math.min(x,y)+0.05); };
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const canvas = dark ? {r:26,g:26,b:26,a:1} : {r:255,g:255,b:255,a:1};
  function bgOf(el) {
    const chain = [];
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage && cs.backgroundImage !== 'none' && /gradient|url/.test(cs.backgroundImage)) return null;
      const c = parse(cs.backgroundColor); if (c && c.a > 0) { chain.push(c); if (c.a >= 1) break; }
    }
    let base = canvas; for (let i = chain.length - 1; i >= 0; i--) base = over(chain[i], base);
    return base;
  }
  const bad = []; let n = 0; const seen = new Set();
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (w.nextNode()) {
    const t = w.currentNode; if (!t.nodeValue.trim()) continue;
    const el = t.parentElement; if (!el || seen.has(el)) continue; seen.add(el);
    if (['SCRIPT','STYLE','NOSCRIPT','OPTION'].includes(el.tagName)) continue;
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    if (r.width < 1 || r.height < 1 || cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) === 0) continue;
    const fgc = parse(cs.color), bg = bgOf(el); if (!fgc || !bg) continue;
    const fg = over(fgc, bg); n++;
    const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 700;
    const need = (size >= 24 || (size >= 18.66 && bold)) ? 3 : 4.5, cr = ratio(fg, bg);
    if (cr < need) bad.push({txt: t.nodeValue.trim().slice(0, 40), cr: +cr.toFixed(2), need, tag: el.tagName + '.' + (typeof el.className === 'string' ? el.className : '')});
  }
  return {dark, checked: n, bad};
})()"""


def login(page):
    page.goto(BASE + "/login")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)


def open_settings(page):
    page.goto(BASE + "/packages")
    row = page.locator(f'#pk-plugins tr[data-plugin="{PLUGIN}"]')
    row.wait_for(timeout=15000)
    row.locator("button", has_text="settings").click()
    page.wait_for_selector("#pk-settings-card.open #pk-set-grid .set-field", timeout=10000)


def field(page, key):
    return page.locator(f'#pk-set-grid [data-key="{key}"]')


def fill_valid(page, interval, token, mode, debug, hosts, name):
    field(page, "interval").fill(str(interval))
    field(page, "name").fill(name)
    field(page, "mode").select_option(mode)
    field(page, "debug").set_checked(debug)
    field(page, "hosts").fill("\n".join(hosts))
    field(page, "listen").fill("18081")
    if token:
        field(page, "token").fill(token)


def read_file():
    st = os.stat(SETTINGS_FILE)
    with open(SETTINGS_FILE) as f:
        return stat.S_IMODE(st.st_mode), json.load(f)


def plugin_serves(expect_interval, expect_token):
    last = None
    for _ in range(40):
        try:
            with urllib.request.urlopen(PLUGIN_URL, timeout=3) as r:
                last = json.loads(r.read())
            if last.get("interval") == expect_interval and last.get("token") == expect_token:
                return True, last
        except Exception as e:  # service restarting
            last = str(e)
        time.sleep(0.5)
    return False, last


def run_combo(p, kind, width, scheme, mode):
    tag = f"[{kind} {width}px {scheme}] "
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": 900 if width > 600 else 780},
                              color_scheme=scheme)
    page = ctx.new_page()
    errors = []
    # Firefox reports a fetch that is cut off by a reload/navigation (or by the plugin
    # service restarting during a save) as a pageerror "NetworkError when attempting to
    # fetch resource."; that is the browser aborting a request, not a script defect.
    # Every other pageerror (TypeError, ReferenceError, ...) still fails the check.
    page.on("pageerror", lambda e: errors.append(str(e))
            if "NetworkError when attempting to fetch resource" not in str(e) else None)
    login(page)
    open_settings(page)
    page.add_style_tag(content="*{transition:none!important}")

    # 1. one field per schema entry, with the right control and the limits as text
    d = api(page, "/api/packages")["json"]
    plug = next(x for x in d["plugins"] if x["name"] == PLUGIN)
    keys = [s["key"] for s in plug["settings"]]
    got = page.locator("#pk-set-grid .set-field").evaluate_all("els => els.map(e => e.dataset.setting)")
    check(tag + "the form has one field per schema entry, in order", got == keys, (got, keys))
    kinds = {k: page.evaluate("k => { const e = document.querySelector('#pk-set-grid [data-key=\"' + k + '\"]'); return e.tagName + ':' + (e.type || ''); }", k)
             for k in keys}
    want = {"interval": "INPUT:number", "name": "INPUT:text", "mode": "SELECT:select-one", "token": "INPUT:password",
            "debug": "INPUT:checkbox", "listen": "INPUT:number", "hosts": "TEXTAREA:textarea", "gateway": "INPUT:text"}
    check(tag + "each type draws its own control", all(kinds.get(k) == v for k, v in want.items()), kinds)
    imin = field(page, "interval").get_attribute("min"), field(page, "interval").get_attribute("max")
    check(tag + "the number field carries the schema's limits", imin == ("5", "3600"), imin)
    lim = page.locator('[data-setting="interval"] .set-limits').inner_text()
    check(tag + "the limits are also written as text", "5 to 3600" in lim, lim)
    check(tag + "a secret is a password field and nothing is prefilled",
          field(page, "token").input_value() == "" and (field(page, "token").get_attribute("placeholder") or "") != "")

    # 2. the hint shows on hover and on keyboard focus, and is wired to the field
    hint = page.locator('[data-setting="interval"] .set-hint')
    page.mouse.move(0, 0)
    field(page, "name").focus()
    check(tag + "a hint is hidden while its field is not hovered or focused", not hint.is_visible())
    if width > 600:
        page.locator('[data-setting="interval"]').hover()
        check(tag + "the hint shows on hover", hint.is_visible() and "seconds" in hint.inner_text().lower(), hint.inner_text())
        page.mouse.move(0, 0)
    field(page, "interval").focus()
    check(tag + "the hint shows on keyboard focus", hint.is_visible())
    desc = field(page, "interval").get_attribute("aria-describedby") or ""
    hid = hint.get_attribute("id") or ""
    check(tag + "the field is described by its hint (aria-describedby)", hid and hid in desc.split(), (hid, desc))

    # 3. contrast and overflow
    r = page.evaluate(CONTRAST_JS)
    check(tag + f"contrast: {r['checked']} text nodes, scheme follows the device (dark={r['dark']})",
          not r["bad"] and r["dark"] == (scheme == "dark"), r["bad"][:5])
    field(page, "interval").focus()
    r2 = page.evaluate(CONTRAST_JS)
    check(tag + "contrast holds with a hint open", not r2["bad"], r2["bad"][:5])
    ov = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    check(tag + "no horizontal scroll", ov <= 1, ov)
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.locator("#pk-settings-card").screenshot(path=f"{SHOTS}/plugin-settings-{width}-{scheme}.png")

    if WRITE and mode == "full":
        cur = api(page, f"/api/packages/plugins/{PLUGIN}/settings")["json"]["settings"]
        before = {s["key"]: s["value"] for s in cur}
        # 5. out of range
        fill_valid(page, 4, SECRET1, "fast", True, ["10.1.1.1", "2001:db8::1"], "good-name")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_selector("#pk-set-err.on", timeout=10000)
        msg = page.locator("#pk-set-err").inner_text()
        check(tag + "an out-of-range number is refused on the page, with the reason", "between 5 and 3600" in msg, msg)
        check(tag + "the refused field is marked invalid", field(page, "interval").get_attribute("aria-invalid") == "true")
        after = {s["key"]: s["value"] for s in api(page, f"/api/packages/plugins/{PLUGIN}/settings")["json"]["settings"]}
        check(tag + "a refusal stores nothing (not even the valid fields)", after == before, (before, after))
        check(tag + "the secret of a refused save was not stored",
              not [s for s in api(page, f"/api/packages/plugins/{PLUGIN}/settings")["json"]["settings"] if s["key"] == "token" and s["is_set"]])
        # 6. pattern
        field(page, "interval").fill("90")
        field(page, "name").fill("Bad Name!")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_function("document.getElementById('pk-set-err').textContent.includes('format')", timeout=10000)
        msg = page.locator("#pk-set-err").inner_text()
        check(tag + "a value that breaks the pattern is refused, naming the field", "Instance name" in msg and "format" in msg, msg)
        # a bad list entry and a bad address
        field(page, "name").fill("good-name")
        field(page, "hosts").fill("10.1.1.1\nnot-an-address")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_function("document.getElementById('pk-set-err').textContent.includes('entry 2')", timeout=10000)
        check(tag + "a bad list entry is refused, naming the entry", "Allowed hosts entry 2" in page.locator("#pk-set-err").inner_text())
        field(page, "hosts").fill("10.1.1.1\n2001:db8::1")
        field(page, "gateway").fill("999.1.1.1")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_function("document.getElementById('pk-set-err').textContent.includes('address')", timeout=10000)
        check(tag + "a bad address is refused", "address" in page.locator("#pk-set-err").inner_text())
        field(page, "gateway").fill("")
        # a port below the schema's lower limit
        field(page, "listen").fill("80")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_function("document.getElementById('pk-set-err').textContent.includes('1024')", timeout=10000)
        msg = page.locator("#pk-set-err").inner_text()
        check(tag + "a port under the schema limit is refused", "1024" in msg and "Listen port" in msg, msg)
        field(page, "listen").fill("18081")

        # 7. a valid save
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_selector("#pk-set-ok.on", timeout=15000)
        check(tag + "a valid save is accepted and the page says so", "Saved" in page.locator("#pk-set-ok").inner_text())
        page.reload()
        open_settings(page)
        check(tag + "a reload shows the saved values",
              field(page, "interval").input_value() == "90" and field(page, "mode").input_value() == "fast"
              and field(page, "debug").is_checked() and field(page, "name").input_value() == "good-name"
              and field(page, "hosts").input_value() == "10.1.1.1\n2001:db8::1")
        check(tag + "the secret field comes back empty, with 'a value is saved'",
              field(page, "token").input_value() == "" and "saved" in page.locator('[data-setting="token"] .set-secret-state').inner_text())
        page_text = page.content() + page.inner_text("body") + json.dumps(page.evaluate(
            "[...document.querySelectorAll('input,textarea,select')].map(e => e.value)"))
        check(tag + "the secret is nowhere in the page", SECRET1 not in page_text)
        for url in ("/api/packages", f"/api/packages/plugins/{PLUGIN}/settings"):
            r = api(page, url)
            check(tag + f"{url} never carries the secret", SECRET1 not in r["body"] and r["status"] == 200, r["body"][:200])
        # 8. the file and the service
        if SETTINGS_FILE:
            mode, doc = read_file()
            check(tag + "the plugin's settings file is mode 0600", mode == 0o600, oct(mode))
            check(tag + "the saved values reached the file",
                  doc.get("interval") == 90 and doc.get("token") == SECRET1 and doc.get("mode") == "fast"
                  and doc.get("debug") is True and doc.get("hosts") == ["10.1.1.1", "2001:db8::1"] and doc.get("listen") == 18081, doc)
            env = open(SETTINGS_FILE.replace(".json", ".env")).read()
            check(tag + "the shell-style file carries them too", "PLUGIN_INTERVAL='90'" in env and f"PLUGIN_TOKEN='{SECRET1}'" in env, env)
        if PLUGIN_URL:
            ok, last = plugin_serves(90, SECRET1)
            check(tag + "the plugin's own service reads and serves the new values", ok, last)
        # an empty secret keeps the stored one; the clear box removes it
        field(page, "interval").fill("120")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_selector("#pk-set-ok.on", timeout=15000)
        if SETTINGS_FILE:
            _, doc = read_file()
            check(tag + "an empty secret keeps the saved one", doc.get("token") == SECRET1 and doc.get("interval") == 120, doc)

    if WRITE and mode == "phone" and SETTINGS_FILE:
        fill_valid(page, 300, SECRET2, "safe", False, ["192.0.2.7"], "phone-name")
        page.click("#pk-settings-form button[type=submit]")
        page.wait_for_selector("#pk-set-ok.on", timeout=15000)
        mode, doc = read_file()
        check(tag + "a save from the phone layout reaches the file",
              mode == 0o600 and doc.get("interval") == 300 and doc.get("token") == SECRET2 and doc.get("hosts") == ["192.0.2.7"], doc)
        if PLUGIN_URL:
            ok, last = plugin_serves(300, SECRET2)
            check(tag + "and the service serves it", ok, last)
        r = api(page, "/api/packages")
        check(tag + "the new secret is not in the API either", SECRET2 not in r["body"])

    check(tag + "no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for kind in kinds:
            run_combo(p, kind, 1280, "light", "full")
            run_combo(p, kind, 1280, "dark", None)
            run_combo(p, kind, 390, "light", None)
            run_combo(p, kind, 390, "dark", "phone")
    print("FAILED: " + (", ".join(failures) if failures else "none"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
