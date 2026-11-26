#!/usr/bin/env python3
"""Browser check of the notification matcher editor (System > Events and notifications > Notification matchers).

Signs in, then in each browser (Firefox by default; Chromium when installed):
  1. builds a tree through the page only: groups (all / any / not), a kind leaf, a severity leaf, a subject leaf and a
     calendar leaf (weekday toggles + start/end time pickers), moved with the buttons (up, down, indent, outdent), with
     the keyboard (Alt+arrow keys, Delete) and by drag and drop between groups; the refusals (a second item in a "not",
     a group dropped inside itself) are announced in the status line and change nothing;
  2. saves it and requires GET /api/system/matchers to carry exactly the tree on screen; reloads the page and requires
     the editor to show the same tree again;
  3. "Preview" marks each recent event as sent / not sent the way the API says;
  4. a channel is pointed at the matcher from the channel list; deleting a matcher that a channel uses is refused;
  5. at 1280 px and at a 390 px phone width, in the light and the dark scheme (switched live with emulate_media, as a
     device does): no sideways scrolling, every row inside the card, every text >= WCAG AA contrast, every button at
     least 24x24 px, no JavaScript error. Screenshots of each width x scheme go to E2E_SHOTS when it names a directory.

Usage: BASE_URL=https://192.0.2.1 E2E_USER=admin E2E_PASSWORD=... [E2E_SHOTS=dir] [E2E_CONTRAST=path/to/contrast.js] \\
       notify-matchers-page-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
SHOTS = os.environ.get("E2E_SHOTS", "")
HERE = os.path.dirname(os.path.abspath(__file__))
CONTRAST = os.environ.get("E2E_CONTRAST") or next(
    (p for p in (os.path.join(HERE, "contrast.js"), os.path.join(HERE, "a11y", "contrast.js")) if os.path.exists(p)), "")

failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:700]), flush=True)
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


DOM_TREE = """() => {
  const walk = (li) => {
    const row = li.querySelector(':scope > .nm-row');
    const op = row.querySelector(':scope > .nm-op').textContent.trim();
    const kids = [...li.querySelectorAll(':scope > ul > li')].map(walk);
    return {label: op, summary: row.getAttribute('aria-label'), items: kids};
  };
  return walk(document.querySelector('#nm-tree > li'));
}"""


def shape(t):
    """compact text form of the on-screen tree: ALL(ANY(event kind x, ...), ...)"""
    if t["label"] in ("All of", "Any of", "Not"):
        return t["label"].split()[0].upper() + "(" + ", ".join(shape(c) for c in t["items"]) + ")"
    return t["summary"]


def tree(page):
    return shape(page.evaluate(DOM_TREE))


def say(page):
    return page.locator("#nm-status").inner_text()


def add(group_row, what):
    group_row.locator("select[aria-label='Add an item to this group']").select_option(label=what)


def row_with(page, text):
    return page.locator(f"#nm-tree .nm-row[aria-label*='{text}']").first


def drag(page, src, dst, where):
    """HTML5 drag and drop of the row `src` onto `dst` at 'before' | 'after' | 'into'"""
    box = dst.bounding_box()
    y = box["y"] + box["height"] * {"before": 0.1, "into": 0.5, "after": 0.9}[where]
    x = box["x"] + box["width"] / 2
    dt = page.evaluate_handle("() => new DataTransfer()")
    src.dispatch_event("dragstart", {"dataTransfer": dt})
    dst.dispatch_event("dragover", {"dataTransfer": dt, "clientX": x, "clientY": y})
    dst.dispatch_event("drop", {"dataTransfer": dt, "clientX": x, "clientY": y})
    src.dispatch_event("dragend", {"dataTransfer": dt})


def run(p, kind):
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 1100})
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

    page.goto(BASE + "/system")
    page.wait_for_selector("#nm-tree .nm-row", timeout=20000)
    check(tag + "the editor is on the system page", page.locator("#nm-card").count() == 1)
    check(tag + "a new matcher starts as an empty 'all' group", tree(page) == "ALL()", tree(page))

    # ---- build the tree
    root = page.locator("#nm-tree .nm-row").first
    add(root, "Any of")
    anyrow = row_with(page, "Any of group")
    add(anyrow, "Event kind")
    kindrow = row_with(page, "event kind")
    kindrow.locator("summary").click()
    kindrow.locator("label:has-text('gateway_down') input").check()
    kindrow.locator("label:has-text('tunnel_down') input").check()
    ksum = kindrow.locator("summary").inner_text()
    check(tag + "kind leaf lists the ticked kinds", "gateway_down" in ksum and "tunnel_down" in ksum, ksum)
    add(anyrow, "Severity at least")
    row_with(page, "severity at least").locator("select[aria-label='Minimum severity']").select_option("warning")
    add(root, "Time window")
    cal = row_with(page, "time window")
    cal.locator("button.nm-day", has_text="Sat").click()   # Mon-Fri by default: add Sat, drop Mon
    cal.locator("button.nm-day", has_text="Mon").click()
    check(tag + "weekday toggles report their state", cal.locator("button.nm-day[aria-pressed=true]").count() == 5
          and cal.locator("button.nm-day", has_text="Mon").get_attribute("aria-pressed") == "false")
    cal.locator("input[aria-label='Start time']").fill("22:00")
    cal.locator("input[aria-label='End time']").fill("06:00")
    add(root, "Not")
    notrow = row_with(page, "Not group")
    add(notrow, "About matches")
    row_with(page, "about matches").locator("input[aria-label='Name pattern']").fill("guest*")
    t = tree(page)
    check(tag + "the tree built through the page",
          t.startswith("ALL(ANY(event kind gateway_down, tunnel_down, severity at least warning), time window")
          and t.endswith("NOT(about matches guest*))"), t)

    add(notrow, "Severity at least")
    check(tag + "a second item in a 'not' is refused and announced", "exactly one" in say(page), say(page))
    check(tag + "...and nothing was added", tree(page).endswith("NOT(about matches guest*))"), tree(page))

    # ---- buttons
    row_with(page, "time window").get_by_role("button", name="Move up").click()
    check(tag + "Move up puts the window above the any group", tree(page).startswith("ALL(time window"), tree(page))
    row_with(page, "time window").get_by_role("button", name="Move down").click()
    check(tag + "Move down puts it back", tree(page).startswith("ALL(ANY("), tree(page))
    row_with(page, "severity at least").get_by_role("button", name="Outdent").click()
    check(tag + "Outdent moves a leaf out of its group",
          tree(page).startswith("ALL(ANY(event kind gateway_down, tunnel_down), severity at least warning"), tree(page))
    row_with(page, "severity at least").get_by_role("button", name="Indent").click()
    check(tag + "Indent moves it into the group above",
          tree(page).startswith("ALL(ANY(event kind gateway_down, tunnel_down, severity at least warning), time window"), tree(page))

    # ---- keyboard
    row_with(page, "about matches").focus()
    page.keyboard.press("Alt+ArrowLeft")
    check(tag + "Alt+Left outdents the focused item", tree(page).endswith("NOT(), about matches guest*)"), tree(page))
    active = page.evaluate("() => document.activeElement.getAttribute('aria-label')")
    check(tag + "focus stays on the moved item", active == "about matches guest*", active)
    page.keyboard.press("Alt+ArrowDown")   # already last: nothing moves
    check(tag + "Alt+Down on the last item changes nothing", tree(page).endswith("NOT(), about matches guest*)"), tree(page))
    page.keyboard.press("Alt+ArrowUp")
    check(tag + "Alt+Up moves it above the 'not'", tree(page).endswith("about matches guest*, NOT())"), tree(page))
    page.keyboard.press("Alt+ArrowDown")
    page.keyboard.press("Alt+ArrowRight")
    check(tag + "Alt+Right indents it into the 'not' again", tree(page).endswith("NOT(about matches guest*))"), tree(page))

    # ---- drag and drop
    drag(page, row_with(page, "time window"), row_with(page, "Not group"), "into")
    check(tag + "dropping a second item into a 'not' is refused",
          "exactly one" in say(page) and tree(page).endswith("NOT(about matches guest*))"), (say(page), tree(page)))
    drag(page, row_with(page, "time window"), row_with(page, "Any of group"), "into")
    check(tag + "dragging a leaf onto a group puts it inside",
          "ALL(ANY(event kind gateway_down, tunnel_down, severity at least warning, time window" in tree(page), tree(page))
    drag(page, row_with(page, "Any of group"), row_with(page, "event kind"), "after")
    check(tag + "a group cannot be dropped inside itself", "inside itself" in say(page), say(page))
    drag(page, row_with(page, "time window"), row_with(page, "Not group"), "before")
    want = tree(page)
    check(tag + "dragging out of a group, before another row",
          want.startswith("ALL(ANY(event kind gateway_down, tunnel_down, severity at least warning), time window ") and ", NOT(about matches guest*)" in want, want)
    add(root, "Severity at least")
    page.locator("#nm-tree > li > ul > li > .nm-row[aria-label='severity at least warning']").last.focus()
    page.keyboard.press("Delete")
    check(tag + "Delete removes the focused item", tree(page) == want, tree(page))

    # ---- save and reload
    page.fill("#nm-name", "e2e-night")
    page.fill("#nm-desc", "built by the browser test")
    page.click("#nm-save")
    page.wait_for_function("document.getElementById('nm-status').textContent.includes('Saved')", timeout=10000)
    got = api(page, "/api/system/matchers")["json"]
    m = [x for x in got if x["name"] == "e2e-night"]
    exp = {"op": "all", "items": [
        {"op": "any", "items": [{"op": "kind", "kinds": ["gateway_down", "tunnel_down"]}, {"op": "severity", "min": "warning"}]},
        {"op": "calendar", "days": ["tue", "wed", "thu", "fri", "sat"], "start": "22:00", "end": "06:00"},
        {"op": "not", "items": [{"op": "subject", "glob": "guest*"}]}]}
    check(tag + "the saved tree in the API equals the one on screen (kinds, weekdays, times, glob)",
          len(m) == 1 and m[0]["tree"] == exp, m)
    page.reload()
    page.wait_for_selector("#nm-tree .nm-row", timeout=20000)
    page.select_option("#nm-select", "e2e-night")
    check(tag + "after a reload the editor shows the saved tree", tree(page) == want, tree(page))

    # ---- preview
    page.click("#nm-preview")
    page.wait_for_selector("#nm-preview-table tbody tr", timeout=10000)
    prev = page.evaluate("""() => [...document.querySelectorAll('#nm-preview-table tbody tr')].map(tr =>
        [...tr.children].map(td => td.textContent.trim()))""")
    ap = api(page, "/api/system/matchers/preview", "POST", {"tree": exp})["json"]
    check(tag + "preview lists the recent events", len(prev) == ap["total"] and len(prev) > 0, (len(prev), ap["total"]))
    check(tag + "preview marks each event Yes / No as the API says",
          sum(1 for r in prev if r[-1] == "Yes") == ap["matched"], (prev, ap))
    check(tag + "the summary line says how many would be sent", f"{ap['matched']} of {ap['total']}" in say(page), say(page))

    # ---- a channel uses it
    api(page, "/api/system/hooks", "POST", {"name": "e2e-hook", "url": "http://192.0.2.9:9/x"})
    page.reload()
    page.wait_for_selector("#hooks-table tbody tr[data-hook=e2e-hook] select", timeout=20000)
    page.select_option("#nm-select", "e2e-night")
    page.locator("#hooks-table tbody tr[data-hook=e2e-hook] select").select_option("e2e-night")
    page.wait_for_timeout(800)
    hooks = api(page, "/api/system/hooks")["json"]
    check(tag + "the channel list points the channel at the matcher",
          [h["matcher"] for h in hooks if h["name"] == "e2e-hook"] == ["e2e-night"], hooks)
    page.wait_for_function("document.getElementById('nm-used').textContent.includes('e2e-hook')", timeout=10000)
    used = page.locator("#nm-used").inner_text()
    check(tag + "the editor says which channel uses it", "e2e-hook" in used, used)
    page.click("#nm-delete")
    page.wait_for_function("document.getElementById('nm-status').textContent.includes('Not deleted')", timeout=10000)
    check(tag + "deleting a matcher that is in use is refused on the page", "e2e-hook" in say(page), say(page))

    # ---- layout and contrast per width x scheme
    page.click("#nm-preview")
    page.wait_for_selector("#nm-preview-table tbody tr")
    contrast = open(CONTRAST).read() if CONTRAST else ""
    check(tag + "the contrast scanner is available", bool(contrast), "set E2E_CONTRAST")
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 1100})
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            page.add_style_tag(content="*{transition:none!important;animation:none!important}")
            page.wait_for_timeout(250)
            card = page.locator("#nm-card")
            card.scroll_into_view_if_needed()
            over = page.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
            check(tag + f"{width}px {scheme}: no sideways scrolling", over <= 1, over)
            outside = page.evaluate("""() => { const r = document.getElementById('nm-card').getBoundingClientRect();
                return [...document.querySelectorAll('#nm-card .nm-row')].filter(e => e.getBoundingClientRect().right > r.right + 1).length; }""")
            check(tag + f"{width}px {scheme}: every tree row stays inside the card", outside == 0, outside)
            if contrast:
                res = page.evaluate(contrast)
                mine = [b for b in res["bad"]]
                check(tag + f"{width}px {scheme}: text contrast >= WCAG AA ({res['checked']} texts on the page)", not mine, mine[:6])
            small = page.evaluate("""() => [...document.querySelectorAll('#nm-card button')].filter(b => {
                const r = b.getBoundingClientRect(); return r.width > 0 && (r.width < 24 || r.height < 24); }).length""")
            check(tag + f"{width}px {scheme}: every button is at least 24x24 px", small == 0, small)
            if SHOTS:
                os.makedirs(SHOTS, exist_ok=True)
                card.screenshot(path=os.path.join(SHOTS, f"{kind}-{width}-{scheme}.png"))
    page.emulate_media(color_scheme="light")
    check(tag + "no JavaScript error", not errors, errors)

    for h in api(page, "/api/system/hooks")["json"]:
        if h["name"] == "e2e-hook":
            api(page, f"/api/system/hooks/{h['id']}", "DELETE")
    api(page, "/api/system/matchers/e2e-night", "DELETE")
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    with sync_playwright() as p:
        for k in kinds:
            run(p, k)
    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
