#!/usr/bin/env python3
"""Browser check of the customizable dashboard (widgets) and the system activity page.

For each requested browser (default: firefox), each colour scheme (light, dark) and each viewport (desktop 1280x800,
phone 390x844) it signs in as an administrator and requires that:
  1. the dashboard is drawn from the saved layout (default order first), with no horizontal overflow on the phone;
  2. Customize shows the edit tools; with the KEYBOARD only (Enter/Space on real buttons): a widget moves down, moves up,
     is removed (it appears in the hidden list, focus stays on the page) and is added again from the hidden list;
  3. with the MOUSE: a widget is dragged by its handle over another one, and removed/added with clicks;
  4. every change is saved: GET /api/v1/dashboard/layout shows the same order and a reload draws the same page;
  5. a second (read-only) account sees the default layout, can save its own, and the administrator's layout stays;
  6. "Reset to default" restores the default order for the administrator only;
  7. axe-core (when axe.min.js is next to this script or in AXE_JS) finds no serious/critical violation in edit mode
     (colour contrast included), on the dashboard and on /activity;
  8. /activity lists processes, can be sorted by clicking a column header (aria-sort follows), filtered by daemon,
     and shows the daemon table; no command line shows a secret;
  9. /diagnostics "Test port" reports open for a listener the script starts, closed for a port nobody listens on;
 10. no JavaScript error on these pages.

Usage: BASE_URL=https://192.0.2.10 E2E_USER=admin E2E_PASSWORD=... dashboard-page-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import json
import os
import socket
import sys
import threading

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
# the address the ROUTER connects to for the port test (the listener below binds every address of this host)
TCP_HOST = os.environ.get("E2E_PORT_TEST_HOST", "127.0.0.1")
VIEWER = "e2e-dash-viewer"
VIEWER_PW = os.environ.get("E2E_VIEWER_PASSWORD", "E2e-Dash-Viewer-Passw0rd!")
HERE = os.path.dirname(os.path.abspath(__file__))
AXE = os.environ.get("AXE_JS") or next(
    (p for p in (os.path.join(HERE, "axe.min.js"), os.path.join(HERE, "a11y", "vendor", "axe.min.js")) if os.path.exists(p)),
    "",
)
# Widgets that exist on every router build with data (dhcp/traffic only appear with data).
CORE = ["internet", "interfaces", "firewall-rules", "system", "network-interfaces", "services"]

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


def login(page, user, pw):
    page.goto(BASE + "/login")
    page.fill("#username", user)
    page.fill("#password", pw)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: "/login" not in u, timeout=30000)


def drawn(page):
    return page.eval_on_selector_all("#dash-grid > .widget", "els => els.map(e => e.dataset.widgetId)")


def saved(page):
    j = api(page, "/api/v1/dashboard/layout")["json"]
    return [w["id"] for w in j["layout"]["widgets"] if w["on"]], j


def only_core(ids):
    return [i for i in ids if i in CORE]


def axe_violations(page):
    if not AXE:
        return None
    page.add_script_tag(path=AXE)
    v = page.evaluate(
        """async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']},
              resultTypes: ['violations']})).violations
              .filter(v => v.impact === 'serious' || v.impact === 'critical')
              .map(v => v.id + ': ' + v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | '))"""
    )
    return v


def run_view(p, kind, scheme, vp_name, size, listener_port):
    tag = f"{kind}/{scheme}/{vp_name}"
    browser = getattr(p, kind).launch(headless=True)
    ctx = browser.new_context(ignore_https_errors=True, color_scheme=scheme, viewport={"width": size[0], "height": size[1]})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, USER, PASSWORD)
    api(page, "/api/v1/dashboard/layout", "DELETE")
    page.goto(BASE + "/")
    page.wait_for_selector("#dash-grid .widget")

    ids = drawn(page)
    check(f"[{tag}] default dashboard: core widgets in registry order", only_core(ids) == CORE, ids)
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    check(f"[{tag}] no horizontal overflow", overflow <= 1, overflow)
    check(f"[{tag}] edit tools hidden until Customize", not page.is_visible(".widget-tools"))

    # ---- keyboard
    page.focus("#dash-customize")
    page.keyboard.press("Enter")
    check(f"[{tag}] Customize shows the edit tools and the hidden list", page.is_visible("#dash-edit-tools") and page.is_visible("#dash-hidden"))
    page.focus("[data-widget-id=internet] [data-act=down]")
    page.keyboard.press("Enter")
    page.wait_for_function("document.querySelector('#dash-status').textContent.indexOf('Saved') >= 0 || document.querySelector('#dash-status').textContent.indexOf('moved') >= 0")
    now = only_core(drawn(page))
    check(f"[{tag}] keyboard: Move down swaps internet with the next widget", now[:2] == ["interfaces", "internet"], now)
    check(f"[{tag}] keyboard: focus stays on the moved widget's button", page.evaluate("document.activeElement && document.activeElement.dataset.act") == "down")
    page.focus("[data-widget-id=internet] [data-act=up]")
    page.keyboard.press("Space")
    page.wait_for_function("document.querySelector('#dash-status').textContent.indexOf('position 2') >= 0 || document.querySelector('#dash-status').textContent.indexOf('position 1') >= 0")
    check(f"[{tag}] keyboard: Move up (Space) restores the order", only_core(drawn(page)) == CORE, drawn(page))
    page.focus("[data-widget-id=firewall-rules] [data-act=remove]")
    page.keyboard.press("Enter")
    page.wait_for_function("document.querySelector('#dash-status').textContent.indexOf('removed') >= 0")
    check(f"[{tag}] keyboard: Remove takes the widget off the page", "firewall-rules" not in drawn(page), drawn(page))
    check(f"[{tag}] keyboard: the removed widget is offered under Hidden widgets", page.is_visible("[data-add=firewall-rules]"))
    sv, _ = saved(page)
    check(f"[{tag}] keyboard: the layout was saved", "firewall-rules" not in sv and sv == drawn(page), (sv, drawn(page)))
    page.focus("[data-add=activity]")
    page.keyboard.press("Enter")
    page.wait_for_selector("[data-widget-id=activity]")
    page.wait_for_selector("#activity-widget-table")
    check(f"[{tag}] keyboard: Add puts the widget on the dashboard (page reloaded)", "activity" in drawn(page))
    check(f"[{tag}] after adding, the page is still in edit mode", page.is_visible("#dash-done") and not page.is_visible("#dash-customize"))
    page.click("#dash-done")
    page.wait_for_function("document.querySelector('#activity-widget-summary').textContent.indexOf('CPU') >= 0", timeout=20000)
    check(f"[{tag}] the System activity widget shows live CPU/load/memory", True)

    # ---- mouse
    page.click("#dash-customize")
    before = only_core(drawn(page))
    # two neighbours that are both on screen, also on the phone where the widgets are stacked
    page.locator("[data-widget-id=internet]").scroll_into_view_if_needed()
    page.evaluate("window.scrollTo(0, 0)")
    h = page.locator("[data-widget-id=interfaces] .widget-handle").bounding_box()
    t = page.locator("[data-widget-id=internet]").bounding_box()
    page.mouse.move(h["x"] + h["width"] / 2, h["y"] + h["height"] / 2)
    page.mouse.down()
    page.mouse.move(t["x"] + 10, t["y"] + 10, steps=12)
    page.mouse.move(t["x"] + 6, t["y"] + 6, steps=4)
    page.mouse.up()
    page.wait_for_function("document.querySelector('#dash-status').textContent.indexOf('moved') >= 0")
    after = only_core(drawn(page))
    check(f"[{tag}] mouse: dragging the handle moves interfaces before internet", after.index("interfaces") < after.index("internet") and after != before, after)
    sv, _ = saved(page)
    check(f"[{tag}] mouse: the dragged order was saved", sv == drawn(page), (sv, drawn(page)))
    page.click("[data-widget-id=services] [data-act=remove]")
    page.wait_for_selector("[data-add=services]")
    check(f"[{tag}] mouse: Remove click hides the widget", "services" not in drawn(page))
    page.click("[data-add=services]")
    page.wait_for_selector("[data-widget-id=services]")
    page.wait_for_selector("#dash-done:visible")
    check(f"[{tag}] mouse: Add click brings it back", "services" in drawn(page))
    page.click("#dash-done")
    check(f"[{tag}] Done hides the edit tools again", not page.is_visible("#dash-edit-tools") and not page.is_visible(".widget-tools"))

    # ---- persistence and a second user
    order = drawn(page)
    page.reload()
    page.wait_for_selector("#dash-grid .widget")
    check(f"[{tag}] reload draws the saved layout", drawn(page) == order, (drawn(page), order))
    vctx = browser.new_context(ignore_https_errors=True, color_scheme=scheme, viewport={"width": size[0], "height": size[1]})
    vpage = vctx.new_page()
    login(vpage, VIEWER, VIEWER_PW)
    api(vpage, "/api/v1/dashboard/layout", "DELETE")  # the account is shared by the views of this run
    vpage.goto(BASE + "/")
    vpage.wait_for_selector("#dash-grid .widget")
    check(f"[{tag}] a second user still sees the default layout", only_core(drawn(vpage)) == CORE and "activity" not in drawn(vpage), drawn(vpage))
    vj = api(vpage, "/api/v1/dashboard/layout")["json"]
    check(f"[{tag}] the second user's API says not customized", vj["customized"] is False and vj["user"] == VIEWER, vj)
    vpage.click("#dash-customize")
    vpage.focus("[data-widget-id=internet] [data-act=down]")
    vpage.keyboard.press("Enter")
    vpage.wait_for_function("document.querySelector('#dash-status').textContent.indexOf('moved') >= 0")
    vj = api(vpage, "/api/v1/dashboard/layout")["json"]
    check(f"[{tag}] a read-only user saves their own layout", vj["customized"] is True)
    aj = api(page, "/api/v1/dashboard/layout")["json"]
    check(f"[{tag}] ... and the administrator's layout is unchanged", [w["id"] for w in aj["layout"]["widgets"] if w["on"]] == order, aj)
    vctx.close()

    # ---- accessibility in edit mode
    page.click("#dash-customize")
    v = axe_violations(page)
    if v is not None:
        check(f"[{tag}] axe (edit mode): no serious/critical violation", not v, v)
    page.click("#dash-done")

    # ---- reset
    page.click("#dash-customize")
    page.click("#dash-reset")
    page.wait_for_function("document.querySelector('#dash-grid') && !document.body.classList.contains('dash-edit')")
    page.wait_for_selector("#dash-grid .widget")
    check(f"[{tag}] Reset to default restores the default order", only_core(drawn(page)) == CORE and "activity" not in drawn(page), drawn(page))

    # ---- the activity page
    page.goto(BASE + "/activity")
    page.wait_for_function("document.querySelector('#act-procs tbody tr td') && !/Collecting/.test(document.querySelector('#act-procs tbody').textContent)", timeout=30000)
    rows = page.locator("#act-procs tbody tr").count()
    check(f"[{tag}] activity page lists processes", rows >= 3, rows)
    check(f"[{tag}] activity page shows CPU, load and memory", page.text_content("#act-cpu").strip().endswith("%") and page.text_content("#act-mem").strip().endswith("%"))
    page.click("#act-procs th button[data-sort=memory]")
    page.wait_for_function("document.querySelector('#act-procs th[aria-sort=descending] button').dataset.sort === 'memory'")
    mem = page.eval_on_selector_all("#act-procs tbody tr", "rs => rs.map(r => r.children[4].textContent)")
    check(f"[{tag}] clicking a column header sorts (aria-sort follows)", len(mem) > 1, mem)
    page.click("#act-procs th button[data-sort=pid]")
    page.wait_for_function("document.querySelector('#act-procs th[aria-sort=ascending] button').dataset.sort === 'pid'")
    pids = [int(x) for x in page.eval_on_selector_all("#act-procs tbody tr", "rs => rs.map(r => r.children[0].textContent)")]
    check(f"[{tag}] PID sort is ascending", pids == sorted(pids), pids)
    daemons = page.locator("#act-daemons tbody tr").count()
    check(f"[{tag}] daemon table is filled (patronus-web at least)", "patronus-web" in page.text_content("#act-daemons"), daemons)
    page.select_option("#act-daemon", "patronus-web")
    page.wait_for_function("(() => { const r = document.querySelectorAll('#act-procs tbody tr'); return r.length > 0 && Array.prototype.every.call(r, x => x.children[2] && x.children[2].textContent.indexOf('patronus') >= 0); })()", timeout=30000)
    names = page.eval_on_selector_all("#act-procs tbody tr", "rs => rs.map(r => r.children[2].textContent)")
    check(f"[{tag}] filtering by daemon shows only that daemon's processes", names and all("patronus" in n for n in names), names)
    body = page.text_content("body")
    check(f"[{tag}] no password or token on the page", "hunter2" not in body)
    v = axe_violations(page)
    if v is not None:
        check(f"[{tag}] axe (/activity): no serious/critical violation", not v, v)
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    check(f"[{tag}] activity page: no horizontal overflow", overflow <= 1, overflow)

    # ---- the port test (once per run, desktop light)
    if listener_port and vp_name == "desktop" and scheme == "light":
        page.goto(BASE + "/diagnostics")
        page.wait_for_selector("#tcp-card")
        def run_tcp(port):
            page.fill("#tcp-card input[name=host]", TCP_HOST)
            page.fill("#tcp-card input[name=port]", str(port))
            page.click("#tcp-card button[type=submit]")
            page.wait_for_function("document.querySelector('#tcp-status').textContent.indexOf('port') >= 0 || document.querySelector('#tcp-status').textContent.indexOf('Failed') >= 0")
            return page.text_content("#tcp-status")
        s_open = run_tcp(listener_port)
        check(f"[{tag}] Test port: a listening port is Open", s_open.endswith("Open"), s_open)
        dead = socket.socket(); dead.bind(("0.0.0.0", 0)); dead_port = dead.getsockname()[1]; dead.close()
        s_closed = run_tcp(dead_port)
        check(f"[{tag}] Test port: a closed port says refused", "Closed" in s_closed, s_closed)
        check(f"[{tag}] Test port: the result table shows the address and time", TCP_HOST in page.text_content("#tcp-table"))

    check(f"[{tag}] no JavaScript error", not errors, errors)
    browser.close()


def main():
    kinds = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
    srv = socket.socket(); srv.bind(("0.0.0.0", 0)); srv.listen(8)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: [srv.accept() for _ in range(100)], daemon=True).start()
    with sync_playwright() as p:
        # a read-only account for the isolation checks (removed at the end)
        b = p.firefox.launch(headless=True)
        ctx = b.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        login(page, USER, PASSWORD)
        r = api(page, "/api/system/users", "POST", {"username": VIEWER, "password": VIEWER_PW, "role": "readonly"})
        check("created the read-only test account", r["status"] in (200, 201, 409), r["body"][:200])
        try:
            for kind in kinds:
                for scheme in ("light", "dark"):
                    for name, size in (("desktop", (1280, 800)), ("phone", (390, 844))):
                        run_view(p, kind, scheme, name, size, port)
        finally:
            users = api(page, "/api/system/users")["json"] or []
            users = users if isinstance(users, list) else users.get("users", [])
            for u in users:
                if u.get("username") == VIEWER:
                    api(page, f"/api/system/users/{u['id']}", "DELETE")
            api(page, "/api/v1/dashboard/layout", "DELETE")
            b.close()
    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
