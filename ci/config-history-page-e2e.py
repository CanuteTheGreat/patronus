#!/usr/bin/env python3
"""Browser journey for System > Configuration history (real Firefox, Playwright), run against the shipped patronus-web.

  1. make two changes (two firewall rules, through the API the Firewall page uses): each records a revision;
  2. /history lists the revision with its source and label, the menu has the entry;
  3. Diff shows a readable per-section diff against the running configuration, no secret in it;
  4. Restore (confirm step) puts the earlier configuration back: the later rule is gone, the earlier one remains,
     and the restore itself is a new revision;
  5. the same page at 390 px phone width: no sideways scroll, actions reachable, dialog fits;
  6. confirm-or-revert timer: set 30 s on the page; a firewall change shows the banner on the Firewall page;
     "Revert now" removes the change, "Keep changes" keeps it; timer back to off;
  7. no JavaScript errors anywhere.
Usage: BASE_URL=https://192.0.2.1:8443 E2E_USER=admin E2E_PASSWORD=... config-history-page-e2e.py [firefox|chromium]
Exit 0 = every check passed."""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
fails = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        fails.append(name)


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


def rule(name):
    return {"name": name, "chain": "input", "action": "accept", "interface": "@lan", "protocol": "tcp",
            "source": "any", "destination": "any", "port": "2222", "description": name, "enabled": True}


def rule_names(page):
    j = api(page, "/api/firewall/rules")["json"]
    rows = j if isinstance(j, list) else (j or {}).get("rules", [])
    return {r["name"]: r.get("id") for r in rows}


def run(browser_name):
    with sync_playwright() as p:
        b = getattr(p, browser_name).launch(headless=True)
        ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        errs = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        page.goto(BASE + "/login")
        page.fill("#username", os.environ["E2E_USER"])
        page.fill("#password", os.environ["E2E_PASSWORD"])
        page.click("button[type=submit]")
        page.wait_for_url(lambda u: not u.endswith("/login"), timeout=30000)
        tag = browser_name + "-" + str(os.getpid())
        keep, undo = "hist-keep-" + tag, "hist-undo-" + tag

        # 1. two changes
        r1 = api(page, "/api/firewall/rules", "POST", rule(keep))
        check("change 1 accepted", r1["status"] in (200, 201), r1["body"])
        r2 = api(page, "/api/firewall/rules", "POST", rule(undo))
        check("change 2 accepted", r2["status"] in (200, 201), r2["body"])

        # 2. the page
        page.goto(BASE + "/history")
        page.wait_for_selector("#history-table", state="visible", timeout=30000)
        check("menu has the Configuration history entry", page.locator("a.nav-item[href='/history']").count() == 1)
        row = page.locator("#history-table tbody tr", has_text="create firewall rule " + undo).first
        check("revision listed with its label", row.count() == 1)
        check("revision shows its source", "web" in row.inner_text(), row.inner_text())
        check("revision shows a time", "UTC" in row.inner_text(), row.inner_text())
        rev_id = row.get_attribute("data-revision")

        # 3. diff
        row.locator("button[data-action=diff]").click()
        page.wait_for_selector("#rev-dialog[open] .diff-section", timeout=30000)
        text = page.inner_text("#rev-dialog")
        check("diff names the section", "Firewall rules" in text, text)
        check("diff says what restoring would remove", "removed" in text.lower() and undo in text, text)
        check("diff does not show the kept rule as a change", keep not in text, text)
        check("diff shows no secret", "password_hash" not in text and "$argon2" not in text, text)
        check("diff offers the restore", page.is_visible("#rev-restore"))

        # 4. restore (confirm step)
        page.click("#rev-restore")
        check("restore asks for confirmation first", page.inner_text("#rev-restore") == "Confirm restore", page.inner_text("#rev-restore"))
        check("nothing restored before the confirmation", undo in rule_names(page))
        page.click("#rev-restore")
        page.wait_for_function("() => document.getElementById('history-msg').textContent.startsWith('Restored revision')", timeout=60000)
        names = rule_names(page)
        check("restored: the later change is gone", undo not in names, names)
        check("restored: the earlier change remains", keep in names, names)
        page.wait_for_function("() => document.querySelectorAll('#history-table tbody tr').length > 0")
        check("the restore is itself a revision", page.locator("#history-table tbody tr", has_text="before restore of revision " + rev_id).count() >= 1)

        # 5. phone width
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(BASE + "/history")
        page.wait_for_selector("#history-table tbody tr", state="visible", timeout=30000)
        check("390 px: no sideways scroll", page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"),
              page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]"))
        btn = page.locator("#history-table tbody tr button[data-action=diff]").first
        check("390 px: row actions reachable", btn.is_visible() and btn.bounding_box()["width"] > 40)
        btn.click()
        page.wait_for_selector("#rev-dialog[open] #rev-body", timeout=30000)
        box = page.locator("#rev-dialog").bounding_box()
        check("390 px: dialog fits the screen", box["x"] >= 0 and box["x"] + box["width"] <= 391, box)
        page.click("#rev-close")
        page.set_viewport_size({"width": 1280, "height": 900})

        # 6. confirm-or-revert timer
        page.goto(BASE + "/history")
        page.fill("#confirm-seconds", "30")
        page.click("#confirm-save")
        page.wait_for_function("() => document.getElementById('history-msg').textContent.includes('Saved')", timeout=30000)
        check("timer saved", api(page, "/api/system/history/settings")["json"]["confirm_seconds"] == 30)
        for label, button, kept in (("revert", "#confirm-revert", False), ("keep", "#confirm-keep", True)):
            nm = "hist-timer-%s-%s" % (label, tag)
            r = api(page, "/api/firewall/rules", "POST", rule(nm))
            check("timer: change %s accepted" % label, r["status"] in (200, 201), r["body"])
            page.goto(BASE + "/firewall")
            page.wait_for_selector("#confirm-banner", state="visible", timeout=30000)
            check("timer: banner counts down (%s)" % label, "reverting in" in page.inner_text("#confirm-banner-text"), page.inner_text("#confirm-banner-text"))
            page.click(button)
            page.wait_for_selector("#confirm-banner", state="hidden", timeout=30000)
            page.wait_for_timeout(1500)
            present = nm in rule_names(page)
            check("timer: %s -> change %s" % (label, "kept" if kept else "reverted"), present == kept, rule_names(page))
        page.goto(BASE + "/history")
        page.fill("#confirm-seconds", "0")
        page.click("#confirm-save")
        page.wait_for_function("() => document.getElementById('history-msg').textContent.includes('off')", timeout=30000)
        check("timer off again", api(page, "/api/system/history/settings")["json"]["confirm_seconds"] == 0)

        # cleanup of what this run created
        for n, i in rule_names(page).items():
            if n.endswith(tag):
                api(page, "/api/firewall/rules/%s" % i, "DELETE")
        check("no JavaScript errors", not errs, errs)
        b.close()


run(sys.argv[1] if len(sys.argv) > 1 else "firefox")
print("FAILED: " + (", ".join(fails) if fails else "none"))
sys.exit(1 if fails else 0)
