#!/usr/bin/env python3
"""Keyboard-only path through the firewall rule list: add, edit and delete a rule without touching the mouse.

Every step moves focus with Tab / Shift+Tab, picks select options by typing, opens and submits with Enter and
closes with Escape, the way a keyboard or screen-reader user works. It proves:

  * the login form, the "Add rule" button and each rule's "Edit" button are reachable by Tab (a control that is
    only clickable, or hidden from the tab order, fails here);
  * the rule dialog opens with focus on its first field, shows the port field only once TCP is picked, saves on
    Enter, keeps typed values on a validation error (empty name -> inline error, focus back on the name);
  * Escape closes the dialog and focus returns to the control that opened it;
  * the saved rule really exists through the API with the typed values, the edit changed it, the delete removed it.

Usage: BASE_URL=https://localhost:8443 E2E_USER=admin E2E_PASSWORD=... kbd_firewall_rule.py [--browser firefox]
"""
import argparse
import json
import os
import random
import string
import sys

from playwright.sync_api import sync_playwright

MAX_TABS = 400


def active(page):
    return page.evaluate("""() => { const a = document.activeElement; if (!a) return {};
        return { id: a.id || '', tag: a.tagName, label: a.getAttribute('aria-label') || '', text: (a.innerText || '').trim().slice(0, 40),
                 name: a.getAttribute('name') || '', inDialog: !!a.closest('dialog[open]') }; }""")


def tab_to(page, pred, what, back=False):
    """Press Tab (or Shift+Tab) until pred(active element) is true (already focused counts: autofocus)."""
    a = active(page)
    if pred(a):
        return a
    seen = []
    for _ in range(MAX_TABS):
        page.keyboard.press("Shift+Tab" if back else "Tab")
        a = active(page)
        if pred(a):
            return a
        seen.append(a.get("id") or a.get("label") or a.get("text") or a.get("tag", "?"))
    raise AssertionError(f"{what} is not reachable with the keyboard ({MAX_TABS} x {'Shift+' if back else ''}Tab); "
                         f"focus went through: {', '.join(dict.fromkeys(seen))[:600]}")


def rules(page, base):
    r = page.request.get(base + "/api/firewall/rules")
    assert r.ok, f"GET /api/firewall/rules -> {r.status}"
    d = r.json()
    return d if isinstance(d, list) else d.get("rules", d.get("items", []))


def find(page, base, name):
    return [r for r in rules(page, base) if r.get("name") == name]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", default=os.environ.get("BROWSER", "firefox"))
    ap.add_argument("--base", default=os.environ.get("BASE_URL", "https://localhost:8443"))
    a = ap.parse_args()
    base = a.base.rstrip("/")
    user, pw = os.environ.get("E2E_USER", "admin"), os.environ["E2E_PASSWORD"]
    name = "kbd-e2e-" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    steps = []

    def ok(s):
        steps.append(s)
        print("PASS", s, flush=True)

    with sync_playwright() as p:
        browser = getattr(p, a.browser).launch()
        ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        page.on("dialog", lambda d: d.accept())  # the native confirm() of a delete: Enter on its default button
        errs = []
        page.on("pageerror", lambda e: errs.append(str(e)[:200]))

        # login, keyboard only
        page.goto(base + "/login", wait_until="load")
        tab_to(page, lambda x: x.get("id") == "username" or x.get("name") == "username", "the username field")
        page.keyboard.type(user)
        tab_to(page, lambda x: x.get("id") == "password" or x.get("name") == "password", "the password field")
        page.keyboard.type(pw)
        page.keyboard.press("Enter")
        page.wait_for_function("() => !location.pathname.startsWith('/login')", timeout=30000)
        ok("login with Tab + typing + Enter")

        # add
        page.goto(base + "/firewall", wait_until="load")
        page.wait_for_selector("#rule-add", timeout=20000)
        tab_to(page, lambda x: x.get("id") == "rule-add", "the Add rule button")
        page.keyboard.press("Enter")
        page.wait_for_selector("#rule-dialog[open]", timeout=5000)
        assert active(page).get("id") == "r-name", f"focus is not on the name field when the dialog opens: {active(page)}"
        ok("Add rule reachable by Tab, dialog opens with focus on Name")

        # empty name -> inline error, focus back on the name, dialog stays open
        page.keyboard.press("Enter")
        page.wait_for_timeout(200)
        assert page.is_visible("#rule-dialog[open]"), "dialog closed on an invalid submit"
        assert page.get_attribute("#r-name", "aria-invalid") == "true", "empty name not marked invalid"
        assert active(page).get("id") == "r-name", "focus did not return to the invalid field"
        ok("empty name: inline error, dialog stays open, focus on the field")

        # Escape closes, focus back on the opener
        page.keyboard.press("Escape")
        page.wait_for_function("() => !document.querySelector('#rule-dialog[open]')", timeout=5000)
        assert active(page).get("id") == "rule-add", f"focus did not return to Add rule after Escape: {active(page)}"
        ok("Escape closes the dialog, focus returns to Add rule")

        page.keyboard.press("Enter")
        page.wait_for_selector("#rule-dialog[open]", timeout=5000)
        page.keyboard.type(name)
        assert not page.is_visible("#r-port"), "port field shown before a protocol that has ports was picked"
        tab_to(page, lambda x: x.get("id") == "r-proto", "the Protocol select")
        page.keyboard.type("TCP")  # typing selects the matching option of a focused select
        page.wait_for_timeout(150)
        assert page.input_value("#r-proto") == "tcp", f"typing TCP picked {page.input_value('#r-proto')}"
        assert page.is_visible("#r-port"), "port field did not appear after picking TCP"
        tab_to(page, lambda x: x.get("id") == "r-port", "the Destination port field")
        page.keyboard.type("8443")
        tab_to(page, lambda x: x.get("id") == "r-desc", "the Description field")
        page.keyboard.type("added by keyboard")
        with page.expect_navigation(timeout=30000):  # saved -> the page reloads with the new rule
            page.keyboard.press("Enter")
        page.wait_for_selector("#rule-add", timeout=20000)
        got = find(page, base, name)
        assert len(got) == 1, f"rule {name} not saved: {got}"
        r = got[0]
        assert str(r.get("protocol", "")).lower() == "tcp" and "8443" in str(r.get("port")), f"saved rule has wrong values: {json.dumps(r)}"
        ok(f"rule {name} saved on Enter (tcp/8443) and present in the API")

        # edit: Tab to this rule's Edit button
        tab_to(page, lambda x: x.get("label") == f"Edit {name}", f"the Edit button of {name}")
        page.keyboard.press("Enter")
        page.wait_for_selector("#rule-dialog[open]", timeout=5000)
        assert page.input_value("#r-name") == name, "edit dialog did not load the rule"
        tab_to(page, lambda x: x.get("id") == "r-desc", "the Description field")
        page.keyboard.press("End")
        page.keyboard.type(", then edited")
        with page.expect_navigation(timeout=30000):
            page.keyboard.press("Enter")
        page.wait_for_selector("#rule-add", timeout=20000)
        r = find(page, base, name)[0]
        assert r.get("description") == "added by keyboard, then edited", f"edit not saved: {r.get('description')!r}"
        ok("edit via Tab to Edit + Enter, change saved on Enter")

        # delete from the dialog
        tab_to(page, lambda x: x.get("label") == f"Edit {name}", f"the Edit button of {name}")
        page.keyboard.press("Enter")
        page.wait_for_selector("#rule-dialog[open]", timeout=5000)
        tab_to(page, lambda x: x.get("id") == "rule-delete", "the Delete rule button")
        with page.expect_navigation(timeout=30000):
            page.keyboard.press("Enter")
        page.wait_for_selector("#rule-add", timeout=20000)
        page.wait_for_timeout(500)
        assert not find(page, base, name), "rule still present after delete"
        ok("delete via the dialog's Delete rule button + confirm")

        assert not errs, f"page errors: {errs}"
        browser.close()
    print(f"kbd_firewall_rule: {len(steps)} steps passed ({a.browser})")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("FAIL", e)
        sys.exit(1)
