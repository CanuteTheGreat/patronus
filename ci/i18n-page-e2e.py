#!/usr/bin/env python3
"""Browser check of the UI language (Playwright, Firefox by default; Chromium when listed).

Against a running patronus-web, requires:
  1. the sign-in page follows the browser's language (German browser -> German page, <html lang=de>), a wrong
     password shows the API's error message in German, and the picker link keeps the choice (cookie);
  2. after signing in, the menu is German (sections and entries) and the API reference page (/api/docs) is German,
     lists every operation of /api/openapi.json and filters when searching;
  3. the account's own language (System > Language) beats the browser: English chosen in a German browser gives an
     English menu, and "use the system default" gives German again;
  4. an error message from the API reaches the user translated: a too-short new password on System > Your account
     shows the German message in the "not applied" dialog;
  5. the system default language (admin) applies to a browser that asks for English, and "follow the browser" undoes it;
  6. desktop (1280) and phone (390) widths both fit without sideways scrolling on the sign-in page and the API page.
It restores the account and system language when it ends.

Usage: BASE_URL=https://192.0.2.1 E2E_USER=admin E2E_PASSWORD=... i18n-page-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
failures = []


def check(name, ok, detail: object = ""):
    print(("PASS" if ok else "FAIL") + ": " + name + ("" if ok else "  " + str(detail)[:600]), flush=True)
    if not ok:
        failures.append(name)


def menu_text(page):
    page.wait_for_selector(".sidebar-nav", timeout=30000)
    return page.text_content(".sidebar-nav")


def sign_in(page, user=USER, pw=PASSWORD):
    page.goto(BASE + "/login")
    page.fill("#username", user)
    page.fill("#password", pw)
    page.click("button[type=submit]")
    page.wait_for_url(lambda u: not u.rstrip("/").endswith("/login"), timeout=30000)


def api(page, path, method="GET", body=None):
    return page.evaluate(
        """async ([p, m, b]) => { const r = await fetch(p, {method: m, credentials: 'same-origin',
             headers: b ? {'content-type': 'application/json'} : {}, body: b ? JSON.stringify(b) : undefined});
             let j = null; try { j = await r.json(); } catch (e) {}
             return {status: r.status, json: j}; }""",
        [path, method, body],
    )


def no_sideways_scroll(page, what):
    over = page.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")
    check(what + ": no sideways scrolling", over <= 1, over)


def run(pw, name):
    print(f"== {name}", flush=True)
    browser = getattr(pw, name).launch(headless=True)
    errs = []

    def ctx(locale, width=1280, height=800):
        c = browser.new_context(
            ignore_https_errors=True, locale=locale, viewport={"width": width, "height": height}
        )
        p = c.new_page()
        p.on("pageerror", lambda e: errs.append(str(e)))
        return c, p

    # 1. sign-in page
    c, page = ctx("de-DE")
    page.goto(BASE + "/login")
    check("German browser: sign-in button is German", page.text_content("button[type=submit]").strip() == "Anmelden", page.text_content("button[type=submit]"))
    check("German browser: <html lang=de>", page.get_attribute("html", "lang") == "de", page.get_attribute("html", "lang"))
    check("German browser: labels", "Benutzername" in page.text_content("form") and "Passwort" in page.text_content("form"), page.text_content("form"))
    page.fill("#username", USER)
    page.fill("#password", "definitely-not-the-password-1")
    page.click("button[type=submit]")
    page.wait_for_selector("#error-message.show", timeout=30000)
    msg = page.text_content("#error-message")
    check("wrong password: the API's error message is shown in German", "Ungültiger Benutzername oder ungültiges Passwort" in msg, msg)
    no_sideways_scroll(page, "desktop sign-in page")
    c.close()

    c, page = ctx("en-US")
    page.goto(BASE + "/login")
    check("English browser: English sign-in page", page.text_content("button[type=submit]").strip() == "Sign In")
    page.click("nav.login-lang a[lang=de]")
    page.wait_for_function("() => document.querySelector('button[type=submit]').textContent.trim() === 'Anmelden'", timeout=30000)
    check("picker switches the sign-in page to German", True)
    page.goto(BASE + "/login")
    check("the picked language is remembered (cookie)", page.text_content("button[type=submit]").strip() == "Anmelden")
    c.close()

    # phone width
    c, page = ctx("de-DE", 390, 844)
    page.goto(BASE + "/login")
    page.wait_for_selector("#username")
    no_sideways_scroll(page, "phone sign-in page")
    c.close()

    # 2. signed in, German browser
    c, page = ctx("de-DE")
    sign_in(page)
    me = api(page, "/api/i18n")["json"]
    original_user, original_system = me["user"], me["system_stored"]
    try:
        m = menu_text(page)
        for want in ("Übersicht", "Sicherheit", "Gerätesegmentierung", "Hochverfügbarkeit", "Diagnose"):
            check(f"German menu has {want}", want in m, m[:300])
        check("German menu has no English section title", "Security" not in m and "Overview" not in m, m[:300])
        check("API says the page language is German", me["current"] == "de", me)

        page.goto(BASE + "/api/docs")
        page.wait_for_selector(".api-op", timeout=30000)
        check("API reference page is German", page.text_content("h1.page-title").strip() == "API-Referenz", page.text_content("h1.page-title"))
        spec = api(page, "/api/openapi.json")["json"]
        n_spec = sum(len(v) for v in spec["paths"].values())
        check("OpenAPI document served", spec["openapi"].startswith("3.1") and n_spec > 200, n_spec)
        n_page = page.locator(".api-op").count()
        check("the reference page lists every operation of the document", n_page == n_spec, f"{n_page} vs {n_spec}")
        page.fill("#api-search", "firewall/rules")
        page.wait_for_function("(n) => document.querySelectorAll('.api-op').length < n", arg=n_page, timeout=10000)
        n_f = page.locator(".api-op").count()
        check("searching narrows the list", 0 < n_f < n_page, n_f)
        page.locator(".api-op").first.click()
        check("an operation opens", page.locator(".api-op[open] .api-body").count() == 1)
        no_sideways_scroll(page, "desktop API reference page")

        # 3. the account's own language beats the browser
        page.goto(BASE + "/system")
        page.wait_for_selector("#language-card", timeout=30000)
        check("language card is German", "Sprache" in page.text_content("#language-card h2"), page.text_content("#language-card h2"))
        page.select_option("#language-form-me select[name=language]", "en")
        page.click("#language-form-me button[type=submit]")
        page.wait_for_function("() => document.documentElement.lang === 'en'", timeout=30000)
        m = menu_text(page)
        check("own language English beats the German browser: English menu", "Security" in m and "Sicherheit" not in m, m[:300])
        page.select_option("#language-form-me select[name=language]", "")
        page.click("#language-form-me button[type=submit]")
        page.wait_for_function("() => document.documentElement.lang === 'de'", timeout=30000)
        check("'use the system default' gives the browser's German again", "Sicherheit" in menu_text(page))

        # 4. an API error reaches the user translated
        page.goto(BASE + "/system")
        page.wait_for_selector("#password-form", timeout=30000)
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
        page.fill("#password-form input[name=current_password]", PASSWORD)
        page.fill("#password-form input[name=new_password]", "short")
        page.click("#password-form button[type=submit]")
        page.wait_for_function("() => true", timeout=1000)
        for _ in range(50):
            if dialogs:
                break
            page.wait_for_timeout(200)
        check(
            "refused change: the dialog shows the German error",
            bool(dialogs)
            and dialogs[0].startswith("Nicht angewendet:")
            and ("Ungültiges Passwort muss mindestens 12 Zeichen" in dialogs[0] or "Systemkonto" in dialogs[0]),
            dialogs,
        )

        # 5. the system default
        r = api(page, "/api/i18n/system", "PUT", {"language": "de"})
        check("admin sets the system default", r["status"] == 200, r)
        c2, p2 = ctx("en-US")
        p2.goto(BASE + "/login")
        check("system default German applies to a browser that asks for English", p2.text_content("button[type=submit]").strip() == "Anmelden")
        c2.close()
        r = api(page, "/api/i18n/system", "PUT", {"language": "auto"})
        c2, p2 = ctx("en-US")
        p2.goto(BASE + "/login")
        check("'follow the browser' undoes it", p2.text_content("button[type=submit]").strip() == "Sign In")
        c2.close()
    finally:
        api(page, "/api/i18n/me", "PUT", {"language": original_user})
        api(page, "/api/i18n/system", "PUT", {"language": original_system})
        c.close()

    # phone: API page, English
    c, page = ctx("en-US", 390, 844)
    sign_in(page)
    page.goto(BASE + "/api/docs")
    page.wait_for_selector(".api-op", timeout=30000)
    no_sideways_scroll(page, "phone API reference page")
    c.close()

    check("no JavaScript errors", not errs, errs)
    browser.close()


browsers = (sys.argv[1] if len(sys.argv) > 1 else "firefox").split(",")
with sync_playwright() as pw:
    for b in browsers:
        run(pw, b)
print("FAILED: " + (", ".join(failures) if failures else "none"))
sys.exit(1 if failures else 0)
