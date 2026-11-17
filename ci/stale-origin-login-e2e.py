#!/usr/bin/env python3
"""Sign in from a browser that still holds what an older firmware left at the router's address.

A router's address usually served the vendor's admin page (or LuCI) before Patronus. The browser keeps that
firmware's cookies for the address (e.g. `Admin-Token` at Path=/) and sends them with every request. Over HTTP/2
each cookie travels in its own `cookie` header field, and patronus-web used to read only the first field: the
password was accepted, the session cookie was set, and every page then bounced back to the login page, while a
private window (no old cookies) worked.

For each browser (Firefox and Chromium by default), this:
  1. signs in from a fresh profile (sanity);
  2. seeds the cookies an older firmware leaves at the address, signs in, and requires the dashboard to load
     and the API to accept the session (no bounce back to /login, no error on the login page);
  3. requires the old firmware's cookies to be gone afterwards (the login page and a sign-in delete them),
     while the session cookie stays;
  4. with E2E_BACKOFF_USER set (a throwaway name, run last: it locks this client out for a while), requires
     repeated failures to end in a refusal that says so and names the wait, not "Invalid username or password".

Usage: BASE_URL=https://localhost:8443 E2E_USER=admin E2E_PASSWORD=... stale-origin-login-e2e.py [firefox,chromium]
Exit 0 = every check passed. Needs the `playwright` package and its browsers.
"""
import os
import sys
from urllib.parse import urlsplit

from playwright.sync_api import TimeoutError as PlaywrightTimeout, sync_playwright

BASE = os.environ.get("BASE_URL", "https://localhost:8443").rstrip("/")
USER = os.environ["E2E_USER"]
PASSWORD = os.environ["E2E_PASSWORD"]
BACKOFF_USER = os.environ.get("E2E_BACKOFF_USER", "")
HOST = urlsplit(BASE).hostname

# What the previous firmware leaves for the address: the GL.iNet 4.x admin token (set by its /rpc without a
# path, i.e. Path=/, not Secure), a LuCI session (Path=/cgi-bin/luci/) and an unrelated preference cookie.
OLD_FIRMWARE_COOKIES = [
    {"name": "Admin-Token", "value": "0123456789abcdef0123456789abcdef", "path": "/", "secure": False,
     "httpOnly": False, "sameSite": "Lax"},
    {"name": "sysauth_https", "value": "fedcba9876543210fedcba9876543210", "path": "/cgi-bin/luci/",
     "secure": True, "httpOnly": True, "sameSite": "Strict"},
    {"name": "lang", "value": "en", "path": "/", "secure": False, "httpOnly": False, "sameSite": "Lax"},
]

failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    if not cond:
        failures.append(what)


def sign_in(page, user, password):
    page.goto(BASE + "/login")
    page.fill("#username", user)
    page.fill("#password", password)
    with page.expect_response(lambda r: r.url.endswith("/api/auth/login"), timeout=20000):
        page.click("button[type=submit]")
    # the dashboard loads, or the login page shows its error; a silent bounce back to /login does neither
    try:
        page.wait_for_function(
            "() => location.pathname !== '/login' || document.getElementById('error-message').classList.contains('show')",
            timeout=10000,
        )
    except PlaywrightTimeout:
        pass
    page.wait_for_load_state("load")


def run(browser_name, pw):
    browser = getattr(pw, browser_name).launch(headless=True)
    try:
        # 1. fresh profile
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        sign_in(page, USER, PASSWORD)
        check(urlsplit(page.url).path == "/" and "Dashboard" in page.title(),
              f"{browser_name}: fresh profile signs in to the dashboard ({page.url})")
        proto = page.evaluate("() => performance.getEntriesByType('navigation')[0].nextHopProtocol")
        check(proto == "h2", f"{browser_name}: served over HTTP/2, where each cookie is its own header field ({proto})")
        ctx.close()

        # 2. profile with an older firmware's cookies for the same address
        ctx = browser.new_context(ignore_https_errors=True)
        ctx.add_cookies([dict(c, domain=HOST) for c in OLD_FIRMWARE_COOKIES])
        page = ctx.new_page()
        sign_in(page, USER, PASSWORD)
        path = urlsplit(page.url).path
        err = page.eval_on_selector("#error-message", "e => e.classList.contains('show') ? e.textContent : ''") \
            if path == "/login" else ""
        check(path == "/" and "Dashboard" in page.title(),
              f"{browser_name}: signs in with old-firmware cookies present (landed {path}, error {err!r})")
        # from the page itself, through the browser's own network stack (HTTP/2, one field per cookie)
        status = page.evaluate("() => fetch('/api/auth/me', {credentials: 'same-origin'}).then(r => r.status)")
        check(status == 200, f"{browser_name}: session accepted by the API with old cookies present ({status})")
        # a page load after sign-in stays signed in
        page.goto(BASE + "/system")
        check(urlsplit(page.url).path == "/system", f"{browser_name}: /system stays signed in ({page.url})")

        # 3. the old firmware's cookies at Path=/ are gone, ours stays
        names = {c["name"] for c in ctx.cookies(BASE + "/")}
        check("session_id" in names, f"{browser_name}: session cookie kept ({sorted(names)})")
        check("Admin-Token" not in names and "lang" not in names,
              f"{browser_name}: old firmware cookies at / removed ({sorted(names)})")
        ctx.close()

    finally:
        browser.close()


def backoff(browser_name, pw):
    """Repeated failures end in a refusal that says it is one (with the wait), not "Invalid username or
    password". Locks this client out for a while, so it runs last."""
    browser = getattr(pw, browser_name).launch(headless=True)
    try:
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        msg = ""
        for _ in range(8):
            sign_in(page, BACKOFF_USER, "Not-The-Password-1")
            msg = page.eval_on_selector("#error-message", "e => e.textContent")
            if "Too many" in msg:
                break
        check("Too many failed sign-in attempts" in msg and "try again in" in msg,
              f"{browser_name}: repeated failures end in a refusal that says so ({msg!r})")
    finally:
        browser.close()


def main():
    browsers = (sys.argv[1] if len(sys.argv) > 1 else "firefox,chromium").split(",")
    with sync_playwright() as pw:
        for b in browsers:
            run(b.strip(), pw)
        if BACKOFF_USER:
            backoff(browsers[0].strip(), pw)
    if failures:
        print(f"{len(failures)} check(s) failed", flush=True)
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
