#!/usr/bin/env python3
"""Sites delete gate: deleting a site without confirmation removes nothing.

Serves ../../static (npm run build first) with mocked APIs, logs in as admin and checks on /sites that
  * the row Delete button is not a red button (danger colour only inside the confirm dialog),
  * clicking it only opens a dialog: no deleteSite request is sent,
  * Cancel, Escape and a click outside send nothing,
  * the dialog's Delete stays disabled for an empty or wrong name, and Enter in the field sends nothing,
  * only the exact site name enables it, and then exactly one deleteSite for that id is sent.
Usage: sites-delete-gate.py [static-dir]      needs `pip install playwright` + a browser (BROWSER=firefox|chromium, default chromium)
"""
import sys, os, json, http.server, threading, re
from playwright.sync_api import sync_playwright
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proofmock import gql, CLUSTER

STATIC = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', '..', 'static'))
if not os.path.exists(os.path.join(STATIC, 'index.html')):
    sys.exit(f'FAIL: {STATIC}/index.html missing (npm run build first)')


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=STATIC, **k)
    def log_message(s, *a): pass
    def do_GET(s):
        if '.' not in os.path.basename(s.path.split('?')[0]): s.path = '/index.html'
        return super().do_GET()


srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

deletes, fails = [], []


def expect(cond, msg):
    print(('ok   ' if cond else 'FAIL ') + msg)
    if not cond: fails.append(msg)


def route(r):
    u = r.request.url
    if '/api/v2/graphql' in u:
        body = json.loads(r.request.post_data or '{}')
        if 'deleteSite' in body.get('query', ''):
            deletes.append(body.get('variables', {}).get('id'))
            r.fulfill(json=dict(data=dict(deleteSite=True)))
        else:
            r.fulfill(json=gql(body))
    elif '/ha/cluster' in u: r.fulfill(json=CLUSTER)
    elif '/api/v1/auth/login' in u:
        r.fulfill(json=dict(access_token='t', refresh_token='r', user=dict(id='1', email='admin@example.com', name='Admin', role='admin')))
    else: r.continue_()


with sync_playwright() as p:
    b = getattr(p, os.environ.get('BROWSER', 'chromium')).launch()
    pg = b.new_context(viewport={'width': 1280, 'height': 800}).new_page()
    pg.route('**/*', route)
    pg.goto(f'http://127.0.0.1:{port}/login')
    pg.fill('#email', 'admin@example.com'); pg.fill('#password', 'x'); pg.click('button[type=submit]')
    pg.wait_for_url(re.compile(r'^(?!.*/login)'), timeout=15000)
    pg.goto(f'http://127.0.0.1:{port}/sites')
    pg.wait_for_selector('[data-testid=site-card]', timeout=15000)
    name = 'HQ Chicago'
    btn = pg.get_by_role('button', name=f'Delete site {name}')

    # the row button is not red
    bg, color = btn.evaluate("e => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color]")
    def reddish(c):
        m = re.findall(r'[\d.]+', c)[:3]
        r_, g, b_ = (float(x) for x in m)
        return r_ > 150 and g < 90 and b_ < 90
    expect(not reddish(bg) and not reddish(color), f'row Delete is not red (bg {bg}, text {color})')

    dlg = pg.get_by_role('dialog')
    def open_dialog():
        btn.click()
        dlg.wait_for(timeout=5000)
    def confirm_btn(): return dlg.get_by_role('button', name='Delete site', exact=True)

    open_dialog()
    expect(len(deletes) == 0, 'clicking the row Delete only opens a dialog (no request)')
    expect(confirm_btn().is_disabled(), 'dialog Delete is disabled with an empty name')
    field = dlg.get_by_label('Type the site name to confirm')
    field.fill('wrong name'); pg.keyboard.press('Enter')
    expect(confirm_btn().is_disabled() and len(deletes) == 0, 'wrong name: disabled, Enter sends nothing')
    field.fill(name.lower()); pg.keyboard.press('Enter')
    expect(len(deletes) == 0, 'name in the wrong case sends nothing')
    dlg.get_by_role('button', name='Cancel').click()
    dlg.wait_for(state='hidden', timeout=3000)
    expect(dlg.count() == 0 and len(deletes) == 0, 'Cancel closes and sends nothing')
    open_dialog(); pg.keyboard.press('Escape')
    dlg.wait_for(state='hidden', timeout=3000)
    expect(dlg.count() == 0 and len(deletes) == 0, 'Escape closes and sends nothing')
    open_dialog(); pg.mouse.click(5, 5)
    dlg.wait_for(state='hidden', timeout=3000)
    expect(dlg.count() == 0 and len(deletes) == 0, 'click outside closes and sends nothing')
    expect(pg.locator('[data-testid=site-card]').count() == 3, 'all 3 sites still listed')

    open_dialog()
    dlg.get_by_label('Type the site name to confirm').fill(name)
    expect(confirm_btn().is_enabled(), 'exact name enables Delete')
    confirm_btn().click()
    pg.wait_for_timeout(600)
    expect(deletes == ['0'], f'exactly one deleteSite for the right id after confirming (got {deletes})')
    b.close()

if fails:
    print('SITES DELETE GATE FAILED:'); [print(' -', f) for f in fails]; sys.exit(1)
print('SITES DELETE GATE PASSED')
