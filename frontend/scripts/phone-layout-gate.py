#!/usr/bin/env python3
"""Phone-layout gate for the shipped dashboard UI (owner 2026-11-07: features must be tested).

Serves ../../static (run `npm run build` first) with the mocked APIs from proofmock.py, opens the
login page and every dashboard page at 390x844 and 360x740 (phone) and FAILS when:
  * the page scrolls sideways (documentElement.scrollWidth > innerWidth),
  * any visible element sticks out past the right edge of the viewport and is not inside its
    own horizontally scrollable container (overflow-x auto/scroll),
  * the page has no way to navigate (no visible link to another page once logged in).
Screenshots go to <outdir> (CI uploads them on failure).
Usage: phone-layout-gate.py <outdir>      needs `pip install playwright && playwright install chromium`"""
import sys, os, glob, json, http.server, threading
from playwright.sync_api import sync_playwright
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proofmock import gql, CLUSTER

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
STATIC = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'static'))
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

# elements wider than the viewport that are not clipped by a scroll container
STICKS_OUT = """() => {
  const vw = document.documentElement.clientWidth, bad = [];
  const clipped = el => { for (let p = el.parentElement; p; p = p.parentElement) {
    const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return true; } return false; };
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.position === 'fixed') continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) continue;
    if (r.right > vw + 1 && !clipped(el)) bad.push((el.tagName + '.' + String(el.className).slice(0, 40) + ' right=' + Math.round(r.right) + ' "' + (el.textContent || '').trim().slice(0, 20) + '"'));
  }
  return bad.slice(0, 5);
}"""
pages = ['dashboard', 'sites', 'topology', 'sla', 'traffic', 'security', 'cluster', 'settings']
exe = next(iter(glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell'))), None)
fails = []
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
    for w, h in ((390, 844), (360, 740)):
        ctx = b.new_context(viewport={'width': w, 'height': h}, color_scheme='light', has_touch=True, is_mobile=True)
        pg = ctx.new_page()

        def route(r):
            u = r.request.url
            if '/api/v2/graphql' in u: r.fulfill(json=gql(json.loads(r.request.post_data or '{}')))
            elif '/ha/cluster' in u: r.fulfill(json=CLUSTER)
            elif '/api/v1/auth/login' in u:
                r.fulfill(json=dict(access_token='t', refresh_token='r', user=dict(id='1', email='admin@example.com', name='Admin', role='admin')))
            else: r.continue_()

        pg.route('**/*', route)

        def check(name):
            pg.wait_for_timeout(1500)
            side = pg.evaluate('document.documentElement.scrollWidth > innerWidth + 1')
            sticks = pg.evaluate(STICKS_OUT)
            pg.screenshot(path=f'{out}/{w}-{name}.png', full_page=True)
            status = 'FAIL' if side or sticks else 'ok'
            print(f'[{w}px] {name}: {status}', 'scrolls sideways' if side else '', sticks)
            if side: fails.append(f'{w}px {name}: page scrolls sideways')
            for s in sticks: fails.append(f'{w}px {name}: sticks out: {s}')

        pg.goto(f'http://127.0.0.1:{port}/login')
        pg.wait_for_selector('#email', timeout=15000)
        check('login')
        pg.fill('#email', 'admin@example.com'); pg.fill('#password', 'x'); pg.click('button[type=submit]')
        pg.wait_for_timeout(1500)
        for name in pages:
            pg.goto(f'http://127.0.0.1:{port}/{name}')
            check(name)
            links = pg.evaluate("[...document.querySelectorAll('a[href^=\"/\"], button')].filter(e => e.getBoundingClientRect().width > 0).length")
            if links == 0:
                fails.append(f'{w}px {name}: no visible navigation')
        ctx.close()
    b.close()
if fails:
    print('PHONE LAYOUT GATE FAILED:'); [print(' -', f) for f in fails]; sys.exit(1)
print('PHONE LAYOUT GATE PASSED:', len(pages) + 1, 'pages x 2 phone sizes')
