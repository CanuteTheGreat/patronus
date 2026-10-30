#!/usr/bin/env python3
"""Render proof for the dashboard UI: builds nothing; serves ../static with mocked APIs and
screenshots every page at 390px and 1280px in light and dark, switching the colour scheme
LIVE (no reload) and running a WCAG AA contrast scan on every text node.
Usage: theme-proof.py <outdir> <contrast.js>   (needs playwright + a chromium)"""
import sys, os, glob, json, http.server, threading, mimetypes
from playwright.sync_api import sync_playwright
out, jsfile = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
STATIC = os.path.join(os.path.dirname(__file__), '..', '..', 'static')
STATIC = os.path.abspath(STATIC)
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k): super().__init__(*a, directory=STATIC, **k)
    def log_message(s, *a): pass
    def do_GET(s):
        if '.' not in os.path.basename(s.path.split('?')[0]): s.path = '/index.html'
        return super().do_GET()
srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
now = '2026-10-30T12:00:00Z'
sites = [dict(id=str(i), name=n, location=l, status=st, endpointCount=c, createdAt=now, updatedAt=now, __typename='Site') for i, (n, l, st, c) in enumerate([
    ('HQ Chicago', 'Chicago, US', 'active', 24), ('Branch Denver', 'Denver, US', 'degraded', 8), ('Branch Berlin', 'Berlin, DE', 'inactive', 3)])]
def gql(body):
    q = body.get('query', '')
    d = {}
    if 'overview' in q:
        d['overview'] = dict(totalSites=3, activeSites=2, totalLinks=4, healthyLinks=3, avgLatency=23.4, totalThroughput=420000000, packetLoss=0.004)
        d['recentAlerts'] = [dict(id='a1', severity='critical', message='Link Berlin-HQ down', timestamp=now, siteId='2'),
                             dict(id='a2', severity='warning', message='Latency above SLA on Denver', timestamp=now, siteId='1'),
                             dict(id='a3', severity='info', message='Policy updated', timestamp=now, siteId='0')]
        d['linkMetrics'] = [dict(timestamp=f'2026-10-30T12:{m:02d}:00Z', throughput=300e6+m*3e6, latency=20+m%7, packetLoss=0.001*(m%4)) for m in range(0, 40, 4)]
    if 'sites {' in q or 'sites{' in q:
        d['sites'] = [dict(x, status=x['status'].upper()) for x in sites] if 'endpointCount' in q else sites
    if 'links {' in q:
        d['links'] = [dict(id='l1', sourceId='0', targetId='1', status='degraded', latency=40, bandwidth=100, utilization=.7),
                      dict(id='l2', sourceId='0', targetId='2', status='down', latency=0, bandwidth=100, utilization=0)]
    if 'slaPolicies' in q:
        d['slaPolicies'] = [dict(id='s1', name='Voice', description='Realtime voice', targetLatency=50, targetPacketLoss=.01, targetAvailability=99.9, currentLatency=42, currentPacketLoss=.004, currentAvailability=99.95, compliance=98.2, violations=1),
                            dict(id='s2', name='Video', description='Conferencing', targetLatency=80, targetPacketLoss=.02, targetAvailability=99.5, currentLatency=120, currentPacketLoss=.03, currentAvailability=98.1, compliance=71.0, violations=14)]
    if 'trafficStats' in q:
        d['trafficStats'] = [dict(siteId='0', siteName='HQ Chicago', totalBytes=5e10, totalPackets=4e7, applications=[dict(name='HTTPS', bytes=3e10, packets=2e7, percentage=60), dict(name='VoIP', bytes=1e10, packets=1e7, percentage=20)])]
    if 'securityEvents' in q:
        d['securityEvents'] = [dict(id='e1', timestamp=now, severity='high', type='intrusion', source='203.0.113.9', destination='10.0.0.5', description='Port scan', blocked=True),
                               dict(id='e2', timestamp=now, severity='medium', type='malware', source='198.51.100.2', destination='10.0.0.9', description='Suspicious download', blocked=False)]
        d['threatStats'] = dict(total=120, blocked=100, allowed=20, byType=[dict(type='intrusion', count=70), dict(type='malware', count=50)])
    return dict(data=d)
CLUSTER = dict(ha_enabled=True, leader_id='n1', term=4, members=[
    dict(addr='10.0.0.1:8080', reachable=True, is_self=True, status=dict(node_id='n1', role='Leader', term=4, leader_id='n1', peers=['n2', 'n3'], cluster_size=3, log_index=120, commit_index=120, applied_index=120)),
    dict(addr='10.0.0.2:8080', reachable=True, is_self=False, status=dict(node_id='n2', role='Follower', term=4, leader_id='n1', peers=['n1', 'n3'], cluster_size=3, log_index=120, commit_index=120, applied_index=119)),
    dict(addr='10.0.0.3:8080', reachable=False, is_self=False, status=None)])
exe = glob.glob(os.path.expanduser('~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell'))[0]
js = open(jsfile).read()
pages = ['dashboard', 'sites', 'topology', 'sla', 'traffic', 'security', 'cluster', 'settings']
bad_total = 0
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=exe)
    for w, h, tag in ((1280, 800, 'desktop'), (390, 844, 'phone')):
        ctx = b.new_context(viewport={'width': w, 'height': h}, color_scheme='light')
        pg = ctx.new_page()
        def route(r):
            u = r.request.url
            if '/api/v2/graphql' in u: r.fulfill(json=gql(json.loads(r.request.post_data or '{}')))
            elif '/ha/cluster' in u: r.fulfill(json=CLUSTER)
            elif '/api/v1/auth/login' in u: r.fulfill(json=dict(access_token='t', refresh_token='r', user=dict(id='1', email='admin@example.com', name='Admin', role='admin')))
            else: r.continue_()
        pg.route('**/*', route)
        pg.goto(f'http://127.0.0.1:{port}/login'); pg.wait_for_timeout(500)
        for scheme in ('light', 'dark'):
            pg.emulate_media(color_scheme=scheme); pg.wait_for_timeout(300)
            pg.add_style_tag(content='*{transition:none!important}')
            r = pg.evaluate(js); bad_total += len(r['bad'])
            print(tag, 'login', scheme, r['checked'], [(x['txt'][:16], x['cr'], x['fg'], x['bg']) for x in r['bad'][:4]])
            pg.screenshot(path=f'{out}/{tag}-login-{scheme}.png', full_page=True)
        pg.emulate_media(color_scheme='light')
        pg.fill('#email', 'admin@example.com'); pg.fill('#password', 'x'); pg.click('button[type=submit]'); pg.wait_for_timeout(1500)
        for name in pages:
            pg.click(f'a[href="/{name}"]:visible') if pg.query_selector(f'a[href="/{name}"]') else pg.goto(f'http://127.0.0.1:{port}/{name}')
            pg.wait_for_timeout(1800)
            for scheme in ('light', 'dark'):
                pg.emulate_media(color_scheme=scheme); pg.wait_for_timeout(500)
                pg.add_style_tag(content='*{transition:none!important}')
                r = pg.evaluate(js); bad_total += len(r['bad'])
                ovf = pg.evaluate('document.documentElement.scrollWidth>innerWidth+1')
                meta = pg.evaluate("[...document.querySelectorAll('meta[name=theme-color]')].filter(m=>matchMedia(m.media).matches).map(m=>m.content)")
                print(tag, name, scheme, 'checked', r['checked'], 'bad', len(r['bad']), [(x['txt'][:16], x['cr'], x['fg'], x['bg']) for x in r['bad'][:4]], 'OVERFLOW' if ovf else '', meta)
                pg.screenshot(path=f'{out}/{tag}-{name}-{scheme}.png', full_page=True)
        ctx.close()
    b.close()
print('TOTAL contrast failures', bad_total)
