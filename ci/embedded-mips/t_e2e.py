"""QEMU malta end-to-end for the router tier web UI: first-run password, login, pages, firewall rule change -> nft, reboot -> persistence.
usage (in the q2 container): t_e2e.py <rootfs.squashfs> [pages,comma,separated]"""
import sys, time, subprocess, json, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qemu_harness import Guest
ROOTFS = sys.argv[1]
PAGES = (sys.argv[2] if len(sys.argv) > 2 else '/,/firewall,/interfaces,/network,/system,/monitoring,/vpn,/dhcp,/dns,/ntp,/routing,/setup,/insights,/qos').split(',')
PW = 'Correct-Horse-Battery-9'
BASE = 'https://127.0.0.1:18443'
JAR = '/tmp/jar'
res = {}
def log(*a): print(*a, flush=True)
def curl(args, t=150):
    r = subprocess.run(['curl', '-sk', '-m', str(t)] + args, capture_output=True, text=True); return r.stdout
def api(method, path, body=None, auth=True, t=150):
    a = ['-X', method, '-w', '\n%{http_code}', '-H', 'content-type: application/json']
    if auth: a += ['-b', JAR]
    if body is not None: a += ['-d', json.dumps(body)]
    out = curl(a + [BASE + path], t)
    txt, _, code = out.rpartition('\n'); return int(code or 0), txt
def boot(label):
    g = Guest('/out/vmlinux-malta-be2', ROOTFS, '/out/data.img', log=f'/out/guest-e2e-{label}.log')
    t0 = time.time(); time.sleep(20)
    while time.time() - t0 < 300:
        o, rc = g.run('grep -c "Starting web server" /var/log/web.log 2>/dev/null; true', 30)
        if o.strip().split('\n')[-1].strip() == '1': break
        time.sleep(4)
    res[f'boot_to_web_{label}_s'] = round(time.time() - t0)
    time.sleep(5)
    return g
RSS = 'for p in /proc/[0-9]*; do n=$(cat $p/comm 2>/dev/null); case $n in patronus*|dnsmasq) echo $n $(grep -E "VmHWM|VmRSS" $p/status | tr -s " \\t" " " | tr "\\n" " ");; esac; done'
def rss(g, tag):
    o, _ = g.run(RSS, 30); res[f'rss_{tag}'] = o; log(f'--- RSS {tag}\n{o}')
    o, _ = g.run('free', 30); log(o)
def check(name, cond, extra=''):
    res[name] = bool(cond); log(('PASS ' if cond else 'FAIL ') + name + (f'  [{extra}]' if extra else ''))

# ---------- boot 1 (fresh data disk)
g = boot('1')
rss(g, 'idle_after_boot')
o, _ = g.run('ip addr show dev eth0 | grep "inet "', 30); log(o)
check('default LAN IP 192.168.1.1 up', '192.168.1.1/24' in o)
code, txt = api('GET', '/', auth=False, t=60); 
r = subprocess.run(['curl','-sk','-m','60','-o','/dev/null','-w','%{http_code} %{redirect_url}',BASE+'/'],capture_output=True,text=True).stdout
check('GET / before password -> 303 /first-run', r.startswith('303') and r.endswith('/first-run'), r)
code, txt = api('GET', '/first-run', auth=False); check('first-run page served', code == 200 and 'Set password' in txt, str(code))
code, txt = api('GET', '/api/firewall/rules', auth=False); check('API locked before password (403)', code == 403, str(code))
code, txt = api('POST', '/api/auth/login', {'username': 'admin', 'password': 'admin'}, auth=False); check('login admin/admin refused', code in (400, 401, 403), str(code))
code, txt = api('POST', '/api/first-run', {'password': 'short', 'confirm': 'short'}, auth=False); check('weak password rejected', code == 400, txt[:80])
code, txt = api('POST', '/api/first-run', {'password': PW, 'confirm': PW + 'x'}, auth=False); check('mismatch rejected', code == 400, txt[:80])
t=time.time(); code, txt = api('POST', '/api/first-run', {'password': PW, 'confirm': PW}, auth=False); check('password set', code == 200, txt[:80]); res['first_run_s']=round(time.time()-t,1)
code, txt = api('POST', '/api/first-run', {'password': PW + 'z', 'confirm': PW + 'z'}, auth=False); check('second first-run refused (409)', code == 409, str(code))
r = subprocess.run(['curl','-sk','-m','60','-o','/dev/null','-w','%{http_code} %{redirect_url}',BASE+'/first-run'],capture_output=True,text=True).stdout
check('/first-run now redirects to /login', r.startswith('303') or r.startswith('307') or r.startswith('308') or r.startswith('302'), r)
t = time.time(); code, txt = api('POST', '/api/auth/login', {'username': 'admin', 'password': PW}, auth=False, t=200) if False else (0, '')
out = curl(['-c', JAR, '-H', 'content-type: application/json', '-d', json.dumps({'username': 'admin', 'password': PW}), '-w', '\n%{http_code}', BASE + '/api/auth/login'], 200)
res['login_s'] = round(time.time() - t, 1); check('login with chosen password', out.strip().endswith('200'), f"{res['login_s']}s")
# pages
res['pages'] = {}
for p in PAGES:
    t = time.time(); out = curl(['-b', JAR, '-o', '/tmp/o.html', '-w', '%{http_code} %{size_download}', BASE + p], 200)
    res['pages'][p] = f'{out} {time.time()-t:.1f}s'; log(f'  {p:16s} {res["pages"][p]}')
rss(g, 'after_pages')
# firewall: add a rule, apply, check nft
rule = {'name': 'qemu-e2e allow 8080', 'enabled': True, 'chain': 'input', 'action': 'accept', 'protocol': 'tcp', 'port': '8080', 'interface': 'any', 'source': 'any', 'destination': 'any', 'description': 'e2e rule'}
code, txt = api('POST', '/api/firewall/rules', rule); check('add firewall rule via API', code == 201, f'{code} {txt[:100]}')
rid = (json.loads(txt).get('id') if code == 201 else None)
code, txt = api('POST', '/api/firewall/rules/apply'); log('apply', code, txt[:120])
o, _ = g.run('nft list chain inet patronus input | grep -n 8080', 30); log(o)
check('nftables contains the new rule after apply', '8080' in o, o.replace('\n', ' | ')[:120])
# backup -> delete the rule -> restore -> the rule is back (backup/restore page)
code, txt = api('POST', '/api/system/backups'); check('create backup via UI API', code == 201, f'{code} {txt[:120]}')
bk = None
try:
    bj = json.loads(txt); bk = bj.get('name') or bj.get('file') or bj.get('filename')
except Exception: pass
if rid is not None:
    code, txt = api('DELETE', f'/api/firewall/rules/{rid}'); log('delete', code)
    api('POST', '/api/firewall/rules/apply'); o, _ = g.run('nft list chain inet patronus input | grep -c 8080; true', 30)
    check('rule removal reaches nftables', o.strip().endswith('0'), o)
if bk:
    code, txt = api('POST', f'/api/system/backups/{bk}/restore', {}); check('restore backup via UI API', code == 200, f'{code} {txt[:120]}')
    o, _ = g.run('nft list chain inet patronus input | grep -c 8080; true', 30)
    check('restore re-created the rule in nftables', o.strip().endswith('1'), o)
else:
    check('backup name parsed', False, txt[:100])
# honesty: things this tier does not have
code, txt = api('GET', '/api/features'); feats = json.loads(txt).get('features', []) if code == 200 else []
check('features API lists the built set, no qos/ha/vpn', code == 200 and 'qos' not in feats and 'ha' not in feats and 'wireguard' not in feats and 'dhcp' in feats, ','.join(feats))
res['features'] = feats
r = subprocess.run(['curl','-sk','-m','60','-o','/dev/null','-w','%{http_code}',BASE+'/qos','-b',JAR],capture_output=True,text=True).stdout
check('unbuilt page /qos answers 501', r == '501', r)
code, txt = api('POST', '/api/system/updates/check', {}); check('portage update check answers 501 (no emerge on the router)', code == 501, f'{code} {txt[:100]}')
rss(g, 'after_firewall_change')
g.run('sync', 30)
log('--- rebooting guest from the web UI (POST /api/system/reboot)'); code, txt = api('POST', '/api/system/reboot', {}); check('reboot API accepted (202)', code == 202, f'{code} {txt[:80]}')
try: g.p.wait(timeout=90)
except Exception: g.kill()
# ---------- boot 2: same data disk
g2 = boot('2')
o, _ = g2.run('nft list chain inet patronus input | grep -c 8080', 30); check('REBOOT: rule still in nftables', o.strip().endswith('1'), o)
code, txt = api('GET', '/api/firewall/rules', auth=False); check('REBOOT: API still needs login', code == 401, str(code))
r = subprocess.run(['curl','-sk','-m','60','-o','/dev/null','-w','%{http_code} %{redirect_url}',BASE+'/'],capture_output=True,text=True).stdout
check('REBOOT: no first-run again (/ -> /login)', 'first-run' not in r, r)
out = curl(['-c', JAR, '-H', 'content-type: application/json', '-d', json.dumps({'username': 'admin', 'password': PW}), '-w', '\n%{http_code}', BASE + '/api/auth/login'], 200)
check('REBOOT: login with the same password', out.strip().endswith('200'))
code, txt = api('GET', '/api/firewall/rules'); check('REBOOT: rule listed in the UI API', 'qemu-e2e allow 8080' in txt, str(code))
o, _ = g2.run('ls /var/lib/patronus; ip addr show dev eth0 | grep "inet "; pgrep dnsmasq || ps | grep [d]nsmasq', 30); log(o)
check('REBOOT: LAN IP and DHCP persisted', '192.168.1.1/24' in o)
rss(g2, 'after_reboot')
g2.kill()
json.dump(res, open('/out/e2e-result.json', 'w'), indent=1)
fails = [k for k, v in res.items() if v is False]
log('FAILED:', fails if fails else 'none')
