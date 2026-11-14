#!/usr/bin/env python3
"""Real-Slate web UI / firewall / backup test (adapted from ci/embedded-mips/t_e2e.py; no QEMU).
usage: t_slate.py <phase>   phase = first (first-run + login + pages + WAN mgmt rules + 8080 rule + backup/restore)
                                    | again (after a reboot/upgrade: login, rules still there, no first-run)
Env: SLATE_IP, SLATE_SSH (ssh wrapper), SLATE_MGMT_NET, SLATE_ADMIN_PW_FILE (created on first use, 0600), SLATE_ADMIN_USER (the system user first-run creates,
     default netadmin: there is no built-in admin), SLATE_RESULTS."""
import sys, time, subprocess, json, os, secrets
PH = sys.argv[1] if len(sys.argv) > 1 else 'first'
IP = os.environ['SLATE_IP']; BASE = f'https://{IP}'   # the router's address on the upstream LAN
MGMT = os.environ.get('SLATE_MGMT_NET', '192.0.2.0/24')   # = MGMT_NET in its unit.conf
PWF = os.path.expanduser(os.environ.get('SLATE_ADMIN_PW_FILE', '~/.config/patronus-slate/web-admin.txt'))
USER = os.environ.get('SLATE_ADMIN_USER', 'netadmin')
if not os.path.exists(PWF):
    os.umask(0o077); open(PWF, 'w').write('Slate-' + secrets.token_urlsafe(12) + '-9\n')
PW = open(PWF).read().strip()
JAR = os.path.expanduser(os.environ.get('SLATE_COOKIE_JAR', '~/.cache/patronus-slate-jar.txt'))
SSH = os.path.expanduser(os.environ['SLATE_SSH'])   # a wrapper: SLATE_SSH -t <timeout> '<cmd>' runs cmd on the router as root
res = {'phase': PH}; fails = []
def log(*a): print(*a, flush=True)
def curl(args, t=150):
    return subprocess.run(['curl', '-sk', '-m', str(t)] + args, capture_output=True, text=True).stdout
def api(method, path, body=None, auth=True, t=150):
    a = ['-X', method, '-w', '\n%{http_code}', '-H', 'content-type: application/json']
    if auth: a += ['-b', JAR]
    if body is not None: a += ['-d', json.dumps(body)]
    txt, _, code = curl(a + [BASE + path], t).rpartition('\n'); return int(code or 0), txt
def ssh(cmd, t=60):
    r = subprocess.run([SSH, '-t', str(t), cmd], capture_output=True, text=True); return r.stdout + r.stderr
def check(name, cond, extra=''):
    log(('PASS' if cond else 'FAIL') + f': {name}' + (f' ({extra})' if extra else ''))
    if not cond: fails.append(name)
def rss(tag):
    o = ssh("for p in $(pidof patronus-web) $(pidof patronus-cli); do echo \"$(tr '\\0' ' ' </proc/$p/cmdline|cut -c1-30) $(grep -E 'VmRSS|VmHWM' /proc/$p/status|tr -s ' \\t\\n' ' ')\"; done; free | sed -n 2p")
    res['rss_' + tag] = o.strip(); log(f'[rss {tag}]\n{o.strip()}')
def login():
    t = time.time()
    out = curl(['-c', JAR, '-H', 'content-type: application/json', '-d', json.dumps({'username': USER, 'password': PW}), '-w', '\n%{http_code}', BASE + '/api/auth/login'], 200)
    res[f'login_s_{PH}'] = round(time.time() - t, 2); return out.strip().endswith('200')
# TLS handshake + redirect timing
t = time.time(); r = curl(['-o', '/dev/null', '-w', '%{http_code} %{time_appconnect} %{time_total}', BASE + '/'], 60); res['tls_first'] = r
log('GET / ->', r)
r80 = curl(['-o', '/dev/null', '-w', '%{http_code} %{redirect_url}', f'http://{IP}/'], 30); check('HTTP :80 answers only a redirect to https', r80.startswith('308') and r80.split()[-1].startswith('https://'), r80)
rss('idle')
if PH == 'first':
    r = curl(['-o', '/dev/null', '-w', '%{http_code} %{redirect_url}', BASE + '/'], 60)
    check('GET / before password -> 303 /first-run', r.startswith('303') and r.endswith('/first-run'), r)
    code, txt = api('GET', '/api/firewall/rules', auth=False); check('API locked before password (403)', code == 403, str(code))
    code, txt = api('POST', '/api/auth/login', {'username': 'admin', 'password': 'admin'}, auth=False); check('admin/admin refused', code in (400, 401, 403), str(code))
    code, txt = api('POST', '/api/first-run', {'username': USER, 'password': 'short', 'confirm': 'short'}, auth=False); check('weak password rejected', code == 400, txt[:60])
    t = time.time(); code, txt = api('POST', '/api/first-run', {'username': USER, 'password': PW, 'confirm': PW}, auth=False, t=200)
    res['first_run_s'] = round(time.time() - t, 2); check('administrator (system user) created on the first-run page', code == 200, f'{code} {res["first_run_s"]}s')
    code, txt = api('POST', '/api/first-run', {'username': USER + '2', 'password': PW + 'z', 'confirm': PW + 'z'}, auth=False); check('second first-run refused (409)', code == 409, str(code))
check('login', login(), f"{res.get(f'login_s_{PH}')}s")
# the web login is a system user checked through PAM: no built-in admin, the first-run account is in /etc/shadow
o = ssh(f"cat /etc/patronus-init; grep -c '^{USER}:\\$6\\$' /etc/shadow; grep -c '^patronus-admin:.*{USER}' /etc/group; ls /etc/pam.d/patronus /lib/security/pam_unix.so; grep -c '^admin:' /etc/passwd")
log('  system-login state:', ' '.join(o.split()))
res['init'] = o.split()[0] if o.split() else ''
lines = o.split()
check('first-run account is a system user (shadow sha512, patronus-admin) checked by PAM; no built-in admin',
      len(lines) >= 6 and lines[1] == '1' and lines[2] == '1' and '/etc/pam.d/patronus' in o and lines[-1] == '0', o.strip()[:200])
rss('after_login')
res['pages'] = {}
for p in '/,/firewall,/interfaces,/network,/system,/monitoring,/dhcp,/dns,/routing,/setup,/insights,/vpn,/qos'.split(','):
    t = time.time(); out = curl(['-b', JAR, '-o', '/dev/null', '-w', '%{http_code} %{size_download}', BASE + p], 120)
    res['pages'][p] = f'{out} {time.time()-t:.2f}s'; log(f'  {p:14s} {res["pages"][p]}')
check('all built pages answer 200, unbuilt 501', all(v.split()[0] in ('200', '501') for v in res['pages'].values()))
code, txt = api('GET', '/api/features'); res['features'] = txt[:200]; log('features', code, txt[:200])
# system log on both init systems: busybox syslogd -> /var/log/messages (+ klogd; on systemd journald forwards to it),
# shown by the web UI's log viewer on /monitoring
tag = f'slate-e2e-{int(time.time())}'
o = ssh(f"logger -t {tag} syslog-probe; sleep 2; M=/var/log/messages; for p in syslogd klogd; do pidof $p >/dev/null && echo run-$p; done; "
        f"grep -q ' kernel: ' $M && echo has-kernel; grep -qE 'dnsmasq|hostapd|wpa_supplicant|udhcpc|dhcpcd|ntpd' $M && echo has-daemon; "
        f"grep -q 'systemd\\[1\\]:' $M && echo has-systemd; grep -q {tag} $M && echo has-probe; cat /etc/patronus-init")
res['syslog'] = ' '.join(o.split()); log('  syslog state:', res['syslog'])
check('syslogd + klogd run; /var/log/messages has kernel, daemon and logger lines',
      all(k in o for k in ('run-syslogd', 'run-klogd', 'has-kernel', 'has-daemon', 'has-probe')), res['syslog'])
if 'INIT=systemd' in o: check('systemd: journald forwards to syslogd (systemd[1] lines in /var/log/messages)', 'has-systemd' in o)
page = curl(['-b', JAR, BASE + '/monitoring'], 120)
check('web UI log viewer (/monitoring) shows /var/log/messages', '[syslog]' in page and tag in page and 'No journal entries' not in page)
rss('after_pages')
if PH == 'first':
    for port in ('443', '22', '80'):   # 443 first: the first Patronus apply replaces the image's boot-time WAN mgmt rule (session runs over WAN)
        rule = {'name': f'home LAN mgmt {port}', 'enabled': True, 'chain': 'input', 'action': 'accept', 'protocol': 'tcp', 'port': port,
                'interface': 'wl24-sta', 'source': MGMT, 'destination': 'any', 'description': 'SSH/web from the home LAN the Slate repeats'}
        code, txt = api('POST', '/api/firewall/rules', rule); check(f'WAN mgmt rule tcp/{port} added via the UI API', code == 201, f'{code} {txt[:80]}')
    # a unit that was not factory-reset may still carry this test's rule from an earlier run (restored by the backup
    # test): remove those first, or the "deleted -> gone from nft" check sees the old copy
    code, txt = api('GET', '/api/firewall/rules')
    if code == 200:
        rl = json.loads(txt); rl = rl if isinstance(rl, list) else rl.get('rules', [])
        for x in rl:
            if x.get('name') == 'slate e2e allow 8080': api('DELETE', f"/api/firewall/rules/{x.get('id')}")
    rule = {'name': 'slate e2e allow 8080', 'enabled': True, 'chain': 'input', 'action': 'accept', 'protocol': 'tcp', 'port': '8080',
            'interface': 'any', 'source': 'any', 'destination': 'any', 'description': 'e2e rule'}
    code, txt = api('POST', '/api/firewall/rules', rule); check('add 8080 rule via the UI API', code == 201, f'{code} {txt[:80]}')
    rid = json.loads(txt).get('id') if code == 201 else None
    t = time.time(); code, txt = api('POST', '/api/firewall/rules/apply'); res['fw_apply_s'] = round(time.time() - t, 2); log('apply', code, txt[:100], res['fw_apply_s'])
    o = ssh('nft list chain inet patronus input'); res['nft_input'] = o
    check('nftables has the 8080 rule after apply', '8080' in o)
    check('nftables has the WAN mgmt rule (Patronus-owned, not the boot rule)', o.count(MGMT) >= 2, o.count(MGMT))
    code, txt = api('POST', '/api/system/backups'); check('create backup via the UI API', code == 201, f'{code} {txt[:80]}')
    bk = json.loads(txt).get('id') if code == 201 else None
    if rid:
        api('DELETE', f'/api/firewall/rules/{rid}'); api('POST', '/api/firewall/rules/apply')
        check('rule deleted -> gone from nft', '8080' not in ssh('nft list chain inet patronus input'))
    if bk:
        code, txt = api('POST', f'/api/system/backups/{bk}/restore', {}); check('restore backup via the UI API', code == 200, f'{code} {txt[:80]}')
        time.sleep(5); check('after restore the 8080 rule is back in nft', '8080' in ssh('nft list chain inet patronus input'))
else:
    r = curl(['-o', '/dev/null', '-w', '%{http_code} %{redirect_url}', BASE + '/'], 60); check('no first-run page again', 'first-run' not in r, r)
    code, txt = api('GET', '/api/firewall/rules'); check('rules persisted (8080 + WAN mgmt)', 'slate e2e allow 8080' in txt and 'home LAN mgmt 22' in txt, str(code))
    check('nft still has them', '8080' in ssh('nft list chain inet patronus input'))
# parallel load (4 logins + 48 page loads at 8 parallel)
import concurrent.futures as cf
def one(i):
    t = time.time(); o = curl(['-b', JAR, '-o', '/dev/null', '-w', '%{http_code}', BASE + ['/', '/firewall', '/dhcp', '/system'][i % 4]], 120); return o, time.time() - t
t = time.time()
with cf.ThreadPoolExecutor(8) as ex: outs = list(ex.map(one, range(48)))
res['load'] = f"{sum(1 for o, _ in outs if o == '200')}/48 x 200 in {time.time()-t:.1f}s, slowest {max(d for _, d in outs):.1f}s"; log('load', res['load'])
rss('after_load')
res['fails'] = fails
out = os.path.join(os.environ.get('SLATE_RESULTS', '.'), f'results-web-{PH}-{int(time.time())}.json'); json.dump(res, open(out, 'w'), indent=1)
log('FAILED:', ', '.join(fails) or 'none'); log('results', out)
