"""Load check on a booted router tier (data.img already holds the admin password from t_e2e.py): parallel page loads, then peak RSS."""
import sys, time, subprocess, json, os, concurrent.futures as cf
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qemu_harness import Guest
PW = 'Correct-Horse-Battery-9'; BASE = 'https://127.0.0.1:18443'
g = Guest('/out/vmlinux-malta-be2', sys.argv[1], '/out/data.img', log='/out/guest-load.log')
time.sleep(20)
while g.run('grep -c "Starting web server" /var/log/web.log 2>/dev/null; true', 30)[0].strip().split('\n')[-1] != '1': time.sleep(4)
time.sleep(5)
def rss():
    o, _ = g.run('for p in /proc/[0-9]*; do n=$(cat $p/comm 2>/dev/null); case $n in patronus-web) grep -E "VmHWM|VmRSS" $p/status;; esac; done', 30); return o
print('before:', rss().replace('\n', ' '))
# 4 independent logins at once (argon2 in parallel is the worst case for memory)
def login(i):
    jar = f'/tmp/jar{i}'
    r = subprocess.run(['curl','-sk','-m','180','-c',jar,'-H','content-type: application/json','-d',json.dumps({'username':'admin','password':PW}),'-o','/dev/null','-w','%{http_code}',BASE+'/api/auth/login'],capture_output=True,text=True); return r.stdout
t = time.time()
with cf.ThreadPoolExecutor(4) as ex: print('4 parallel logins:', list(ex.map(login, range(4))), f'{time.time()-t:.1f}s')
print('after logins:', rss().replace('\n', ' '))
pages = ['/', '/firewall', '/system', '/dhcp', '/interfaces', '/monitoring']
def hit(i):
    jar = f'/tmp/jar{i % 4}'; p = pages[i % len(pages)]
    r = subprocess.run(['curl','-sk','-m','180','-b',jar,'-o','/dev/null','-w','%{http_code}',BASE+p],capture_output=True,text=True); return r.stdout
t = time.time()
with cf.ThreadPoolExecutor(8) as ex: codes = list(ex.map(hit, range(96)))
print('96 page loads, 8 parallel:', {c: codes.count(c) for c in set(codes)}, f'{time.time()-t:.1f}s')
print('after load:', rss().replace('\n', ' '))
o, _ = g.run('free', 30); print(o)
g.kill()
