"""Long-lived QEMU malta guest with a unix-socket command server (so a test session can reuse one boot).
  guestd.py serve <rootfs> [data.img]      # boots, serves /out/guest.sock
  guestd.py x '<shell cmd>' [timeout]      # run a command in the guest, print output, exit with its rc
  guestd.py quit | reboot-guest <rootfs>   # (see harness: 'reboot' in the guest powers QEMU off; serve again to boot)"""
import sys, os, json, socket, time, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
SOCK = '/out/guest.sock'

def serve(rootfs, data='/out/data.img'):
    from qemu_harness import Guest
    g = Guest('/out/vmlinux-malta-be2', rootfs, data, log='/out/guest-serve.log')
    if os.path.exists(SOCK): os.unlink(SOCK)
    s = socket.socket(socket.AF_UNIX); s.bind(SOCK); s.listen(4)
    while True:
        c, _ = s.accept()
        req = json.loads(c.makefile().readline())
        if req['cmd'] == '__quit__':
            g.kill(); c.sendall(b'{"out":"bye","rc":0}\n'); break
        if req['cmd'] == '__alive__':
            c.sendall(json.dumps({'out': 'up' if g.p.poll() is None else 'down', 'rc': 0}).encode() + b'\n'); continue
        try:
            o, rc = g.run(req['cmd'], req.get('t', 60))
        except Exception as e:
            o, rc = f'ERR {e}', 255
        c.sendall(json.dumps({'out': o, 'rc': rc}).encode() + b'\n')

def x(cmd, t=60):
    s = socket.socket(socket.AF_UNIX); s.connect(SOCK)
    s.sendall(json.dumps({'cmd': cmd, 't': t}).encode() + b'\n')
    r = json.loads(s.makefile().readline()); print(r['out']); return r['rc']

if __name__ == '__main__':
    if sys.argv[1] == 'serve': serve(*sys.argv[2:])
    elif sys.argv[1] == 'x': sys.exit(x(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 60))
    elif sys.argv[1] == 'quit': x('__quit__')
