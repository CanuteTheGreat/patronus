"""Tiny QEMU malta (MIPS BE) console harness: boot a squashfs rootfs + ext4 data disk, run shell commands over the serial console."""
import subprocess, threading, time, os, re, sys

class Guest:
    def __init__(self, kernel, rootfs, data, mem=128, fwd=((18443, 443), (18080, 80)), log='/out/guest.log'):
        fw = ','.join(f'hostfwd=tcp:127.0.0.1:{h}-192.168.1.1:{g}' for h, g in fwd)
        self.cmd = ['qemu-system-mips', '-M', 'malta', '-cpu', '24Kc', '-m', str(mem), '-kernel', kernel,
                    '-drive', f'file={rootfs},format=raw,if=virtio,readonly=on',
                    '-drive', f'file={data},format=raw,if=ide,index=0',
                    '-append', 'root=/dev/vda rootfstype=squashfs ro console=ttyS0 init=/sbin/init',
                    '-nographic', '-no-reboot',
                    # eth0 = LAN port (slirp net 192.168.1.0/24, the router is 192.168.1.1), eth1 = WAN port (10.0.2.0/24, DHCP, real egress)
                    '-netdev', f'user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dhcpstart=192.168.1.50,{fw}', '-device', 'pcnet,netdev=lan,romfile=',
                    '-netdev', 'user,id=wan,net=10.0.2.0/24', '-device', 'pcnet,netdev=wan,romfile=']
        self.buf = ''
        self.log = open(log, 'a')
        self.p = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.n = 0
        threading.Thread(target=self._rd, daemon=True).start()

    def _rd(self):
        while True:
            b = self.p.stdout.read(1)
            if not b:
                return
            c = b.decode('latin1')
            self.buf += c
            self.log.write(c); self.log.flush()

    def wait(self, pat, timeout=120):
        t = time.time()
        while time.time() - t < timeout:
            if re.search(pat, self.buf):
                return True
            time.sleep(0.2)
        raise TimeoutError(pat + ' | tail: ' + self.buf[-400:])

    def run(self, cmd, timeout=60):
        """Run `cmd` (one or more shell lines); return (output, exit_code). Markers are printf'd so the
        console's echo of the command line can never be mistaken for them."""
        self.n += 1
        n = self.n
        start = len(self.buf)
        self.p.stdin.write((f"printf '@@%s@@\\n' S{n}\n{cmd}\nprintf '@@%s@@%s\\n' E{n} $?\n").encode()); self.p.stdin.flush()
        t = time.time()
        while time.time() - t < timeout:
            m = re.search(rf'@@E{n}@@(\d+)\r?\n', self.buf[start:])
            if m:
                seg = self.buf[start:start + m.start()].replace('\r', '')
                k = seg.find(f'@@S{n}@@\n')
                body = seg[k + len(f'@@S{n}@@\n'):] if k >= 0 else seg
                body = '\n'.join(l for l in body.split('\n') if not l.startswith('~ #') and "printf '@@%s@@" not in l)
                return body.strip('\n'), int(m.group(1))
            time.sleep(0.2)
        raise TimeoutError(cmd)

    def kill(self):
        self.p.kill()
