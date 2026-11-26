#!/usr/bin/env python3
"""qemu-gate.py <openrc|systemd> <bundle-dir>: boot the GL-AR750S ("Slate") Patronus root under QEMU malta (MIPS 24Kc, big endian, 128 MB, OpenWrt's malta/be
kernel of the Slate's own release) and test the router role end to end. The board's radios, switch and NAND cannot be emulated: this proves the root (init
system, services, web UI, firewall in the kernel, DHCP/DNS to a LAN client, settings persistence across a guest restart, boot guard, memory), not the
board drivers. The test unit is a throwaway one (qemu-bundle.sh): a fresh ssh key, never a real unit's files.

Bundle layout (qemu-bundle.sh): vmlinux.elf, ci_ed25519 (the gate's ssh key), <init>/root.img (the shipped NOR root + malta kernel modules, squashfs).
Env: GATE_SSHP/GATE_WEBP/GATE_HTTPP/GATE_INJP (host ports, defaults 23222/28443/28080/22224), RESULTS (dir), BOOT_TIMEOUT (s, default 2400),
GATE_QEMU (default qemu-system-mips), GATE_LAN (router LAN address, default 10.0.66.1), GATE_HOLD (s: keep the unit up after the checks).
stdlib only (python3.9+); needs qemu-system-mips, ssh, mke2fs. Prints PASS:/FAIL: per check and GATEMETRIC lines, ends with "FAILED: none" (exit 0) or
"FAILED: <names>" (exit 1)."""
import http.client, json, os, re, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time

INIT = sys.argv[1]; B = os.path.abspath(sys.argv[2])
SSHP = int(os.environ.get("GATE_SSHP", 23222)); WEBP = int(os.environ.get("GATE_WEBP", 28443)); HTTPP = int(os.environ.get("GATE_HTTPP", 28080))
INJP = int(os.environ.get("GATE_INJP", 22224)); TMO = int(os.environ.get("BOOT_TIMEOUT", 2400)); QEMU = os.environ.get("GATE_QEMU", "qemu-system-mips")
LAN = os.environ.get("GATE_LAN", "10.0.66.1")
RES = os.environ.get("RESULTS", "/tmp/slate-qemu-" + INIT); os.makedirs(RES, exist_ok=True)
W = tempfile.mkdtemp(prefix="slate-qemu.", dir=os.environ.get("TMPDIR") or None)
KEY = os.path.join(B, "ci_ed25519"); PW = "Correct-Horse-Battery-9"; USER = "cigate"
fails = []; QP = None; COOKIE = ""; LANC = None; RID = None
TLS = ssl.create_default_context(); TLS.check_hostname = False; TLS.verify_mode = ssl.CERT_NONE


def out(s):
    print(s, flush=True)
    with open(os.path.join(RES, "results.txt"), "a") as f: f.write(s + "\n")


def check(name, fn):
    try:
        r = fn()
        if r is False: raise AssertionError("returned False")
        out("PASS: " + name)
    except Exception as e:
        fails.append(name); out("FAIL: " + name)
        for l in (str(e) or e.__class__.__name__).strip().splitlines()[-12:]: out("    " + l[:300])


def need(cond, msg):
    if not cond: raise AssertionError(msg)


# ------------------------------------------------------------------ guest access
SSHO = ["-i", KEY, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=20",
        "-o", "ServerAliveInterval=15", "-o", "KexAlgorithms=curve25519-sha256", "-o", "BatchMode=yes"]


def R(cmd, timeout=120):
    p = subprocess.run(["ssh"] + SSHO + ["-p", str(SSHP), "root@127.0.0.1", cmd], capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def Rok(cmd, timeout=120):
    rc, o = R(cmd, timeout); need(rc == 0, f"`{cmd[:90]}` rc={rc}: {o[-400:]}"); return o


def web(method, path, body=None, auth=True, port=None, timeout=300):
    h = {"content-type": "application/json"}
    if auth and COOKIE: h["cookie"] = COOKIE
    last = None
    for attempt in range(6):    # a handshake the emulated 24Kc could not finish (or a connection the user-mode network dropped) is retried; a refused request is not
        c = http.client.HTTPSConnection("127.0.0.1", port or WEBP, timeout=timeout, context=TLS)
        try:
            c.request(method, path, json.dumps(body) if body is not None else None, h)
            r = c.getresponse(); data = r.read().decode("utf-8", "replace"); hd = dict((k.lower(), v) for k, v in r.getheaders())
            return r.status, data, hd
        except (ssl.SSLError, ConnectionError, http.client.HTTPException, socket.timeout) as e:
            last = e; time.sleep(5)
        finally: c.close()
    raise AssertionError(f"{method} {path}: no answer after retries: {last!r}")


def jget(path):
    c, t, _ = web("GET", path); need(c == 200, f"GET {path}: {c} {t[:200]}"); return json.loads(t)


# ------------------------------------------------------------------ the LAN client: raw frames over a QEMU socket netdev (no privileges, no extra guest OS)
class Lan:
    MAC = bytes.fromhex("02c19a7e0001")

    def __init__(self):
        self.s = None; self.frames = []; self.lock = threading.Lock(); self.ip = None; self.rmac = None

    def connect(self, timeout=60):
        t = time.time()
        while time.time() - t < timeout:
            try: self.s = socket.create_connection(("127.0.0.1", INJP), 5); self.s.settimeout(None); break
            except OSError: time.sleep(1)
        need(self.s, "inject socket not up")
        threading.Thread(target=self._rd, daemon=True).start()

    def _rd(self):
        buf = b""; s = self.s
        while True:
            try: d = s.recv(65536)
            except OSError: return
            if not d: return
            buf += d
            while len(buf) >= 4:
                n = struct.unpack("!I", buf[:4])[0]
                if len(buf) < 4 + n: break
                f = buf[4:4 + n]; buf = buf[4 + n:]
                self._rx(f)

    def _rx(self, f):
        if len(f) >= 42 and f[12:14] == b"\x08\x06" and struct.unpack("!H", f[20:22])[0] == 1 and self.ip and f[38:42] == socket.inet_aton(self.ip):
            # ARP request for our leased address: answer, so the router can reach us whatever its neighbour table holds
            self.send(f[6:12] + self.MAC + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + self.MAC + socket.inet_aton(self.ip) + f[22:28] + f[28:32])
        with self.lock: self.frames.append(f)

    def send(self, f):
        f = f + bytes(max(0, 60 - len(f)))        # Ethernet minimum: the emulated NIC of newer QEMU drops runt frames (a 42-byte ARP reply never reached the guest)
        try: self.s.sendall(struct.pack("!I", len(f)) + f)
        except OSError: pass

    @staticmethod
    def csum(b):
        if len(b) % 2: b += b"\0"
        c = sum(struct.unpack("!%dH" % (len(b) // 2), b)); c = (c & 0xFFFF) + (c >> 16); c = (c & 0xFFFF) + (c >> 16); return ~c & 0xFFFF

    def udp(self, dmac, sip, dip, sport, dport, payload):
        u = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, socket.inet_aton(sip), socket.inet_aton(dip))
        h = h[:10] + struct.pack("!H", self.csum(h)) + h[12:]
        return dmac + self.MAC + b"\x08\x00" + h + u

    def udp_frames(self, dport, since):
        with self.lock: fs = self.frames[since:]
        for f in fs:
            if len(f) > 42 and f[12:14] == b"\x08\x00" and f[23] == 17 and struct.unpack("!H", f[36:38])[0] == dport:
                yield f, f[42:]

    def mark(self):
        with self.lock: return len(self.frames)

    def dhcp(self, hostname, timeout=240):
        xid = 0x5a1a7e01

        def pkt(opts):
            return struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, xid, 0, 0x8000, 0, 0, 0, 0) + self.MAC + bytes(10) + bytes(192) + b"\x63\x82\x53\x63" + opts + b"\xff"
        host = bytes([12, len(hostname)]) + hostname.encode()

        def talk(opts, want):
            m = self.mark(); t = time.time(); last = 0
            while time.time() - t < timeout:
                if time.time() - last > 20:
                    self.send(self.udp(b"\xff" * 6, "0.0.0.0", "255.255.255.255", 68, 67, pkt(opts))); last = time.time()
                for f, p in self.udp_frames(68, m):
                    if len(p) < 240 or p[0] != 2 or struct.unpack("!I", p[4:8])[0] != xid: continue
                    o = self.opts(p)
                    # the emulator's own user-mode network answers DHCP on the bridge too: only the router counts
                    if o.get(54) == socket.inet_aton(LAN) and o.get(53) == bytes([want]): return f, p, o
                time.sleep(0.5)
            raise AssertionError(f"no DHCP {'OFFER' if want == 2 else 'ACK'} from {LAN} within {timeout}s ({self.mark() - m} frames seen)")
        f, p, o = talk(bytes([53, 1, 1]) + host + bytes([55, 3, 1, 3, 6]), 2)
        offered = p[16:20]
        f, p, o = talk(bytes([53, 1, 3, 50, 4]) + offered + bytes([54, 4]) + socket.inet_aton(LAN) + host, 5)
        self.ip = socket.inet_ntoa(p[16:20]); self.rmac = f[6:12]
        self.announce()
        return {"ip": self.ip, "router": socket.inet_ntoa(o.get(3, b"\0\0\0\0")[:4]), "dns": socket.inet_ntoa(o.get(6, b"\0\0\0\0")[:4]),
                "lease": struct.unpack("!I", o.get(51, b"\0\0\0\0"))[0]}

    def announce(self):
        """gratuitous ARP for the leased address: the router learns our MAC at once (the reply of a DNS query must not wait for an ARP round trip)"""
        ip = socket.inet_aton(self.ip)
        self.send(b"\xff" * 6 + self.MAC + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + self.MAC + ip + bytes(6) + ip)

    def diag(self):
        """what the client saw, and the router's view (neighbour table, DNS listeners, dnsmasq log): evidence for a DNS timeout"""
        with self.lock: fs = list(self.frames)
        kinds = {}
        for f in fs:
            k = "arp" if f[12:14] == b"\x08\x06" else "ip%d" % f[23] if f[12:14] == b"\x08\x00" and len(f) > 23 else "ip6" if f[12:14] == b"\x86\xdd" else "other"
            kinds[k] = kinds.get(k, 0) + 1
        try:
            g = R("ip neigh show dev br-lan; ping -c2 -W5 %s >/dev/null 2>&1; echo ping-rc=$?; ip neigh show dev br-lan; netstat -lnu | grep ':53 '; grep -i dnsmasq /var/log/messages | tail -3 | cut -c1-120" % self.ip, 90)[1]
        except Exception as e: g = repr(e)
        arp, ipb = b"\x08\x06", socket.inet_aton(self.ip)
        asked = sum(1 for f in fs if f[12:14] == arp and f[20:22] == b"\x00\x01" and f[38:42] == ipb)
        return "client saw %d frames %s, ARP requests for %s: %d; guest: %s" % (len(fs), kinds, self.ip, asked, g.replace("\n", " | "))

    @staticmethod
    def opts(p):
        o = {}; i = 240
        while i < len(p) and p[i] != 255:
            if p[i] == 0: i += 1; continue
            o[p[i]] = p[i + 2:i + 2 + p[i + 1]]; i += 2 + p[i + 1]
        return o

    def dns(self, name, timeout=90):
        q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
        qid = 0x4d41; msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q
        m = self.mark(); t = time.time(); last = 0
        while time.time() - t < timeout:
            if time.time() - last > 8:
                self.send(self.udp(self.rmac, self.ip, LAN, 5353, 53, msg)); last = time.time()
            for f, p in self.udp_frames(5353, m):
                if len(p) >= 12 and struct.unpack("!H", p[:2])[0] == qid:
                    rcode = p[3] & 15; an = struct.unpack("!H", p[6:8])[0]; addrs = []
                    i = 12
                    while p[i] != 0: i += 1 + p[i]
                    i += 5
                    for _ in range(an):
                        while True:
                            if p[i] & 0xC0 == 0xC0: i += 2; break
                            if p[i] == 0: i += 1; break
                            i += 1 + p[i]
                        typ, _c, _ttl, ln = struct.unpack("!HHIH", p[i:i + 10]); i += 10
                        if typ == 1: addrs.append(socket.inet_ntoa(p[i:i + 4]))
                        i += ln
                    return rcode, addrs
            time.sleep(0.4)
        raise AssertionError(f"no DNS answer for {name} from {LAN}; " + self.diag())


# ------------------------------------------------------------------ the emulator
def qemu_start(n, data):
    global QP
    cmd = [QEMU, "-M", "malta", "-cpu", "24Kc", "-m", "128", "-kernel", os.path.join(B, "vmlinux.elf"),
           "-drive", f"file={W}/root.img,format=raw,if=ide,index=0", "-drive", f"file={data},format=raw,if=ide,index=1,cache=unsafe",   # a throwaway disk: no host flushes (dnsmasq fsyncs its lease file; under a low IO priority host that stalled DNS for minutes)
           "-append", "root=/dev/sda rootfstype=squashfs ro console=ttyS0 init=/usr/sbin/patronus-init patronus.data=/dev/sdb panic=-1",
           "-nographic", "-monitor", "none", "-serial", "file:" + os.path.join(RES, f"serial-boot{n}.txt"), "-no-reboot",
           # eth0 = LAN port (the emulator's user network 10.0.66.0/24: ssh, web 443 and the http redirect on 80 are forwarded to the router's LAN address)
           "-netdev", f"user,id=lan,net=10.0.66.0/24,host=10.0.66.2,dhcpstart=10.0.66.20,hostfwd=tcp:127.0.0.1:{SSHP}-{LAN}:22,hostfwd=tcp:127.0.0.1:{WEBP}-{LAN}:443,hostfwd=tcp:127.0.0.1:{HTTPP}-{LAN}:80",
           "-device", "pcnet,netdev=lan,romfile=",
           # eth1 = WAN (DHCP from the emulator's network, real egress)
           "-netdev", "user,id=wan,net=10.0.2.0/24", "-device", "pcnet,netdev=wan,romfile=",
           # eth2 = a second LAN port with the test client behind it (frames over a local socket)
           "-netdev", f"socket,id=inj,listen=127.0.0.1:{INJP}", "-device", "pcnet,netdev=inj,mac=02:c1:9a:7e:00:fe,romfile="]
    QP = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return QP


def qemu_stop():
    global QP
    if QP and QP.poll() is None: QP.kill()
    if QP: QP.wait(); QP = None


def GM(k, v): out(f"GATEMETRIC {k}={v}")


def boot(n, data):
    t0 = time.time(); qemu_start(n, data)
    while True:
        if QP.poll() is not None:
            out(f"FAIL: boot {n}: QEMU exited ({QP.returncode})"); fails.append(f"boot {n}: QEMU exited"); return False
        if time.time() - t0 > TMO:
            out(f"FAIL: boot {n}: no ssh within {TMO}s"); fails.append(f"boot {n}: no ssh"); return False
        try:
            rc, o = R("true", 90)
            if rc == 0: break
        except subprocess.TimeoutExpired: pass
        time.sleep(5)
    for _ in range(120):        # the web UI and the apply finish a little after sshd
        rc, o = R("grep -c patronus-started /tmp/boot-times 2>/dev/null; true", 60)
        if o.strip().endswith("1"): break
        time.sleep(3)
    GM("boot%d_s" % n, int(time.time() - t0)); return True


def stats(tag):
    rc, o = R("free -k | sed -n 2p; for p in $(pidof patronus-web patronus-cli dnsmasq etphonehome ntpd dropbear); do echo \"rss $(sed -n 's/^Name:[[:space:]]*//p' /proc/$p/status) $(sed -n 's/^VmRSS:[[:space:]]*//p' /proc/$p/status) hwm $(sed -n 's/^VmHWM:[[:space:]]*//p' /proc/$p/status)\"; done", 60)
    open(os.path.join(RES, f"stats-{tag}.txt"), "w").write(o)
    m = re.search(r"^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+(\d+)", o, re.M)
    if m: GM(f"guest_{tag}_total_mb", int(m.group(1)) // 1024); GM(f"guest_{tag}_avail_mb", int(m.group(4)) // 1024)
    for l in o.splitlines():
        m = re.match(r"rss (\S+) (\d+) kB hwm (\d+) kB", l)
        if m: GM(f"rss_{tag}_{m.group(1)}_kb", m.group(2)); GM(f"hwm_{tag}_{m.group(1)}_kb", m.group(3))


# ------------------------------------------------------------------ checks
SERVICES = ("dropbear" if INIT == "openrc" else "patronus-dropbear", "patronus-web", "patronus-applyd", "patronus-etph", "dnsmasq")


def init_checks(tag):
    pid1 = Rok("cat /proc/1/comm").strip()
    want = "openrc-init" if INIT == "openrc" else "systemd"
    need(pid1 == want, f"PID 1 is {pid1!r}, want {want!r}")
    if INIT == "openrc":
        o = Rok("rc-status -a")
        bad = [l for l in o.splitlines() if re.search(r"\[\s*(crashed|stopped|inactive)\b", l) and "Runlevel" not in l]
        bad = [l for l in bad if not re.search(r"\b(killprocs|savecache|mount-ro)\b", l)]    # shutdown-runlevel services are stopped by design
        need(not bad, "services not running:\n" + "\n".join(bad))
        for s in SERVICES: need(re.search(rf"^\s*{s}\s+\[\s*started", o, re.M), f"{s} not started:\n{o[-600:]}")
    else:
        o = Rok("systemctl --failed --no-legend --plain; echo ---; systemctl list-units --type=service --state=running --no-legend --plain | cut -d' ' -f1")
        failed, _, running = o.partition("---\n")
        need(not failed.strip(" \n-"), "failed units:\n" + failed)
        for s in SERVICES: need(re.search(rf"^{s}(\.service)?$", running, re.M), f"{s} not running:\n{running}")
    GM(f"{tag}_init", pid1)


def times():
    o = Rok("cat /tmp/boot-times"); ev = {}
    for l in o.splitlines():
        p = l.split(None, 1)
        if len(p) == 2:
            try: ev.setdefault(p[1], float(p[0]))
            except ValueError: pass
    for k in ("patronus-started", "network-up", "dropbear-up", "modules-loaded"):
        if k in ev: GM("t_" + k.replace("-", "_") + "_s", ev[k])
    need("patronus-started" in ev, "no patronus-started marker:\n" + o)
    need("NO-DATA" not in o, "the settings disk was not mounted:\n" + o)


def first_run():
    global COOKIE
    c, t, h = web("GET", "/", auth=False)
    need(c in (302, 303, 307, 308) and "/first-run" in h.get("location", ""), f"GET / before setup: {c} {h.get('location')}")
    c, t, _ = web("GET", "/first-run", auth=False); need(c == 200 and "Create administrator" in t, f"/first-run page: {c}")
    c, t, _ = web("GET", "/api/firewall/rules", auth=False); need(c == 403, f"API open before setup: {c}")
    code = Rok("cat /run/patronus/first-run-code").strip().splitlines()[-1]; need(len(code) == 14, f"setup code {code!r}")
    c, t, _ = web("POST", "/api/first-run", {"username": USER, "password": PW, "confirm": PW, "setup_code": ""}, auth=False); need(c == 403, f"claim without the setup code: {c}")
    c, t, _ = web("POST", "/api/first-run", {"username": USER, "password": "short", "confirm": "short", "setup_code": code}, auth=False); need(c == 400, f"weak password: {c} {t[:100]}")
    c, t, _ = web("POST", "/api/first-run", {"username": USER, "password": PW, "confirm": PW, "setup_code": code}, auth=False); need(c == 200, f"claim: {c} {t[:150]}")
    c, t, _ = web("POST", "/api/first-run", {"username": USER + "b", "password": PW + "z", "confirm": PW + "z", "setup_code": code}, auth=False); need(c == 409, f"second claim: {c}")
    login()


def setup_wizard_router():
    # router role: the setup wizard is offered and says what this build can set up; a step the image was built
    # without (PPPoE) is refused with a plain reason before anything changes
    c, t, _ = web("GET", "/api/setup/status"); need(c == 200, f"setup status: {c} {t[:150]}")
    s = json.loads(t); f = s.get("features", {})
    need(s.get("role") == "router" and s.get("wizard") is True, f"role/wizard: {s.get('role')} {s.get('wizard')}")
    need(f.get("dhcp") is True and f.get("pppoe") is False and f.get("ipv6") is True, f"features: {f}")
    c, t, _ = web("POST", "/api/setup/apply", {"wan_interface": "eth0", "lan_interface": "eth1", "lan_ipv4": "192.168.9.1/24",
                                               "wan_mode": "pppoe", "pppoe_username": "u", "pppoe_password": "p"})
    need(c == 400 and "PPPoE" in t, f"PPPoE on a build without it: {c} {t[:150]}")
    c, t, _ = web("GET", "/api/setup/status"); need(c == 200 and json.loads(t).get("completed") is False, f"refused apply changed setup: {t[:150]}")


def login():
    global COOKIE
    c, t, h = web("POST", "/api/auth/login", {"username": USER, "password": PW}, auth=False); need(c == 200, f"login: {c} {t[:150]}")
    sc = h.get("set-cookie", ""); need("=" in sc, "no session cookie"); COOKIE = sc.split(";")[0]


def web_ports():
    c, t, h = web("GET", "/login", auth=False); need(c == 200, f"https /login: {c}")
    hc = http.client.HTTPConnection("127.0.0.1", HTTPP, timeout=120); hc.request("GET", "/login"); r = hc.getresponse(); r.read(); loc = r.getheader("location") or ""; hc.close()
    need(r.status in (301, 302, 307, 308) and loc.startswith("https://"), f"http :80 -> {r.status} {loc!r}")
    n = Rok("netstat -ltn | grep -E ':(443|80) ' | wc -l").strip(); need(n == "2", f"listeners on 443/80: {n}")


RULE = {"name": "slate-gate allow 8080", "enabled": True, "chain": "input", "action": "accept", "protocol": "tcp", "port": "8080", "interface": "any",
        "source": "any", "destination": "any", "description": "gate rule"}


def nft_input(): return Rok("nft list chain inet patronus input")


def fw_rule():
    global RID
    c, t, _ = web("POST", "/api/firewall/rules", RULE); need(c == 201, f"add rule: {c} {t[:200]}"); RID = json.loads(t)["id"]
    c, t, _ = web("POST", "/api/firewall/rules/apply"); need(c == 200, f"apply: {c} {t[:200]}")
    need("8080" in nft_input(), "rule not in the kernel's nft chain after apply:\n" + nft_input()[-600:])


def fw_fail_closed():
    before = nft_input()
    bad = dict(RULE, name="slate-gate bad", action="bogus-action", port="99999")
    c, t, _ = web("POST", "/api/firewall/rules", bad); need(c in (400, 422), f"invalid rule accepted: {c} {t[:150]}")
    c, t, _ = web("POST", "/api/firewall/rules/apply"); need(c == 200, f"apply after the refused rule: {c} {t[:150]}")
    need(nft_input() == before, "the kernel's rules changed after a refused rule")


def history_rollback():
    h = jget("/api/system/history"); need(h, "no configuration revisions")
    # a revision holds the state BEFORE the change that created it: the revision our change makes is the way back

    c, t, _ = web("POST", "/api/firewall/rules", dict(RULE, name="slate-gate rollback me", port="8081")); need(c == 201, f"add rule 2: {c} {t[:150]}")
    c, t, _ = web("POST", "/api/firewall/rules/apply"); need(c == 200, f"apply: {c}")
    need("8081" in nft_input(), "second rule not applied")
    h2 = jget("/api/system/history"); need(len(h2) > len(h) or h2[0]["id"] != h[0]["id"], "the change made no revision")
    c, t, _ = web("GET", f"/api/system/history/{h2[0]['id']}/diff"); need(c == 200, f"diff: {c} {t[:100]}")
    back = h2[0]["id"]; c, t, _ = web("POST", f"/api/system/history/{back}/restore"); need(c == 200, f"restore revision {back}: {c} {t[:200]}")
    n = nft_input(); need("8081" not in n and "8080" in n, "restore did not put the kernel's rules back:\n" + n[-500:])
    rules = web("GET", "/api/firewall/rules")[1]; need("rollback me" not in rules, "rolled-back rule still listed")


def dhcp_dns(lan, lease):
    Rok("ip link set eth2 up && ip link set eth2 master br-lan"); time.sleep(2)
    L = lan.dhcp("gate-phone"); lease.update(L)
    need(L["router"] == LAN and L["dns"] == LAN, f"lease options: {L}")
    need(L["ip"].startswith("10.0.66.") and 100 <= int(L["ip"].split(".")[3]) <= 249, f"lease {L['ip']} outside the pool")
    time.sleep(2)
    leases = web("GET", "/api/dhcp/leases")[1]; need("02:c1:9a:7e:00:01" in leases.lower() and L["ip"] in leases, f"lease not listed by the API: {leases[:300]}")
    GM("dhcp_lease", L["ip"])


def dns_local():
    c, t, _ = web("POST", "/api/dns/hosts", {"hostname": "gatehost", "domain": "gate.test", "address": "10.0.66.77", "description": "gate"}); need(c in (200, 201), f"add host: {c} {t[:150]}")
    c, t, _ = web("POST", "/api/dns/apply"); need(c == 200, f"dns apply: {c} {t[:150]}")
    time.sleep(3)
    rc, a = LANC.dns("gatehost.gate.test"); need(rc == 0 and a == ["10.0.66.77"], f"A gatehost.gate.test -> rcode {rc} {a}")
    rc, a = LANC.dns("nohost.gate.test"); need(a == [], f"an unknown name got {a}"); GM("dns_unknown_rcode", rc)


def dns_rollback():
    h = jget("/api/system/history")
    cand = [r for r in h if "host" in (r.get("summary") or "").lower() or "dns" in (r.get("summary") or "").lower()]
    need(cand, "no revision mentions the DNS host change: " + json.dumps(h[:4]))
    c, t, _ = web("POST", f"/api/system/history/{cand[0]['id']}/restore"); need(c == 200, f"restore: {c} {t[:150]}")
    time.sleep(3)
    rc, a = LANC.dns("gatehost.gate.test"); need(a == [], f"the DNS host survived the rollback: rcode {rc} {a}")
    h2 = jget("/api/system/history"); c, t, _ = web("POST", f"/api/system/history/{h2[0]['id']}/restore"); need(c == 200, f"undo the rollback: {c} {t[:150]}")
    time.sleep(3)
    rc, a = LANC.dns("gatehost.gate.test"); need(a == ["10.0.66.77"], f"the DNS host did not come back with the undo: {rc} {a}")


def general_set():
    g = jget("/api/system/general"); need(isinstance(g, dict) and "settings" in g, "general settings: " + json.dumps(g)[:200])
    c, t, _ = web("PUT", "/api/system/general", {"hostname": "slate-gate2", "domain": "gate.test", "timezone": "America/Los_Angeles"}); need(c == 200, f"PUT general: {c} {t[:200]}")
    g = jget("/api/system/general"); need("slate-gate2" in json.dumps(g), "host name not stored: " + json.dumps(g)[:200])
    need("slate-gate2" in Rok("hostname"), "host name not applied live")


def boot_guard():
    o = R("patronus-guard status")[1]; need("armed" in o, "guard not armed at boot: " + o)
    Rok("patronus-guard ok"); o = R("patronus-guard status")[1]; need(re.search(r"\bok\b", o), "guard not confirmed: " + o)


def etph():
    Rok("pgrep etphonehome >/dev/null"); Rok("test -x /usr/sbin/etphonehome")


def main():
    global LANC, COOKIE
    shutil.copy(os.path.join(B, INIT, "root.img"), os.path.join(W, "root.img"))
    data = os.path.join(W, "data.img")
    subprocess.run(["truncate", "-s", "64M", data], check=True)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-L", "patronus_data", data], check=True)
    open(os.path.join(RES, "results.txt"), "w").close()
    LANC = Lan(); t00 = time.time(); lease = {}
    # ---------------- boot 1: fresh settings disk
    if not boot(1, data): return finish()
    LANC.connect()
    check("boot 1: boot markers (settings disk mounted, patronus started)", times)
    check(f"boot 1: init system {INIT}: PID 1, every service up, 0 crashed/failed", lambda: init_checks("boot1"))
    check("boot 1: ETPhoneHome router client running (baked into every Slate image)", etph)
    check("boot 1: router role: first-run claim (setup code; weak, mismatch, second claim refused) and login", first_run)
    check("boot 1: router role: setup wizard offered with this build's features; PPPoE (not in this build) refused, nothing changed", setup_wizard_router)
    check("boot 1: web UI on 443 and the plain-http redirect on 80, both listening", web_ports)
    check("boot 1: boot guard armed, `patronus-guard ok` confirms the boot", boot_guard)
    check("boot 1: firewall rule added through the web API is in the kernel's nft chain after apply", fw_rule)
    check("boot 1: an invalid firewall rule is refused and the kernel's rules stay exactly as they were", fw_fail_closed)
    check("boot 1: config change recorded as a revision; restoring the earlier revision removes it from nft", history_rollback)
    check("boot 1: DHCP: a LAN client behind eth2 gets a lease from the router (pool, router + DNS options) and the API lists it", lambda: dhcp_dns(LANC, lease))
    check("boot 1: DNS: the router answers a local host record to that client; an unknown name gets no address", lambda: dns_local() if lease else need(False, "no lease"))
    check("boot 1: DNS change rolled back through the revision history and undone again", lambda: dns_rollback() if lease else need(False, "no lease"))
    check("boot 1: system settings (host name, domain, time zone) saved through the web API and applied", general_set)
    time.sleep(30); stats("boot1")
    Rok("sync")
    c, t, _ = web("POST", "/api/system/reboot", {})
    check("boot 1: restart from the web UI (POST /api/system/reboot) accepted", lambda: need(c == 202, f"{c} {t[:100]}"))
    try: QP.wait(timeout=300)
    except subprocess.TimeoutExpired: pass
    qemu_stop()
    # ---------------- boot 2: the same settings disk
    LANC = Lan(); COOKIE = ""
    if not boot(2, data): return finish()
    LANC.connect()
    check("boot 2: boot markers, settings disk mounted", times)
    check(f"boot 2: init system {INIT}: PID 1, every service up, 0 crashed/failed", lambda: init_checks("boot2"))

    def p1():
        n = nft_input(); need("8080" in n, "firewall rule gone after the restart:\n" + n[-500:]); need("8081" not in n, "rolled-back rule came back")
    check("boot 2: the firewall rule persisted across the restart (settings disk) and is applied at boot", p1)

    def p2():
        global COOKIE
        c, t, h = web("GET", "/", auth=False); need(c in (302, 303, 307, 308) and "first-run" not in h.get("location", ""), f"first-run again: {c} {h.get('location')}")
        COOKIE = ""; c, t, _ = web("GET", "/api/firewall/rules"); need(c == 401, f"API without login: {c}")
        login(); c, t, _ = web("GET", "/api/firewall/rules"); need(c == 200 and "slate-gate allow 8080" in t, f"rules via API: {c}")
    check("boot 2: no first-run again, the API still needs a login, the same password works, the rule is listed", p2)
    check("boot 2: web UI on 443 and the http redirect on 80", web_ports)

    def p3():
        g = jget("/api/system/general"); j = json.dumps(g)
        need("slate-gate2" in j and "gate.test" in j and "America/Los_Angeles" in j, "general settings lost: " + j[:300])
        hn = Rok("hostname"); need("slate-gate2" in hn, "host name not applied at boot: " + hn)
        tz = Rok("cat /etc/TZ 2>/dev/null; echo ---; date +%Z; ls /usr/share/zoneinfo 2>&1 | head -2"); GM("tz_check", tz.replace("\n", " | ")[:80])
    check("boot 2: system settings (host name, domain, time zone) persisted and applied at boot", p3)

    def p4():
        Rok("ip link set eth2 up && ip link set eth2 master br-lan"); time.sleep(2)
        L = LANC.dhcp("gate-phone"); need(L["ip"] == lease.get("ip"), f"the same client got {L['ip']}, had {lease.get('ip')}")
        rc, a = LANC.dns("gatehost.gate.test"); need(a == ["10.0.66.77"], f"DNS host record lost after the restart: {rc} {a}")
    check("boot 2: DHCP lease kept (same client, same address) and the DNS record still answers", lambda: p4() if lease else need(False, "no lease in boot 1"))
    check("boot 2: boot guard armed again, confirmed", boot_guard)
    time.sleep(60); stats("boot2")
    GM("gate_s", int(time.time() - t00))
    if os.environ.get("GATE_HOLD"):
        out(f"HOLD: unit up for {os.environ['GATE_HOLD']}s (web on 127.0.0.1:{WEBP}, user {USER})"); time.sleep(int(os.environ["GATE_HOLD"]))
    return finish()


def finish():
    qemu_stop()
    shutil.rmtree(W, ignore_errors=True)
    if not fails: out("FAILED: none"); return 0
    out("FAILED: " + "; ".join(fails)); return 1


if __name__ == "__main__":
    rc = 1
    try: rc = main()
    except KeyboardInterrupt: rc = 130
    finally: qemu_stop()
    sys.exit(rc)
