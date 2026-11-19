"""Installed Patronus image: first-run wizard + configuration that must survive a reboot (init-agnostic: OpenRC and systemd use the same script).

fw  = Patronus installed from the ISO by the unattended installer; WAN = QEMU user net (enp0s1, 10.0.2.x), LAN = hub `lan` (enp0s2, 10.77.0.1/24)
cli = Alpine live on the same hub (a real second kernel and NIC standing in for "a client in a second network namespace")

What it proves on the SHIPPED image (the daily ISO's own files, init scripts and kernel; the netns lanes in ci/netlab cannot):
 1. the product is package-managed: binaries, init scripts, systemd templates and config belong to net-firewall/patronus (qfile/qcheck), so the
    wizard cannot hit a service that "does not exist" (patronus-dhcpc was missing on the hand-copied image)
 2. a wizard that fails half-way answers one readable sentence and leaves NOTHING applied (LAN address, roles, completed flag all unchanged)
 3. the wizard with the default WAN = "DHCP from the ISP" answers 200 and a dhcpcd client for the WAN interface runs (the supervised
    patronus-dhcpc instance), the LAN is static and the installer's system dhcpcd is told to keep off both ports
 4. a LAN pool + a reservation + a static WAN gateway configured through the API are all still there after a reboot: dnsmasq runs, the client gets
    the RESERVED address, the static default route (proto 250) is present, no DHCP default route fights it

    python3 -m vmtest run scenarios/installed_firstrun.py --arg iso=patronus-...iso
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vmtest import Disk, Network, Nic, NodeSpec, Test, cache  # noqa: E402
from vmtest.recipes import PROJECTS, PW, make_answers, unattended_install  # noqa: E402

ALPINE = ("https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.4-x86_64.iso",
          "157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f")

# every operational value of the scenario in one place (nothing buried in the steps)
WAN, LAN = "enp0s1", "enp0s2"
WAN_NET, WAN_GW = "10.0.2.15/24", "10.0.2.2"
LAN_IP, POOL = "10.77.0.1", ("10.77.0.100", "10.77.0.199")
CLIENT_MAC, RESERVED = "52:54:00:02:00:01", "10.77.0.50"
UNUSED_LAN = "10.88.0.1/24"          # what a half-applied failing wizard would leave on the LAN port

# runs inside the guest: log in once (cookie jar), then METHOD PATH [JSON] -> "HTTP <code>\n<body>"
API_PY = r'''
import json, ssl, sys, urllib.request, urllib.error, http.cookiejar
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.MozillaCookieJar("/tmp/fwapi.jar")
try: jar.load(ignore_discard=True)
except OSError: pass
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=ctx))
def call(m, p, body=None):
    r = urllib.request.Request(sys.argv[4] + p, method=m, data=None if body is None else json.dumps(body).encode(), headers={"content-type": "application/json"})
    try:
        x = op.open(r, timeout=180); return x.status, x.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
m, p = sys.argv[1], sys.argv[2]
body = json.loads(sys.argv[3]) if sys.argv[3] != "-" else None
s, b = call(m, p, body)
if s == 401:
    ls, lb = call("POST", "/api/auth/login", {"username": sys.argv[5], "password": sys.argv[6]})
    if ls != 200: print("HTTP", ls); print(lb); sys.exit(0)
    jar.save(ignore_discard=True); s, b = call(m, p, body)
print("HTTP", s); print(b)
'''


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers("patronus")
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8", boot_timeout=420,
                  nics=[Nic("user", forwards={}), Nic("lan", mac="52:54:00:01:00:01")])
    cli = NodeSpec(name="cli", mem=512, cpus=1, iso=args.get("client_iso") or cache.fetch(*ALPINE), disks=[Disk("1G")],
                   nics=[Nic("user", forwards={}), Nic("lan", mac=CLIENT_MAC)])

    def run(m):
        fw, cli = m.fw, m.cli

        def api(method, path, body=None, timeout=240):
            """-> (http status, parsed JSON or text) of one call to the web API from inside the guest."""
            arg = "-" if body is None else "'" + json.dumps(body).replace("'", "'\\''") + "'"
            out = fw.succeed(f"python3 /tmp/fwapi.py {method} {path} {arg} https://127.0.0.1:{P['port']} {P['web_user']} '{PW}'", timeout=timeout)
            head, _, rest = out.strip().partition("\n")
            code = int(head.split()[1])
            try:
                return code, json.loads(rest)
            except ValueError:
                return code, rest

        def default_routes():
            return fw.execute("ip -4 route show default")[1]

        m.phase("install the firewall, boot the client")
        unattended_install(m, fw)
        cli.start()
        cli.wait_for_shell()
        cli.succeed("ip link set eth1 up")

        m.phase("first boot of the installed disk")
        fw.start()
        m.check("fw-boots-to-login", fw.q.expect(r"login:", fw.T(420)), "")
        fw.wait_for_shell()
        fw.wait_for_unit(P["svc"], 300)
        m.check(f"{P['svc']}-active", True, fw.init.name)
        fw.wait_until_succeeds(f"timeout 3 bash -c ': </dev/tcp/127.0.0.1/{P['port']}'", 120, 3)   # no nc on the image
        fw.put_file(_write_tmp(API_PY), "/tmp/fwapi.py")
        code, st = api("GET", "/api/setup/status")
        m.check("wizard-status-before", code == 200 and st.get("completed") is False and st.get("wizard") is True, str(st)[:300])

        m.phase("1. the product is owned by a package")
        owned = fw.succeed("for f in /usr/bin/patronus-web /usr/bin/patronus-cli /etc/init.d/patronus-dhcpc /etc/init.d/patronus-services "
                           "/usr/lib/systemd/system/patronus-dhcpc@.service /usr/lib/systemd/system/patronus-services.service "
                           "/etc/patronus/patronus.toml /etc/pam.d/patronus; do echo \"$f $(qfile -Cq $f)\"; done")
        bad = [ln for ln in owned.strip().splitlines() if not ln.endswith(" net-firewall/patronus")]
        m.check("product-files-owned-by-net-firewall-patronus", not bad, "unowned: " + "; ".join(bad) if bad else "binaries, OpenRC scripts, systemd units, config, PAM service")
        out = fw.succeed("n=0; m=0; for f in $(qlist -e net-firewall/patronus); do n=$((n+1)); [ -e $f ] || [ -L $f ] || { m=$((m+1)); echo missing:$f; }; done; echo files=$n missing=$m")
        m.check("every-file-of-the-product-package-is-on-disk", "files=0 " not in out and out.strip().endswith("missing=0"), out.strip()[-300:])

        m.phase("2. a failing wizard is readable and leaves nothing applied")
        code, r = api("POST", "/api/setup/apply", {"wan_interface": "nosuch0", "wan_mode": "dhcp", "lan_interface": LAN, "lan_ipv4": UNUSED_LAN, "dhcp": False, "force": True})
        msg = r.get("error", "") if isinstance(r, dict) else str(r)
        m.check("wizard-refuses-a-port-that-does-not-exist", code == 400 and "does not exist" in msg and "\n" not in msg, f"{code} {msg[:300]}")
        # the LAN step succeeds and applies, the WAN step then fails on its address: the LAN change must be undone, not left half-applied
        code, r = api("POST", "/api/setup/apply", {"wan_interface": WAN, "wan_mode": "static", "wan_ipv4": "not-an-address", "wan_gateway": WAN_GW, "lan_interface": LAN,
                                                   "lan_ipv4": UNUSED_LAN, "dhcp": False, "force": True})
        msg = r.get("error", "") if isinstance(r, dict) else str(r)
        m.check("failing-wizard-is-http-4xx-5xx-with-one-sentence", code >= 400 and msg.startswith("Setup was not applied and nothing was changed.") and "\n" not in msg and r.get("rolled_back") is True, f"{code} {msg[:300]}")
        m.check("failing-wizard-left-the-lan-port-alone", UNUSED_LAN.split("/")[0] not in fw.succeed(f"ip -4 addr show dev {LAN}") and LAN_IP in fw.succeed(f"ip -4 addr show dev {LAN}"), "LAN keeps the installer's address")
        code, st = api("GET", "/api/setup/status")
        m.check("failing-wizard-did-not-mark-setup-done", st.get("completed") is False, str(st.get("completed")))

        m.phase("3. wizard, WAN = DHCP from the ISP (the default)")
        code, r = api("POST", "/api/setup/apply", {"wan_interface": WAN, "wan_mode": "dhcp", "lan_interface": LAN, "lan_ipv4": f"{LAN_IP}/24",
                                                   "dhcp": True, "dhcp_start": POOL[0], "dhcp_end": POOL[1], "force": True})
        m.check("wizard-dhcp-wan-answers-200", code == 200 and r.get("completed") is True, f"{code} {str(r)[:300]}")
        # the installed image has ONE DHCP client, the system dhcpcd manager; Patronus asks it to run DHCP on the WAN port (a second dhcpcd for
        # the same port would only hand its command line to the manager and exit). The lease must be the WAN's, dynamic, with a default route.
        fw.wait_until_succeeds(f"dhcpcd -U {WAN} 2>&1 | grep -q '^ip_address='", 90, 3)
        m.check("dhcpcd-holds-a-lease-for-the-wan-interface", True, fw.succeed(f"dhcpcd -U {WAN} 2>&1 | grep -E '^(ip_address|routers)='").strip()[:200])
        m.check("no-failing-second-dhcp-client-for-the-wan", fw.execute(f"pgrep -fc '[s]upervise-daemon patronus-dhcpc.{WAN}'")[1].strip() in ("0", ""), "no respawning patronus-dhcpc instance beside the manager")
        fw.wait_until_succeeds(f"ip -4 route show default dev {WAN} | grep -q via", 90, 3)
        fw.wait_until_succeeds("pgrep -x dnsmasq >/dev/null", 60, 2)
        m.check("wizard-started-the-lan-dhcp-server", True, "dnsmasq")
        conf = fw.succeed("cat /etc/dhcpcd.conf")
        m.check("system-dhcpcd-keeps-off-the-static-lan-port-only", f"denyinterfaces {LAN}\n" in conf and f"denyinterfaces {WAN}" not in conf.split("# BEGIN patronus-managed")[-1], "denyinterfaces block: LAN denied, WAN (DHCP) left to the manager")
        m.check("deny-block-is-in-the-global-part-of-dhcpcd-conf", conf.index("# BEGIN patronus-managed") < conf.index(f"interface {LAN}") if f"interface {LAN}" in conf else True, "before the first interface scope")
        code, st = api("GET", "/api/setup/status")
        m.check("wizard-marks-setup-done", st.get("completed") is True, str(st.get("completed")))

        m.phase("4. LAN pool + reservation + static WAN, then a reboot")
        code, r = api("POST", "/api/setup/apply", {"wan_interface": WAN, "wan_mode": "static", "wan_ipv4": WAN_NET, "wan_gateway": WAN_GW, "lan_interface": LAN,
                                                   "lan_ipv4": f"{LAN_IP}/24", "dhcp": True, "dhcp_start": POOL[0], "dhcp_end": POOL[1], "force": True})
        m.check("wizard-static-wan-answers-200", code == 200, f"{code} {str(r)[:300]}")
        conf = fw.succeed("cat /etc/dhcpcd.conf")
        m.check("system-dhcpcd-keeps-off-both-ports-once-static", f"denyinterfaces {WAN} {LAN}" in conf or f"denyinterfaces {LAN} {WAN}" in conf, "denyinterfaces block lists both ports")
        code, d = api("GET", "/api/dhcp")
        pools = d.get("pools", []) if isinstance(d, dict) else []
        pid = next((p["id"] for p in pools if p.get("interface") == LAN), None)
        m.check("lan-pool-exists", pid is not None, str(pools)[:200])
        code, r = api("POST", f"/api/dhcp/pools/{pid}/static", {"mac": CLIENT_MAC, "ip": RESERVED, "hostname": "vmtest-client"})
        m.check("reservation-created", code in (200, 201), f"{code} {r}")
        fw.wait_until_succeeds(f"ip -4 route show default | grep -q 'proto 250'", 60, 2)
        m.check("static-default-route-before-reboot", "proto 250" in default_routes(), default_routes().strip())
        _lease(m, cli, "before-reboot")

        fw.succeed("sync")
        fw.reboot(420)
        fw.wait_for_unit(P["svc"], 300)
        m.check("fw-back-after-reboot", True, fw.init.name)
        # the second boot pass (patronus-services) runs once the network is up: allow it a bounded time, then everything must be in place
        fw.wait_until_succeeds("pgrep -x dnsmasq >/dev/null", 180, 3)
        m.check("dnsmasq-running-after-reboot", True, fw.succeed("pgrep -a dnsmasq").strip()[:120])
        fw.wait_until_succeeds("ip -4 route show default | grep -q 'proto 250'", 120, 3)
        routes = default_routes()
        m.check("static-default-route-after-reboot", "proto 250" in routes and WAN_GW in routes, routes.strip())
        m.check("no-dhcp-default-route-fights-the-static-one", "proto dhcp" not in routes, routes.strip())
        lan_routes = fw.succeed(f"ip -4 route show dev {LAN}")
        m.check("lan-port-is-static-not-dhcp-managed", "proto dhcp" not in lan_routes and LAN_IP in fw.succeed(f"ip -4 addr show dev {LAN}"), lan_routes.strip())
        _lease(m, cli, "after-reboot")
        fw.screenshot("fw-after-reboot")

    def _lease(m, cli, when):
        """The client (no address) asks for one: the pool must hand out the RESERVED address for its MAC."""
        cli.succeed("ip addr flush dev eth1; ip link set eth1 up")
        cli.wait_until_succeeds("udhcpc -i eth1 -n -q -t 3 -T 2 >/dev/null 2>&1", 150, 5)
        got = cli.succeed("ip -4 -o addr show dev eth1")
        m.check(f"client-gets-the-reserved-address-{when}", RESERVED in got, got.strip()[:200])

    return Test("installed-firstrun", nodes=[fw, cli], networks=[Network("lan")], run=run, timeout=5400,
                description="installed Patronus: package-owned product, wizard (DHCP WAN, readable failure), reboot persistence of DHCP/DNS service and routes")


def _write_tmp(text):
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    f.write(text)
    f.close()
    return f.name
