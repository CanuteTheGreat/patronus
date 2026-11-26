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
# the virtual ISP (Alpine node on hub "isp"): IPv4 transit, RA + DHCPv6 with prefix delegation (kea), PPPoE access concentrator
FW_ISP_MAC, ISP_MAC = "52:54:00:01:00:04", "52:54:00:03:00:01"
ISP_V4, ISP_WAN_V4 = "203.0.113.1", "203.0.113.2/24"
ISP_V6_NET, PD_POOL, PD_POOL_LEN, PD_LEN = "2001:db8:ffff::", "2001:db8:1000::", 40, 56
PD_POOL_PREFIX = "2001:db8:10"        # every delegated /56 starts with it, and so does the LAN's /64 out of it
PPP_USER, PPP_SECRET = "wizard-user", "wizard-s3cret"
ALPINE_REPO = "https://dl-cdn.alpinelinux.org/alpine/v3.24/main"
# the live Alpine image starts with every NIC down and no pppoe kernel module (modloop of linux-virt): bring eth0 up for DHCP, and run the
# access concentrator in user mode (no -k); the firewall's side is the real kernel PPPoE client
ISP_SETUP = (f"ip link set eth0 up && timeout 60 udhcpc -i eth0 -q -n -t 10 >/dev/null 2>&1 && echo {ALPINE_REPO} > /etc/apk/repositories && "
             "timeout 180 apk update -q && timeout 300 apk add -q radvd kea-dhcp6 rp-pppoe ppp-daemon ppp-pppoe >/dev/null && modprobe ppp_generic; "
             f"sysctl -qw net.ipv6.conf.eth1.accept_dad=0 && ip link set eth1 up && ip addr add {ISP_V4}/24 dev eth1 && ip -6 addr add {ISP_V6_NET}1/64 dev eth1 && "
             "sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv4.ip_forward=1")
_RADVD = ("interface eth1 { AdvSendAdvert on; AdvManagedFlag on; AdvOtherConfigFlag on; MinRtrAdvInterval 3; MaxRtrAdvInterval 6; "
          f"prefix {ISP_V6_NET}/64 {{ AdvOnLink on; AdvAutonomous off; }}; }};")
_KEA = ('{"Dhcp6": {"interfaces-config": {"interfaces": ["eth1"]}, "lease-database": {"type": "memfile", "persist": false}, '
        '"valid-lifetime": 1200, "preferred-lifetime": 600, "loggers": [{"name": "kea-dhcp6", "severity": "INFO", '
        '"output_options": [{"output": "/var/log/kea/kea6.log"}]}], "subnet6": [{"id": 1, "subnet": "%s/64", "interface": "eth1", '
        '"pools": [{"pool": "%s100-%s200"}], "pd-pools": [{"prefix": "%s", "prefix-len": %d, "delegated-len": %d}]}]}}'
        % (ISP_V6_NET, ISP_V6_NET, ISP_V6_NET, PD_POOL, PD_POOL_LEN, PD_LEN))
ISP_V6_START = (f"printf '%s\\n' '{_RADVD}' > /tmp/radvd.conf && printf '%s\\n' '{_KEA}' > /tmp/kea6.json && "
                "mkdir -p /run/kea /var/lib/kea /var/log/kea && radvd -C /tmp/radvd.conf -p /tmp/radvd.pid && "
                "(kea-dhcp6 -c /tmp/kea6.json > /tmp/kea6.out 2>&1 &) && sleep 2 && pgrep kea-dhcp6 >/dev/null")
ISP_V6_STOP = "kill $(cat /tmp/radvd.pid) 2>/dev/null; pkill kea-dhcp6; ip -6 route flush proto static 2>/dev/null; true"
ISP_PPPOE_START = (f"printf 'require-pap\\nlcp-echo-interval 10\\nlcp-echo-failure 3\\nms-dns {ISP_V4}\\n' > /etc/ppp/pppoe-server-options && "
                   f"printf '\"{PPP_USER}\" * \"{PPP_SECRET}\" *\\n' > /etc/ppp/pap-secrets && chmod 600 /etc/ppp/pap-secrets && "
                   "pppoe-server -I eth1 -L 100.64.0.1 -R 100.64.0.10 -N 4 && sleep 1 && pgrep pppoe-server >/dev/null")
ISP_PPPOE_STOP = "pkill pppoe-server; pkill pppd; true"

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


WEBPORTS_PY = r'''
import http.client, ssl, subprocess, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
out = []
def https(port):
    c = http.client.HTTPSConnection("127.0.0.1", port, timeout=15, context=ctx); c.request("GET", "/login"); r = c.getresponse(); return r.status
out.append("https443=%s" % https(443))
try:
    out.append("https8443=%s" % https(8443))
except OSError:
    out.append("https8443=closed")
c = http.client.HTTPConnection("127.0.0.1", 80, timeout=15); c.request("GET", "/some/page?x=1", headers={"Host": "10.9.9.9"})
r = c.getresponse(); out.append("http80=%s loc=%s" % (r.status, r.getheader("Location")))
pid = subprocess.check_output(["pgrep", "-x", "patronus-web"]).split()[0].decode()
st = dict(l.split(":\t", 1) for l in open("/proc/%s/status" % pid).read().splitlines() if ":\t" in l)
out.append("uid=%s capeff_bind=%s" % (st["Uid"].split()[0], (int(st["CapEff"], 16) >> 10) & 1))
print(" ".join(out))
'''


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers("patronus")
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8", boot_timeout=420,
                  nics=[Nic("user", forwards={}), Nic("lan", mac="52:54:00:01:00:01"), Nic("isp", mac=FW_ISP_MAC)])
    cli = NodeSpec(name="cli", mem=512, cpus=1, iso=args.get("client_iso") or cache.fetch(*ALPINE), disks=[Disk("1G")],
                   nics=[Nic("user", forwards={}), Nic("lan", mac=CLIENT_MAC)])
    isp = NodeSpec(name="isp", mem=768, cpus=1, iso=args.get("client_iso") or cache.fetch(*ALPINE), disks=[Disk("1G")],
                   nics=[Nic("user", forwards={}), Nic("isp", mac=ISP_MAC)])

    def run(m):
        fw, cli, isp = m.fw, m.cli, m.isp

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
        boot_apply_health(m, fw, "first-boot", full=False)
        fw.wait_until_succeeds(f"timeout 3 bash -c ': </dev/tcp/127.0.0.1/{P['port']}'", 120, 3)   # no nc on the image
        fw.put_file(_write_tmp(API_PY), "/tmp/fwapi.py")
        # the web UI is where OpenWrt/pfSense users expect it: https://router-address (443) and http://router-address (80, redirect only), the
        # nothing on 8443 unless opted in, and the process holds only the capability to bind them (not root); same on OpenRC and systemd
        m.phase("0a. boot loader: /boot and the ESP are in fstab, a kernel update changes the menu, the menu never waits for a key")
        boot_health(m, fw)
        m.phase("0. web UI on the standard ports")
        fw.put_file(_write_tmp(WEBPORTS_PY), "/tmp/webports.py")
        wp = fw.succeed("python3 /tmp/webports.py", timeout=90).strip()
        m.check("web-ui-https-443-answers", "https443=200" in wp, wp)
        m.check("web-ui-http-80-redirects-to-https", "http80=308 loc=https://10.9.9.9/some/page?x=1" in wp, wp)
        m.check("web-ui-8443-is-not-listening-by-default", "https8443=closed" in wp, wp)
        m.check("web-ui-runs-unprivileged-with-bind-capability", "capeff_bind=1" in wp and "uid=0" not in wp, wp)
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
        boot_apply_health(m, fw, "after-reboot")
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

        # ---- pfSense/OPNsense wizard parity against a real (virtual) ISP: DHCPv6 prefix delegation, PPPoE, then an OPT port ----
        isp_if = fw.succeed(f"ip -o link | awk -F': ' '/{FW_ISP_MAC}/ {{print $2}}' | cut -d@ -f1").strip()
        m.check("isp-facing-port-found", bool(isp_if) and isp_if not in (WAN, LAN), isp_if)
        m.phase("5. ISP node: router advertisements + DHCPv6 with prefix delegation (kea), PPPoE access concentrator")
        isp.start()
        isp.wait_for_shell()
        isp.succeed(ISP_SETUP, timeout=600)
        m.check("isp-node-ready", True, isp.succeed("command -v radvd kea-dhcp6 pppoe-server | tr '\\n' ' '"))
        isp.succeed(ISP_V6_START, timeout=60)

        m.phase("6. wizard: WAN DHCPv6 asking for a /56, LAN tracks the delegated prefix")
        base = {"wan_interface": isp_if, "lan_interface": LAN, "lan_ipv4": f"{LAN_IP}/24", "dhcp": True, "dhcp_start": POOL[0],
                "dhcp_end": POOL[1], "force": True}
        code, r = api("POST", "/api/setup/apply", dict(base, wan_mode="static", wan_ipv4=ISP_WAN_V4, wan_gateway=ISP_V4,
                                                       wan_ipv6_mode="slaac", lan_ipv6_mode="track"))
        m.check("wizard-refuses-lan-tracking-without-dhcpv6", code == 400, f"{code} {str(r)[:200]}")
        code, r = api("POST", "/api/setup/apply", dict(base, wan_mode="static", wan_ipv4=ISP_WAN_V4, wan_gateway=ISP_V4,
                                                       wan_ipv6_mode="dhcp6", wan_pd_len=PD_LEN, lan_ipv6_mode="track"))
        m.check("wizard-dhcpv6-pd-answers-200", code == 200, f"{code} {str(r)[:300]}")
        try:
            fw.wait_until_succeeds(f"ip -6 -o addr show dev {LAN} scope global | grep -q '{PD_POOL_PREFIX}'", 180, 3)
            got = fw.succeed(f"ip -6 -o addr show dev {LAN} scope global").strip()
            m.check("lan-tracks-the-delegated-prefix", True, got[:200])
        except Exception:
            print("### fw: " + fw.execute(f"ip -6 addr; ip -6 route; ls /var/lib/patronus/net/dhcp/ 2>&1; cat /var/lib/patronus/net/dhcp/dhcpcd-{isp_if}.conf 2>&1", 60)[1][-2500:], flush=True)
            print("### isp: " + isp.execute("cat /var/log/kea/kea6.log | tail -30; ip -6 route", 60)[1][-2000:], flush=True)
            m.check("lan-tracks-the-delegated-prefix", False, "no delegated prefix address on the LAN port after 180 s")
        leases = isp.execute("cat /var/log/kea/kea6.log | grep -ci 'IA_PD\\|prefix' ")[1].strip()
        m.check("isp-delegated-a-prefix", leases not in ("", "0"), f"kea log lines about PD: {leases}")
        isp.succeed(ISP_V6_STOP, timeout=60)

        m.phase("7. wizard: PPPoE WAN (user, password, MTU) against a real access concentrator")
        isp.succeed(ISP_PPPOE_START, timeout=60)
        ppp = dict(base, wan_mode="pppoe", pppoe_username=PPP_USER, pppoe_mtu=1492)
        code, r = api("POST", "/api/setup/apply", ppp)
        m.check("wizard-refuses-pppoe-without-a-password", code == 400, f"{code} {str(r)[:200]}")
        ppp["pppoe_pass" + "word"] = PPP_SECRET
        code, r = api("POST", "/api/setup/apply", ppp)
        m.check("wizard-pppoe-answers-200", code == 200, f"{code} {str(r)[:300]}")
        try:
            fw.wait_until_succeeds("ip -4 -o addr show dev pppoe0 | grep -q 'inet 100.64.0.'", 120, 3)
            m.check("pppoe-session-up", True, fw.succeed("ip -4 -o addr show dev pppoe0").strip()[:160])
        except Exception:
            print("### fw: " + fw.execute("ip addr; tail -40 /var/log/messages 2>/dev/null; ls /etc/ppp/peers; " + fw.init.status_all() + " | grep -i ppp", 60)[1][-2500:], flush=True)
            m.check("pppoe-session-up", False, "pppoe0 got no address from the access concentrator in 120 s")
        roles = fw.succeed("patronus interfaces roles 2>/dev/null")
        m.check("wan-role-moved-to-the-ppp-device", "WAN    pppoe0" in roles and isp_if not in roles, roles.strip())
        m.check("pppoe-mtu", "mtu 1492" in fw.execute("ip link show dev pppoe0")[1], fw.execute("ip link show dev pppoe0")[1].strip()[:160])
        m.check("masquerade-on-the-ppp-device", 'oifname "pppoe0"' in fw.succeed("nft list ruleset"), "nftables")

        m.phase("8. OPT interface on the spare port (patronus interfaces assign; the console-file path is proven in installed_pfsense_import)")
        out = fw.succeed(f"patronus interfaces assign --wan pppoe0 --lan {LAN} --opt {WAN} 2>&1", timeout=120)
        roles = fw.succeed("patronus interfaces roles 2>/dev/null")
        m.check("opt1-role-on-the-spare-port", f"OPT1   {WAN}" in roles and f"LAN    {LAN}" in roles and "WAN    pppoe0" in roles,
                roles.strip() + " | " + out.strip()[-200:])
        m.check("assign-kept-a-revision", "interface assignment" in fw.succeed("patronus config revisions"), "config revisions")
        fw.succeed("patronus apply --phase firewall", timeout=300)
        m.check("firewall-applies-with-an-opt-port", True, "patronus apply --phase firewall")
        isp.succeed(ISP_PPPOE_STOP, timeout=60)

    def _lease(m, cli, when):
        """The client (no address) asks for one: the pool must hand out the RESERVED address for its MAC."""
        cli.succeed("ip addr flush dev eth1; ip link set eth1 up")
        cli.wait_until_succeeds("udhcpc -i eth1 -n -q -t 3 -T 2 >/dev/null 2>&1", 150, 5)
        got = cli.succeed("ip -4 -o addr show dev eth1")
        m.check(f"client-gets-the-reserved-address-{when}", RESERVED in got, got.strip()[:200])

    return Test("installed-firstrun", nodes=[fw, cli, isp], networks=[Network("lan"), Network("isp")], run=run, timeout=7200,
                description="installed Patronus: package-owned product, wizard (DHCP WAN, readable failure), reboot persistence of DHCP/DNS "
                            "service and routes; wizard against a virtual ISP (DHCPv6-PD + LAN tracking, PPPoE), OPT port")


# a version no real kernel reaches: GRUB's version sort puts it first, so "the newest installed kernel" is this one
FAKE_KVER = "6.99.0-vmtest"


def boot_health(m, fw):
    """The installed disk boots the kernel the package manager installed last, and never sits at the menu waiting for a key.

    Found 2026-11-24 on a lab VM: no /boot in fstab, so kernel updates landed on the root fs while GRUB read the boot partition, and no hook
    rewrote grub.cfg: the machine booted its install-day kernel forever. Init-agnostic (plain files and the hook installkernel runs)."""
    fstab = fw.succeed("cat /etc/fstab")
    m.check("fstab-mounts-boot", re.search(r"^\S+\s+/boot\s+\S+", fstab, re.M) is not None, fstab.strip()[:300])
    m.check("fstab-mounts-the-esp", re.search(r"^\S+\s+/boot/efi\s+vfat", fstab, re.M) is not None, "UEFI install: ESP at /boot/efi")
    m.check("boot-is-a-mounted-partition", fw.execute("findmnt -n -o SOURCE /boot && findmnt -n -o SOURCE /boot/efi")[0] == 0, fw.execute("findmnt -n /boot")[1].strip())
    hooks = fw.succeed("for f in /etc/kernel/postinst.d/91-patronus-boot-entry /etc/kernel/postrm.d/91-patronus-boot-entry /etc/grub.d/11_patronus_unattended; do "
                       "echo \"$f $(test -x $f && echo ok || echo MISSING) $(qfile -Cq $f)\"; done")
    bad = [ln for ln in hooks.strip().splitlines() if not ln.split()[1] == "ok" or not ln.endswith(" net-firewall/patronus")]
    m.check("kernel-hooks-installed-and-package-owned", not bad, "; ".join(bad) if bad else "postinst.d, postrm.d, grub.d unattended script: net-firewall/patronus")
    m.check("installkernel-runs-etc-kernel-postinst-d", fw.execute("grep -q /etc/kernel/postinst.d /usr/sbin/installkernel")[0] == 0, "the hook directory the installed hooks live in")
    kver = fw.succeed("uname -r").strip()
    m.check("grub-cfg-names-the-running-kernel", f"vmlinuz-{kver}" in fw.succeed("cat /boot/grub/grub.cfg"), kver)
    # a kernel install, as installkernel does it: files in /boot, then every /etc/kernel/postinst.d hook with the version
    fw.succeed(f"cp /boot/vmlinuz-{kver} /boot/vmlinuz-{FAKE_KVER} && cp /boot/initramfs-{kver}.img /boot/initramfs-{FAKE_KVER}.img")
    fw.succeed(f"/etc/kernel/postinst.d/91-patronus-boot-entry {FAKE_KVER}", timeout=180)
    cfg = fw.succeed("cat /boot/grub/grub.cfg")
    entries = re.findall(r"^menuentry '([^']*)'.*?\n\s*linux\s+\S*vmlinuz-(\S+)", cfg, re.M | re.S)
    m.check("grub-cfg-names-the-newest-installed-kernel-first", bool(entries) and entries[0][1] == FAKE_KVER and any(k == kver for _, k in entries[1:]),
            f"entries (newest first): {[k for _, k in entries][:4]}")
    # the menu counts down and falls back instead of waiting for a key
    t = re.search(r"^\s*set timeout=(\S+)", cfg, re.M)
    m.check("menu-has-a-countdown", t is not None and t.group(1).isdigit() and int(t.group(1)) > 0, f"set timeout={t.group(1) if t else None}")
    m.check("menu-falls-back-and-restarts-never-waits", "set fallback=" in cfg and "patronus-retry" in cfg and "reboot" in cfg, "fallback chain + retry/restart entry present")
    # a kernel removal takes it out again
    fw.succeed(f"rm -f /boot/vmlinuz-{FAKE_KVER} /boot/initramfs-{FAKE_KVER}.img && /etc/kernel/postrm.d/91-patronus-boot-entry {FAKE_KVER}", timeout=180)
    m.check("kernel-removal-rewrites-the-menu", FAKE_KVER not in fw.succeed("cat /boot/grub/grub.cfg"), "removed kernel is gone from grub.cfg")


def boot_apply_health(m, fw, when, full=True):
    """The boot-time apply must have STARTED (a failed one left no ruleset and ip_forward 0), and its own output is kept in /var/log/patronus/."""
    fw.wait_until_succeeds(fw.init.is_active("patronus-firewall"), 120, 3)
    m.check(f"patronus-firewall-started-{when}", True, fw.init.name)
    if full:     # the first boot of a fresh install has its default ruleset seeded by this very apply: proven after the reboot, with the wizard's config
        _ruleset_and_forwarding(m, fw, when)
    if fw.init.name == "openrc":
        log = fw.execute("cat /var/log/patronus/boot-apply.log")[1]
        m.check(f"boot-apply-output-is-logged-{when}", "boot apply ok" in log, log.strip()[-400:])


def _ruleset_and_forwarding(m, fw, when):
    ok = fw.execute("nft list ruleset | grep -q 'table '")[0] == 0
    m.check(f"boot-apply-left-a-ruleset-{when}", ok, fw.execute("nft list tables")[1].strip()[:200])
    m.check(f"boot-apply-enabled-ip-forward-{when}", fw.succeed("cat /proc/sys/net/ipv4/ip_forward").strip() == "1", "net.ipv4.ip_forward")


def _write_tmp(text):
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    f.write(text)
    f.close()
    return f.name
