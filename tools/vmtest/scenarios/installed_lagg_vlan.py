"""Installer-made LAGG + VLANs + management network: the box is reachable on the right network at its FIRST boot, nobody at the console.

fw     = Patronus installed by the unattended installer from an answer file that asks for
           bond0 = enp0s1 + enp0s2, 802.3ad (LACP fast, hash layer2+3)
           WAN  = bond0.100, DHCP          (fake ISP on VLAN 100)
           LAN  = bond0.30, 192.168.30.1/24
           MGMT = bond0.20, 10.20.0.1/24   (SSH + web UI only here)
         plus a third NIC (enp0s3, QEMU user net, unassigned) that carries the installer's internet and a host forward to its port 443.
switch = Alpine live with the partner side: eth1 + eth2 in a Linux bond (mode 802.3ad) enslaved to a VLAN-aware bridge (vlan_filtering)
         that trunks VLANs 20/30/100 to the firewall; the switch itself has an address on each VLAN and runs a DHCP server (dnsmasq) on
         VLAN 100 = the fake ISP.

What it proves on the SHIPPED image (both inits run this same script; it never names a service manager):
 1. the answer file is accepted and the installer writes the bonds / VLANs / roles / addressing into the first-boot bootstrap file
 2. first boot, no console: /proc/net/bonding/bond0 is 802.3ad with BOTH members in ONE aggregator whose partner is the switch's bond
 3. WAN over VLAN 100 gets its lease from the fake ISP (and the default route through it)
 4. https://10.20.0.1/ answers (443) and http://10.20.0.1/ redirects to https ON the management VLAN; SSH answers there
 5. SSH and the web UI do NOT answer on the LAN VLAN, the WAN VLAN or the unassigned port (management network only)
 6. cutting one bond member keeps the management network reachable (LACP fails over), and bringing it back rejoins the aggregator

    python3 -m vmtest run scenarios/installed_lagg_vlan.py --arg iso=patronus-...iso
"""
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vmtest import Disk, Network, Nic, NodeSpec, Test, cache  # noqa: E402
from vmtest.recipes import PROJECTS, PW, answer_toml, unattended_install  # noqa: E402

ALPINE = ("https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.4-x86_64.iso",
          "157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f")
ALPINE_REPO = "https://dl-cdn.alpinelinux.org/alpine/v3.24/main"

# every operational value of the scenario in one place (nothing buried in the steps)
M1, M2, UPLINK = "enp0s1", "enp0s2", "enp0s3"          # fw ports: the two bond members, then the QEMU user NIC
BOND, HASH, LACP_RATE = "bond0", "layer2+3", "fast"
VLAN_MGMT, VLAN_LAN, VLAN_WAN = 20, 30, 100
MGMT_IP, MGMT_SW = "10.20.0.1", "10.20.0.2"
LAN_IP, LAN_SW = "192.168.30.1", "192.168.30.2"
ISP_GW, ISP_POOL = "203.0.113.1", ("203.0.113.100", "203.0.113.150")
SW_MACS = ("52:54:00:0e:00:01", "52:54:00:0e:00:02")   # switch eth1 / eth2 (the bond takes eth1's)

NETWORK_TOML = f"""
[[network.bond]]
name = "{BOND}"
members = ["{M1}", "{M2}"]
mode = "802.3ad"
hash = "{HASH}"
lacp_rate = "{LACP_RATE}"

[network.wan]
iface = "{BOND}"
vlan = {VLAN_WAN}
mode = "dhcp"

[network.lan]
iface = "{BOND}"
vlan = {VLAN_LAN}
address = "{LAN_IP}/24"

[network.mgmt]
iface = "{BOND}"
vlan = {VLAN_MGMT}
address = "{MGMT_IP}/24"
only = true
"""

SWITCH_SH = f"""
set -e
modprobe bonding; modprobe 8021q; modprobe bridge
ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100 xmit_hash_policy layer2+3
for p in eth1 eth2; do ip link set $p down; ip link set $p master bond0; done
ip link add br0 type bridge vlan_filtering 1
ip link set bond0 master br0
for v in {VLAN_MGMT} {VLAN_LAN} {VLAN_WAN}; do bridge vlan add dev bond0 vid $v; bridge vlan add dev br0 self vid $v; done
ip link set bond0 up; ip link set br0 up
ip link add link br0 name br0.{VLAN_MGMT} type vlan id {VLAN_MGMT}; ip addr add {MGMT_SW}/24 dev br0.{VLAN_MGMT}
ip link add link br0 name br0.{VLAN_LAN} type vlan id {VLAN_LAN}; ip addr add {LAN_SW}/24 dev br0.{VLAN_LAN}
ip link add link br0 name br0.{VLAN_WAN} type vlan id {VLAN_WAN}; ip addr add {ISP_GW}/24 dev br0.{VLAN_WAN}
for d in br0.{VLAN_MGMT} br0.{VLAN_LAN} br0.{VLAN_WAN}; do ip link set $d up; done
dnsmasq --interface=br0.{VLAN_WAN} --bind-interfaces --port=0 --dhcp-range={ISP_POOL[0]},{ISP_POOL[1]},255.255.255.0,1h \
  --dhcp-option=option:router,{ISP_GW} --dhcp-leasefile=/tmp/isp.leases --log-dhcp --log-facility=/tmp/isp.log
echo switch-ready
"""


def make_answers_lagg(work):
    """-> (answers.img, ssh private key): the standard vmtest answer file with this scenario's [network] tables."""
    key = os.path.join(work, "key")
    subprocess.check_call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vmtest", "-f", key])
    pwhash = subprocess.check_output(["openssl", "passwd", "-6", "-salt", "vmtest01", PW]).decode().strip()
    base = answer_toml("patronus", open(key + ".pub").read().strip(), pwhash)
    text = base[:base.index("[network.wan]")] + NETWORK_TOML
    d = os.path.join(work, "a")
    os.mkdir(d)
    open(f"{d}/answer.toml", "w").write(text)
    img = os.path.join(work, "answers.img")
    subprocess.check_call(["mke2fs", "-q", "-t", "ext4", "-L", "PATRONUS-ANSWERS", "-d", d, img, "8M"])
    return img, key


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers_lagg(tempfile.mkdtemp(prefix="vmt-lagg-"))
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8", boot_timeout=420,
                  nics=[Nic("l1"), Nic("l2"), Nic("user", forwards={"web": 443})])
    sw = NodeSpec(name="switch", mem=768, cpus=1, iso=args.get("switch_iso") or cache.fetch(*ALPINE), disks=[Disk("1G")],
                  nics=[Nic("user", forwards={}), Nic("l1", mac=SW_MACS[0]), Nic("l2", mac=SW_MACS[1])])

    def run(m):
        fw, sw = m.fw, m.switch

        def sw_http(url, extra=""):
            return sw.execute(f"curl -sk -m 8 -o /dev/null -w '%{{http_code}} %{{redirect_url}}' {extra} {url}", 30)[1].strip()

        def sw_tcp(ip, port):
            """True when the TCP port accepts a connection from the switch (OpenBSD nc: connect only, no data)."""
            return sw.execute(f"nc -z -w 4 {ip} {port}", 20)[0] == 0

        m.phase("install the firewall from the answer file (bond + VLANs + management network)")
        unattended_install(m, fw)

        m.phase("the switch: LACP partner + VLAN-aware bridge + fake ISP on VLAN 100")
        sw.start()
        sw.wait_for_shell()
        sw.succeed("ip link set eth0 up && udhcpc -i eth0 -n -q -t 5 >/dev/null 2>&1", timeout=90)
        sw.succeed(f"echo {ALPINE_REPO} >> /etc/apk/repositories && apk update -q && apk add -q dnsmasq curl netcat-openbsd", timeout=300)
        sw.succeed("cat > /tmp/switch.sh <<'EOF'\n" + SWITCH_SH + "\nEOF\nsh /tmp/switch.sh", timeout=120)
        sw_mac = sw.succeed("cat /sys/class/net/bond0/address").strip().lower()
        m.check("switch-bond-is-802.3ad", "802.3ad" in sw.succeed("cat /proc/net/bonding/bond0"), sw_mac)

        m.phase("first boot of the installed disk: nobody touches the console")
        fw.start()
        m.check("fw-boots-to-login", fw.q.expect(r"login:", fw.T(420)), "")
        # the proof is from the network side FIRST (the switch on the management VLAN), before any console command runs on the box
        sw.wait_until_succeeds(f"curl -sk -m 5 -o /dev/null https://{MGMT_IP}/login", 420, 5)
        m.check("web-ui-answers-on-the-management-vlan-at-first-boot", True, f"https://{MGMT_IP}/login from {MGMT_SW} (VLAN {VLAN_MGMT})")
        code = sw_http(f"https://{MGMT_IP}/login")
        m.check("https-443-on-mgmt-is-200", code.startswith("200"), code)
        code = sw_http(f"http://{MGMT_IP}/some/page")
        m.check("http-80-on-mgmt-redirects-to-https", code.startswith("308") and f"https://{MGMT_IP}/some/page" in code, code)
        banner = sw.execute(f"echo | nc -w 4 {MGMT_IP} 22 | head -1", 20)[1].strip()
        m.check("ssh-answers-on-the-management-vlan", banner.startswith("SSH-2.0"), banner[:80])

        m.phase("the bond: 802.3ad, both members in one aggregator, partner = the switch")
        fw.wait_for_shell()
        bonding = fw.succeed(f"cat /proc/net/bonding/{BOND}")
        m.check("fw-bond-mode-is-802.3ad", "IEEE 802.3ad Dynamic link aggregation" in bonding, bonding.splitlines()[1] if len(bonding.splitlines()) > 1 else "")
        m.check("fw-bond-has-both-members", f"Slave Interface: {M1}" in bonding and f"Slave Interface: {M2}" in bonding, f"{M1} + {M2}")
        partners = set(x.lower() for x in re.findall(r"Partner Mac Address:\s*(\S+)", bonding))
        m.check("lacp-partner-is-the-switch", sw_mac in partners and "00:00:00:00:00:00" not in partners, f"partner {sorted(partners)} switch {sw_mac}")
        active = re.search(r"Active Aggregator Info:\s*\n\s*Aggregator ID: (\d+)", bonding)
        slave_aggs = re.findall(r"Slave Interface: \S+.*?Aggregator ID: (\d+)", bonding, re.S)
        m.check("both-members-in-the-active-aggregator", len(slave_aggs) == 2 and len(set(slave_aggs)) == 1 and (active is None or active.group(1) == slave_aggs[0]),
                f"active {active.group(1) if active else '?'} members {slave_aggs}")
        m.check("lacp-rate-and-hash-from-the-answer-file", f"Transmit Hash Policy: {HASH}" in bonding and "LACP rate: fast" in bonding,
                "; ".join(l.strip() for l in bonding.splitlines() if "Hash" in l or "LACP rate" in l))
        boot = fw.succeed("cat /etc/patronus/patronus.toml")
        m.check("bootstrap-file-carries-the-install-choices", f'mgmt_interface = "{BOND}.{VLAN_MGMT}"' in boot and "[[network.bond]]" in boot
                and f'wan_interface = "{BOND}.{VLAN_WAN}"' in boot, "[network] roles + [[network.bond]] + [[network.vlan]] + [firstboot]")

        m.phase("WAN over VLAN 100: lease from the fake ISP")
        fw.wait_until_succeeds(f"ip -4 -o addr show dev {BOND}.{VLAN_WAN} | grep -q 'inet 203\\.0\\.113\\.'", 180, 3)
        wan = fw.succeed(f"ip -4 -o addr show dev {BOND}.{VLAN_WAN}").strip()
        m.check("wan-vlan-has-a-lease-from-the-fake-isp", re.search(r"inet 203\.0\.113\.(1[0-4]\d|150)/24", wan) is not None, wan[:160])
        leases = sw.succeed("cat /tmp/isp.leases").strip()
        m.check("fake-isp-handed-out-that-lease", leases != "" and wan.split()[3].split("/")[0] in leases, leases[:160])
        fw.wait_until_succeeds(f"ip -4 route show default | grep -q 'via {ISP_GW} dev {BOND}.{VLAN_WAN}'", 120, 3)
        m.check("default-route-via-the-isp-on-the-vlan", True, fw.succeed("ip -4 route show default").strip()[:160])
        fw_wan = wan.split()[3].split("/")[0]

        m.phase("SSH + web UI only on the management network")
        lan = fw.succeed(f"ip -4 -o addr show dev {BOND}.{VLAN_LAN}")
        m.check("lan-vlan-has-its-static-address", f"{LAN_IP}/24" in lan, lan.strip()[:120])
        sw.succeed(f"ping -c 2 -W 2 {LAN_IP}")      # the LAN itself works (L3 reachable) ...
        m.check("web-ui-closed-on-the-lan-vlan", not sw_tcp(LAN_IP, 443) and not sw_tcp(LAN_IP, 80), f"{LAN_IP}:443/80 from {LAN_SW}")
        m.check("ssh-closed-on-the-lan-vlan", not sw_tcp(LAN_IP, 22), f"{LAN_IP}:22")
        m.check("web-ui-and-ssh-closed-on-the-wan-vlan", not sw_tcp(fw_wan, 443) and not sw_tcp(fw_wan, 22), f"{fw_wan} from {ISP_GW}")
        st, _ = fw.http("web", "/login", timeout=10)     # QEMU host forward -> the unassigned port enp0s3:443
        m.check("web-ui-closed-on-the-unassigned-port", st == 0, f"host forward -> {UPLINK}:443 answered {st}")
        rules = fw.succeed("nft list chain inet patronus input")
        m.check("firewall-renders-the-management-only-rule", f'iifname != "{BOND}.{VLAN_MGMT}"' in rules and "Management network only" in rules,
                next((l.strip() for l in rules.splitlines() if "Management network only" in l), "missing")[:200])

        m.phase("cut one bond member: still reachable; plug it back: it rejoins")
        fw.set_link(0, False)
        fw.wait_until_succeeds(f"grep -A2 'Slave Interface: {M1}' /proc/net/bonding/{BOND} | grep -q 'MII Status: down'", 30, 1)
        for i in range(3):
            code = sw_http(f"https://{MGMT_IP}/login")
            if code.startswith("200"):
                break
        m.check("mgmt-reachable-with-one-member-cut", code.startswith("200"), f"{M1} down -> {code}")
        fw.set_link(0, True)
        fw.wait_until_succeeds(f"grep -A2 'Slave Interface: {M1}' /proc/net/bonding/{BOND} | grep -q 'MII Status: up'", 60, 2)
        def one_aggregator():
            b = fw.succeed(f"cat /proc/net/bonding/{BOND}")
            ids = re.findall(r"Slave Interface: \S+.*?Aggregator ID: (\d+)", b, re.S)
            active = re.search(r"Active Aggregator Info:\s*\n\s*Aggregator ID: (\d+)", b)
            return len(ids) == 2 and len(set(ids)) == 1 and (active is None or active.group(1) == ids[0])
        fw.wait_until(one_aggregator, 90, 3, f"{M1} back in the active aggregator")
        m.check("member-rejoins-the-aggregator", True, f"{M1} back up")
        code = sw_http(f"https://{MGMT_IP}/login")
        m.check("mgmt-reachable-after-the-member-returns", code.startswith("200"), code)
        fw.screenshot("fw-lagg-vlan")

    return Test("installed-lagg-vlan", nodes=[fw, sw], networks=[Network("l1"), Network("l2")], run=run, timeout=5400,
                description="installed Patronus: answer-file bond (802.3ad) + VLAN WAN/LAN/management: reachable on the management VLAN at first boot, "
                            "nowhere else; LACP partner + member failover")
