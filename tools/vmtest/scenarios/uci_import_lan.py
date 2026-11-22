"""Patronus OpenWrt migration on real VMs: the installed firewall imports an x86 OpenWrt router's configuration
(`patronus import-uci`, the netlab fixture ci/netlab/fixtures/uci-router) and a LAN client VM proves it works.

 fw  = Patronus (installed from the ISO by the unattended installer), WAN = QEMU user net, LAN = hub `lan`
 cli = Alpine live (OpenRC), LAN = hub `lan`, gets everything from the imported configuration

Checks (two real kernels, the shipped image and its own init system, openrc or systemd):
 - import-uci dry run and import succeed, the report shows no key, a second import adds nothing
 - the client gets its static lease (192.168.50.21) by DHCP from the imported pool
 - DNS on the router: the static lease's name, `domain` host records and the router name in the local domain
 - IPv6: the client gets an address from the imported ULA prefix (RA from the router)
 - WireGuard: wg0 is up with the imported key and port (its public key matches the old one)
 - firewall: the imported REJECT default answers with a reset instead of silence; MSS clamping is in place
 - all of it survives a power cut (cold boot from the store)
    python3 -m vmtest run scenarios/uci_import_lan.py --arg iso=patronus-...iso
"""
import os
import shutil
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vmtest import Disk, Network, Nic, NodeSpec, Test, cache  # noqa: E402
from vmtest.recipes import PROJECTS, PW, make_answers, unattended_install  # noqa: E402

ALPINE = ("https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.4-x86_64.iso",
          "157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f")
FW_LAN_MAC, CLI_LAN_MAC = "52:54:00:01:00:01", "52:54:00:02:00:01"
SRV_PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="   # test key of the fixture, never a real one
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
FIXTURE = os.path.join(ROOT, "ci", "netlab", "fixtures", "uci-router")


def fixture_tarball():
    """The netlab fixture adapted to the VM: WAN by DHCP (QEMU user net), the static lease on the client's MAC,
    the peer's placeholder key is replaced on the firewall (wg pubkey of a test key)."""
    work = tempfile.mkdtemp(prefix="vmt-uci-")
    d = os.path.join(work, "uci")
    shutil.copytree(FIXTURE, d)
    net = os.path.join(d, "etc", "config", "network")
    s = open(net).read()
    wan = s.index("config interface 'wan'")
    end = s.index("\nconfig ", wan + 1)
    s = s[:wan] + "config interface 'wan'\n\toption device 'eth1'\n\toption proto 'dhcp'\n" + s[end:]
    open(net, "w").write(s)
    dhcp = os.path.join(d, "etc", "config", "dhcp")
    open(dhcp, "w").write(open(dhcp).read().replace("02:00:00:00:00:21", CLI_LAN_MAC))
    tgz = os.path.join(work, "uci.tgz")
    with tarfile.open(tgz, "w:gz") as t:
        t.add(d, arcname="uci")
    return tgz


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers("patronus")
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8", boot_timeout=420,
                  nics=[Nic("user", forwards={}), Nic("lan", mac=FW_LAN_MAC)])
    cli = NodeSpec(name="cli", mem=512, cpus=1, iso=args.get("client_iso") or cache.fetch(*ALPINE), disks=[Disk("1G")],
                   nics=[Nic("user", forwards={}), Nic("lan", mac=CLI_LAN_MAC)])

    def run(m):
        RTR = "192.168.50.1"

        m.phase("install the firewall, boot the client")
        unattended_install(m, m.fw)
        m.cli.start()
        m.cli.wait_for_shell()
        m.cli.succeed("ip link set eth1 up", "sysctl -w net.ipv6.conf.eth1.accept_ra=2 net.ipv6.conf.eth1.autoconf=1")

        m.phase("firewall first boot")
        m.fw.start()
        m.check("fw-boots-to-login", m.fw.q.expect(r"login:", m.fw.T(420)), "")
        m.fw.wait_for_shell()
        m.fw.wait_for_unit(P["svc"], 300)
        m.check(f"{P['svc']}-active", True, m.fw.init.name)

        m.phase("import the OpenWrt configuration")
        devs = m.fw.succeed("for d in /sys/class/net/*; do n=${d##*/}; if [ -e $d/device ]; then echo $n $(cat $d/address); fi; done").split("\n")
        lan = next(l.split()[0] for l in devs if FW_LAN_MAC in l)
        wan = next(l.split()[0] for l in devs if l.strip() and FW_LAN_MAC not in l)
        m.fw.put_file(fixture_tarball(), "/root/uci.tgz", "600")
        m.fw.succeed("rm -rf /root/uci && tar xzf /root/uci.tgz -C /root")
        m.fw.succeed("k=$(printf %s cEhzR3xbVwCJk9i0e6dbHUeW8wy9vEaRbNk+9bk5TlE= | wg pubkey) && "
                     "sed -i \"s|PLACEHOLDER-SITE-B-PUB|$k|\" /root/uci/etc/config/network")
        maps = f"--map lan={lan} --map wan={wan} --map vpn=wg0"
        dry = m.fw.succeed(f"patronus import-uci /root/uci {maps} --dry-run 2>&1", timeout=120)
        rep = m.fw.succeed(f"patronus import-uci /root/uci {maps} 2>&1", timeout=120)
        leak = [w for w in (SRV_PRIV, "private_key", "preshared_key") if w in dry or w in rep]
        m.check("import-report-has-no-key", not leak, f"{len(rep.splitlines())} report lines, lan={lan} wan={wan}")
        print("--- import report (dhcp/pool/lease/lan lines):\n" + "\n".join(
            l for l in (dry + "\n" + rep).splitlines() if any(w in l.lower() for w in ("dhcp", "pool", "lease", "lan", "unmapped"))), flush=True)
        again = m.fw.succeed(f"patronus import-uci /root/uci {maps} 2>&1", timeout=120)
        peers = m.fw.succeed("wg show wg0 peers 2>/dev/null | wc -l; true").strip()
        m.check("second-import-adds-nothing", "wireguard wg0: already present" in again, f"peers on wg0 before apply: {peers or 'n/a'}")
        m.fw.succeed("patronus apply 2>&1", timeout=300)
        m.check("apply-imported-store", True, "")

        def lan_checks(tag):
            m.cli.succeed("killall udhcpc 2>/dev/null; ip -4 addr flush dev eth1; true")
            try:
                m.cli.wait_until_succeeds("udhcpc -i eth1 -n -q -t 5 -T 2 -s /usr/share/udhcpc/default.script", 120, 3)
            except Exception:
                # no lease: print what the firewall's DHCP server saw, so the red run says why (addresses, listeners,
                # input rules, daemon logs) instead of only "no lease"
                for what, cmd in (("addresses", "ip -br addr; ip -br link"),
                                  ("udp listeners", "ss -lunp"),
                                  ("input rules", "nft list chain inet patronus input 2>&1 | head -60"),  # vmtest:init-ok
                                  ("dhcp daemons", "rc-status 2>/dev/null | grep -i -E 'kea|dnsmasq|dhcp'; systemctl --no-pager status kea-dhcp4 dnsmasq 2>&1 | head -40"),  # vmtest:init-ok (diagnostics must try both inits)
                                  ("dhcp logs", "journalctl --no-pager -n 60 -u kea-dhcp4 -u dnsmasq -u patronus-web 2>&1 | tail -80; ls /etc/kea /etc/dnsmasq.d 2>&1; cat /etc/kea/kea-dhcp4.conf 2>&1 | head -60"),  # vmtest:init-ok
                                  ("store", "patronus apply 2>&1 | tail -30")):
                    try:
                        _rc, out = m.fw.execute(cmd, 60)
                    except Exception as ex:  # diagnostics must never hide the real failure
                        out = f"(could not run: {ex})"
                    print(f"--- fw {what}:\n{out}", flush=True)
                raise
            ip4 = m.cli.succeed("ip -4 -o addr show dev eth1")
            m.check(f"{tag}:static-lease", "192.168.50.21/" in ip4, ip4.strip())
            for name, want in (("nas.home.example", "192.168.50.21"), ("printer.home.example", "192.168.50.22"),
                               ("router.home.example", RTR)):
                out = m.cli.wait_until_succeeds(f"nslookup {name} {RTR} | grep -A3 '^Name' | grep {want}", 60, 2)
                m.check(f"{tag}:dns:{name}", want in out, want)
            ip6 = m.cli.wait_until_succeeds("ip -6 -o addr show dev eth1 scope global | grep fd12:3456:789a:", 120, 3)
            m.check(f"{tag}:ula-from-ra", True, ip6.strip().split()[3])
            pub = m.fw.succeed("wg show wg0 public-key").strip()
            want = m.fw.succeed(f"printf %s '{SRV_PRIV}' | wg pubkey").strip()
            port = m.fw.succeed("wg show wg0 listen-port").strip()
            m.check(f"{tag}:wireguard-kept-key-and-port", pub == want and port == "51820", port)
            # REJECT: a closed port on the router answers at once (reset) instead of a timeout
            rc, o = m.cli.execute(f"timeout 5 nc -z -w 4 {RTR} 7; echo rc=$?", 30)
            m.check(f"{tag}:reject-not-drop", "rc=1" in o, o.strip().splitlines()[-1] if o.strip() else "")
            nft = m.fw.succeed("nft list ruleset")
            m.check(f"{tag}:mss-clamp", "maxseg size set rt mtu" in nft, "")

        m.phase("the LAN client on the imported configuration")
        lan_checks("import")

        m.phase("power cut: the imported configuration comes back from the store")
        m.fw.crash()
        m.fw.start()
        m.check("fw-boots-after-power-cut", m.fw.q.expect(r"login:", m.fw.T(420)), "")
        m.fw.wait_for_shell()
        m.fw.wait_for_unit(P["svc"], 300)
        m.fw.wait_until_succeeds("wg show wg0 listen-port", 180, 3)
        lan_checks("cold-boot")

    return Test("uci-import-lan", nodes=[fw, cli], networks=[Network("lan")], run=run, timeout=5400,
                description="Patronus firewall VM imports an OpenWrt configuration; a LAN client VM uses DHCP/DNS/IPv6 from it")
