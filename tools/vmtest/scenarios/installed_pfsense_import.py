"""Installed Patronus image: import a pfSense / OPNsense config.xml (init-agnostic: OpenRC and systemd use the same script).

The config.xml is written by this test (no Netgate/Deciso file is committed): WAN + LAN + an OPT port with a VLAN on it, an alias,
filter rules, a port forward, a DHCP reservation, a DNS host override, and one section Patronus has no equivalent for.

 1. `patronus import pfsense FILE --plan` prints the plan (what maps, what does not, in plain words) and writes NOTHING
 2. the web API plan (System > Import: POST /api/system/import/pfsense/plan) says the same; the unmappable section is named
 3. the web API apply writes + applies it in one step (a configuration revision is kept first): kernel state = the imported
    addresses on the OPT port and its VLAN, the rules / port forward / alias in nftables, the reservation + host override in the store
 4. everything is still there after a reboot

    python3 -m vmtest run scenarios/installed_pfsense_import.py --arg iso=patronus-...iso
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vmtest import Disk, Network, Nic, NodeSpec, Test  # noqa: E402
from vmtest.recipes import PROJECTS, PW, make_answers, unattended_install  # noqa: E402

# every operational value of the scenario in one place
LAN_IP = "10.77.0.1"
OPT_MAC, OPT_IP, VLAN_TAG, VLAN_IP = "52:54:00:01:00:03", "10.66.0.1", 30, "10.30.0.1"
FWD_PORT, FWD_TARGET, FWD_LOCAL = 8080, "10.77.0.50", 80
RES_MAC, RES_IP = "52:54:00:02:00:09", "10.77.0.51"
DNS_HOST, DNS_DOMAIN, DNS_IP = "nas", "example.lan", "10.77.0.60"
CFG = "/root/config.xml"

CONFIG_XML = f"""<?xml version="1.0"?>
<pfsense>
  <version>23.3</version>
  <system><hostname>fw-imported</hostname><domain>{DNS_DOMAIN}</domain><timezone>Europe/Amsterdam</timezone></system>
  <interfaces>
    <wan><enable/><if>em0</if><descr>WAN</descr><ipaddr>dhcp</ipaddr></wan>
    <lan><enable/><if>em1</if><descr>LAN</descr><ipaddr>{LAN_IP}</ipaddr><subnet>24</subnet></lan>
    <opt1><enable/><if>em2</if><descr>LAB</descr><ipaddr>{OPT_IP}</ipaddr><subnet>24</subnet></opt1>
    <opt2><enable/><if>em2.{VLAN_TAG}</if><descr>IOT</descr><ipaddr>{VLAN_IP}</ipaddr><subnet>24</subnet></opt2>
  </interfaces>
  <vlans><vlan><if>em2</if><tag>{VLAN_TAG}</tag><vlanif>em2.{VLAN_TAG}</vlanif><descr>IoT VLAN</descr></vlan></vlans>
  <aliases><alias><name>web_ports</name><type>port</type><address>80 443</address></alias></aliases>
  <filter>
    <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>lan</network></source><destination><any/><port>web_ports</port></destination><descr>LAN web out</descr></rule>
    <rule><type>block</type><interface>opt2</interface><ipprotocol>inet</ipprotocol><protocol>tcp/udp</protocol>
      <source><network>opt2</network></source><destination><network>lan</network></destination><descr>IoT not to LAN</descr></rule>
  </filter>
  <nat>
    <outbound><mode>automatic</mode></outbound>
    <rule><interface>wan</interface><protocol>tcp</protocol><source><any/></source>
      <destination><network>wanip</network><port>{FWD_PORT}</port></destination>
      <target>{FWD_TARGET}</target><local-port>{FWD_LOCAL}</local-port><descr>web to server</descr></rule>
  </nat>
  <dhcpd><lan><enable/><range><from>10.77.0.100</from><to>10.77.0.199</to></range>
    <staticmap><mac>{RES_MAC}</mac><ipaddr>{RES_IP}</ipaddr><hostname>printer</hostname></staticmap></lan></dhcpd>
  <unbound><enable/><hosts><host>{DNS_HOST}</host><domain>{DNS_DOMAIN}</domain><ip>{DNS_IP}</ip></hosts></unbound>
  <captiveportal><guests><zone>guests</zone></guests></captiveportal>
</pfsense>
"""

# runs inside the guest: log in once (cookie jar), then METHOD PATH (JSON | @file) BASE USER PASSWORD -> "HTTP <code>\\n<body>"
API_PY = r'''
import json, ssl, sys, urllib.request, urllib.error, http.cookiejar
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.MozillaCookieJar("/tmp/fwapi.jar")
try: jar.load(ignore_discard=True)
except OSError: pass
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=ctx))
def call(m, p, body=None, ctype="application/json"):
    r = urllib.request.Request(sys.argv[4] + p, method=m, data=body, headers={"content-type": ctype})
    try:
        x = op.open(r, timeout=300); return x.status, x.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
m, p, a = sys.argv[1], sys.argv[2], sys.argv[3]
if a == "-": body, ct = None, "application/json"
elif a.startswith("@"): body, ct = open(a[1:], "rb").read(), "application/xml"
else: body, ct = a.encode(), "application/json"
s, b = call(m, p, body, ct)
if s == 401:
    ls, lb = call("POST", "/api/auth/login", json.dumps({"username": sys.argv[5], "password": sys.argv[6]}).encode())
    if ls != 200: print("HTTP", ls); print(lb); sys.exit(0)
    jar.save(ignore_discard=True); s, b = call(m, p, body, ct)
print("HTTP", s); print(b)
'''


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers("patronus")
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8", boot_timeout=420,
                  nics=[Nic("user", forwards={}), Nic("lan", mac="52:54:00:01:00:01"), Nic("opt", mac=OPT_MAC)])

    def run(m):
        fw = m.fw

        def api(method, path, body="-", timeout=300):
            arg = body if body == "-" or body.startswith("@") else "'" + json.dumps(body).replace("'", "'\\''") + "'"
            out = fw.succeed(f"python3 /tmp/fwapi.py {method} '{path}' {arg} https://127.0.0.1:{P['port']} {P['web_user']} '{PW}'", timeout=timeout)
            head, _, rest = out.strip().partition("\n")
            code = int(head.split()[1])
            try:
                return code, json.loads(rest)
            except ValueError:
                return code, rest

        def dev_of(mac):
            return fw.succeed(f"ip -o link | awk -F': ' '/{mac}/ {{print $2}}' | cut -d@ -f1").strip()

        m.phase("install, first boot")
        unattended_install(m, fw)
        fw.start()
        m.check("fw-boots-to-login", fw.q.expect(r"login:", fw.T(420)), "")
        fw.wait_for_shell()
        fw.wait_for_unit(P["svc"], 300)
        fw.wait_until_succeeds(f"timeout 3 bash -c ': </dev/tcp/127.0.0.1/{P['port']}'", 120, 3)
        wan, lan, opt = dev_of("52:54:00:12:34:56") or "", dev_of("52:54:00:01:00:01"), dev_of(OPT_MAC)
        if not wan:
            wan = fw.succeed("ip -4 route show default | awk '{print $5; exit}'").strip()
        m.check("three-ports-found", bool(wan and lan and opt) and len({wan, lan, opt}) == 3, f"wan={wan} lan={lan} opt={opt}")
        fw.put_file(_write_tmp(CONFIG_XML, ".xml"), CFG)
        fw.put_file(_write_tmp(API_PY, ".py"), "/tmp/fwapi.py")

        m.phase("0. OPT interface: roles set the way the console menu sets them (patronus.toml + interfaces assign --from-bootstrap)")
        fw.succeed(f"sed -i '/^opt_interfaces *=/d; s/^lan_interface *=.*/&\\nopt_interfaces = [\"{opt}\"]/' /etc/patronus/patronus.toml")
        out = fw.succeed("patronus interfaces assign --from-bootstrap", timeout=120)
        roles = _roles(fw)
        m.check("opt1-role-assigned", f"OPT1   {opt}" in roles and f"WAN    {wan}" in roles, roles.strip() + " | " + out.strip())
        bad = fw.execute("patronus interfaces assign --wan nosuch0 2>&1")
        m.check("assign-refuses-a-port-that-does-not-exist", bad[0] != 0 and "does not exist" in bad[1], bad[1].strip()[-200:])
        m.check("refused-assign-changed-nothing", _roles(fw) == roles, "roles unchanged")

        m.phase("1. CLI plan: printed, nothing written")
        fw.succeed("patronus config export > /root/export-before.json")
        revs_before = fw.succeed("patronus config revisions | wc -l").strip()
        plan = fw.succeed(f"patronus import pfsense {CFG} --plan --map em0={wan} --map em1={lan} --map em2={opt}", timeout=120)
        m.check("cli-plan-names-the-rules", "LAN web out" in plan and "IoT not to LAN" in plan, plan[-600:])
        m.check("cli-plan-names-the-vlan-on-the-mapped-port", f"{opt}.{VLAN_TAG}" in plan, plan[-600:])
        m.check("cli-plan-lists-what-does-not-map", "captiveportal" in plan.lower(), plan[-600:])
        _nothing_imported(m, fw, revs_before, "cli-plan")

        m.phase("2. web plan (System > Import), no port names given: the old ports follow this box's WAN / LAN / OPT1")
        code, r = api("POST", "/api/system/import/pfsense/plan", "@" + CFG)
        text = r.get("plan", "") if isinstance(r, dict) else str(r)
        m.check("web-plan-200", code == 200 and "LAN web out" in text, f"{code} {text[:300]}")
        m.check("web-plan-maps-ports-by-role", all(f"port matched by role: {o} -> {n}" in text for o, n in (("em0", wan), ("em1", lan), ("em2", opt))),
                "\n".join(l for l in text.splitlines() if "matched by role" in l))
        m.check("web-plan-names-the-unmappable-section", "captiveportal" in text.lower(), text[-400:])
        code, r = api("POST", "/api/system/import/pfsense/plan", "@/etc/hostname")
        m.check("web-plan-refuses-a-file-that-is-not-config-xml", code == 400, f"{code} {str(r)[:200]}")
        _nothing_imported(m, fw, revs_before, "web-plan")

        m.phase("3. web apply: written + applied, revision kept")
        code, r = api("POST", "/api/system/import/pfsense/apply", "@" + CFG, timeout=600)
        m.check("web-apply-200", code == 200 and isinstance(r, dict) and r.get("ok") is True, f"{code} {str(r)[:400]}")
        revs = fw.succeed("patronus config revisions")
        m.check("revision-kept-before-the-import", "import" in revs.lower(), revs[:400])
        _kernel_state(m, fw, lan, opt, "after-import")
        export = fw.succeed("patronus config export")
        m.check("reservation-in-the-store", RES_MAC in export.lower() and RES_IP in export, "dhcp static map")
        m.check("dns-host-override-in-the-store", DNS_IP in export and DNS_HOST in export, "unbound host override")

        m.phase("4. reboot: everything comes back")
        fw.succeed("sync")
        fw.reboot(420)
        fw.wait_for_unit(P["svc"], 300)
        fw.wait_until_succeeds(f"ip -4 addr show dev {opt}.{VLAN_TAG} | grep -q {VLAN_IP}/", 240, 3)
        _kernel_state(m, fw, lan, opt, "after-reboot")
        fw.screenshot("fw-after-import-reboot")

    return Test("installed-pfsense-import", nodes=[fw], networks=[Network("lan"), Network("opt")], run=run, timeout=4200,
                description="installed Patronus: pfSense/OPNsense config.xml import (CLI plan, web plan + apply, kernel state, reboot persistence)")


def _kernel_state(m, fw, lan, opt, when):
    fw.wait_until_succeeds(f"ip -4 addr show dev {opt} | grep -q {OPT_IP}/24", 180, 3)
    m.check(f"opt-port-has-the-imported-address-{when}", True, fw.succeed(f"ip -4 -br addr show dev {opt}").strip())
    vl = fw.execute(f"ip -d -4 addr show dev {opt}.{VLAN_TAG}")[1]
    m.check(f"vlan-on-the-opt-port-{when}", f"vlan protocol 802.1Q id {VLAN_TAG}" in vl and f"{VLAN_IP}/24" in vl, vl.strip()[:300])
    m.check(f"lan-address-kept-{when}", f"{LAN_IP}/24" in fw.succeed(f"ip -4 -br addr show dev {lan}"), lan)
    nft = fw.succeed("nft list ruleset")
    m.check(f"alias-set-loaded-{when}", "elements = { 80, 443 }" in nft, "web_ports")
    m.check(f"imported-rules-loaded-{when}", "LAN web out" in nft and "IoT not to LAN" in nft, "rule comments")
    m.check(f"port-forward-loaded-{when}", f"dnat" in nft and f"{FWD_TARGET}:{FWD_LOCAL}" in nft and f"dport {FWD_PORT}" in nft,
            "\n".join(l for l in nft.splitlines() if "dnat" in l)[:300])


def _nothing_imported(m, fw, revs_before, what):
    """nothing of the config.xml reached the store: no rule, alias, VLAN, reservation or host override, no new revision
    (other store rows may change meanwhile: the services write their own state)"""
    exp = fw.succeed("patronus config export")
    found = [s for s in ("LAN web out", "IoT not to LAN", "web_ports", f".{VLAN_TAG}\"", RES_MAC, DNS_IP, "fw-imported") if s in exp]
    revs = fw.succeed("patronus config revisions | wc -l").strip()
    diff = fw.execute("patronus config export > /root/export-now.json; diff /root/export-before.json /root/export-now.json | head -20")[1]
    m.check(f"{what}-wrote-nothing", not found and revs == revs_before, f"imported strings in the store: {found}; revisions {revs_before}->{revs}; "
            f"other changes: {diff.strip()[:300] or 'none'}")


def _roles(fw):
    """the role lines of `patronus interfaces roles` (WAN / LAN / OPTn)"""
    return "\n".join(ln.strip() for ln in fw.succeed("patronus interfaces roles 2>/dev/null").splitlines() if ln[:3] in ("WAN", "LAN", "OPT"))


def _write_tmp(text, suffix):
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    f.write(text)
    f.close()
    return f.name
