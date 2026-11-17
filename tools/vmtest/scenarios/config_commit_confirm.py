"""Commit-confirmed config changes on a real Patronus VM (OpenRC and systemd images, one script).

 fw  = Patronus installed from the ISO by the unattended installer, WAN = QEMU user net, LAN = hub `lan` (10.77.0.1/24)
 cli = Alpine live, LAN = hub `lan` (10.77.0.2/24)

A bad change (an input rule that drops ICMP from the LAN to the firewall) is applied "on trial"
(X-Confirm-In). The client really loses access, patronus applyd's own timer reverts the change at the deadline and the access
comes back. The same with the web service restarted while pending, and with a power cut while pending; Confirm keeps a change.
Service control goes through the init-agnostic API (`restart_unit`), so one script runs on the OpenRC and the systemd image.

    python3 -m vmtest run scenarios/config_commit_confirm.py --arg iso=patronus-server-openrc-...iso
    python3 -m vmtest run scenarios/config_commit_confirm.py --arg iso=patronus-server-systemd-...iso

An ISO that predates config generations has no `patronus config generations`: the scenario then records a note and stops
(pass --arg require_generations=1 to make that a failure; CI does once the daily ISO carries the feature).
"""
import json
import os
import shlex
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vmtest import Disk, Network, Nic, NodeSpec, Test, cache  # noqa: E402
from vmtest.recipes import PROJECTS, PW, make_answers, unattended_install  # noqa: E402

ALPINE = ("https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.4-x86_64.iso",
          "157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f")
FW = "10.77.0.1"
# the risky change: ICMP from the LAN to the firewall is dropped, so the client's ping fails (the anti-lockout ports 22/8443 always stay open)
LOCKOUT = {"name": "vmt-lockout", "chain": "input", "action": "drop", "interface": "@lan", "protocol": "icmp",
           "source": "any", "destination": "any", "port": "any", "description": "vmt-lockout", "enabled": True}


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers("patronus")
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8",
                  boot_timeout=420, nics=[Nic("user", forwards={}), Nic("lan", mac="52:54:00:01:00:01")])
    cli = NodeSpec(name="cli", mem=512, cpus=1, iso=args.get("client_iso") or cache.fetch(*ALPINE), disks=[Disk("1G")],
                   nics=[Nic("user", forwards={}), Nic("lan", mac="52:54:00:02:00:01")])

    def run(m):
        fw_, cli_ = m.fw, m.cli
        ping = f"ping -c1 -W2 {FW}"
        web = f"nc -z -w 3 {FW} {P['port']}"

        def api(method, path, body=None, headers=()):
            """Call the web API on the firewall itself (loopback: no firewall rule can cut it) with a session cookie."""
            c = ["curl", "-sk", "-m", "40", "-b", "/tmp/vmt.jar", "-c", "/tmp/vmt.jar", "-X", method,
                 "-H", "content-type: application/json", "-D", "/tmp/vmt.hdr", "-o", "/tmp/vmt.out", "-w", "%{http_code}"]
            for h in headers:
                c += ["-H", h]
            if body is not None:
                c += ["-d", json.dumps(body)]
            c.append(f"https://127.0.0.1:{P['port']}/api{path}")
            code = fw_.succeed(" ".join(shlex.quote(x) for x in c), timeout=90).strip().splitlines()[-1]
            out = fw_.succeed("cat /tmp/vmt.out; echo; grep -i '^x-pending' /tmp/vmt.hdr || true", timeout=30)
            try:
                return int(code), out
            except ValueError:
                return 0, out

        def login():
            code, out = api("POST", "/auth/login", {"username": P["web_user"], "password": PW})
            m.check("web-login", code == 200, f"{P['web_user']} -> {code}")

        def pending():
            code, out = api("GET", "/system/generations/pending")
            return json.loads(out.strip().splitlines()[0]) if code == 200 else {}

        def arm(minutes=1):
            code, out = api("POST", "/firewall/rules", LOCKOUT, headers=[f"X-Confirm-In: {minutes}", "X-Commit-Message: vmtest%20risky%20change"])
            m.check("risky-change-armed", code == 201 and "x-pending-deadline" in out.lower(), f"HTTP {code} {out[:120]!r}")

        def locked_out(what):
            cli_.wait_until_fails(ping, 45, 2)
            cli_.fail(ping)
            fw_.succeed("nft list ruleset | grep -F vmt-lockout >/dev/null")
            cli_.succeed(web)            # the anti-lockout ports stay open: the client can still reach the UI to confirm
            m.check(f"client-loses-access-{what}", True, "ping to the firewall fails, rule is in nft, UI port still open")

        def access_back(what, timeout=240):
            cli_.wait_until_succeeds(ping, timeout, 3)
            fw_.fail("nft list ruleset | grep -F vmt-lockout >/dev/null")
            m.check(f"access-returns-{what}", True, "ping works again and the rule is gone from nft")

        m.phase("install the firewall, boot the client")
        unattended_install(m, fw_)
        cli_.start()
        cli_.wait_for_shell()
        cli_.succeed("ip link set eth1 up && ip addr add 10.77.0.2/24 dev eth1")

        m.phase("firewall first boot")
        fw_.start()
        m.check("fw-boots-to-login", fw_.q.expect(r"login:", fw_.T(420)), "")
        fw_.wait_for_shell()
        fw_.wait_for_unit(P["svc"], 300)
        fw_.wait_for_unit("patronus-applyd", 120)
        m.check("applyd-active", True, f"{fw_.init.name}: patronus-applyd, the root daemon that owns the revert timer")
        cli_.wait_until_succeeds(ping, 240, 3)
        cli_.wait_until_succeeds(web, 300, 5)
        has, _ = fw_.execute("patronus config generations >/dev/null 2>&1")
        if has != 0:
            (m.check if args.get("require_generations") else m.note)(
                "iso-has-config-generations", False, "this ISO predates config generations: nothing to test")
            return
        m.check("iso-has-config-generations", True, "")
        fw_.wait_until(lambda: api("POST", "/auth/login", {"username": P["web_user"], "password": PW})[0] == 200, 300, 5, "web login")
        login()

        m.phase("1. a bad change is reverted at the deadline")
        arm(1)
        locked_out("on-trial")
        p = pending()
        m.check("countdown-is-stored", bool(p.get("pending")) and p["pending"]["seconds_left"] > 0, str(p)[:160])
        access_back("at-the-deadline", 240)
        fw_.wait_until(lambda: not pending().get("pending"), 60, 3, "pending cleared")
        out = fw_.succeed("patronus config generations")
        m.check("revert-recorded-as-a-generation", "revert" in out and "commit-confirm" in out, out[:300])

        m.phase("2. confirm keeps a change")
        arm(1)
        locked_out("on-trial-2")
        code, out = api("POST", "/system/generations/pending/confirm")
        m.check("confirm-accepted", code == 200, out[:120])
        fw_.wait_until(lambda: not pending().get("pending"), 30, 2, "pending cleared")
        time.sleep(75)
        cli_.fail(ping)
        m.check("confirmed-change-survives-the-deadline", True, "still blocked 75 s later")
        code, out = api("GET", "/firewall/rules")
        rid = [r["id"] for r in json.loads(out.strip().splitlines()[0]) if r["name"] == "vmt-lockout"][0]
        api("DELETE", f"/firewall/rules/{rid}")
        access_back("after-deleting-the-rule", 90)

        m.phase("3. the web service restarts while pending: the revert still happens")
        arm(1)
        locked_out("on-trial-3")
        fw_.restart_unit(P["svc"])        # openrc or systemd, same call
        fw_.wait_for_unit(P["svc"], 120)
        access_back("web-restarted-while-pending", 240)

        m.phase("4. power cut while pending")
        arm(1)
        locked_out("on-trial-4")
        fw_.crash()
        cli_.wait_until_fails(web, 30, 2)
        fw_.start()
        fw_.wait_for_shell()
        fw_.wait_for_unit(P["svc"], 420)
        fw_.wait_for_unit("patronus-applyd", 120)
        access_back("after-the-power-cut", 420)
        out = fw_.succeed("patronus config generations")
        m.check("no-pending-after-boot", "applied on trial" not in out, out[-200:])
        m.fw.screenshot("fw-after-commit-confirm")
        m.note("init-system", True, fw_.init.name)

    return Test("config-commit-confirm", nodes=[fw, cli], networks=[Network("lan")], run=run, timeout=5400,
                description="commit-confirmed config change: client loses access, applyd reverts at the deadline, access returns (web restart and power cut too)")
