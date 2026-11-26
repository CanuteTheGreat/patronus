"""Installed Patronus image: S.M.A.R.T. disk health (USE=smart) against QEMU-emulated SMART-capable disks (init-agnostic).

fw = Patronus installed from the ISO by the unattended installer, then booted with two extra disks: an AHCI/SATA disk (ide-hd, ATA SMART) and an
emulated NVMe controller (SMART/Health log page).  The installed disk itself is virtio (no SMART): it must be listed honestly as unsupported.

What it proves on the SHIPPED image (smartctl from the image's own package set, the patronus poller started by its own init script/unit):
 1. smartctl is package-owned (sys-apps/smartmontools) and the S.M.A.R.T. page/API exist
 2. the feature switched on through the API starts the poller, and within a few poll intervals /api/v1/smart lists the SATA disk and the NVMe disk
    with health PASSED and a protocol of ata / nvme
 3. the virtio system disk is not claimed to have S.M.A.R.T.
 4. a short self-test requested through the API is accepted for a SMART disk and refused (400/404) for a bad type
 5. the poller comes back after a reboot with the same disks (settings come from the store, not from memory)

    python3 -m vmtest run scenarios/installed_smart.py --arg iso=patronus-...iso
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vmtest import Disk, Network, Nic, NodeSpec, Test  # noqa: E402
from vmtest.recipes import PROJECTS, PW, make_answers, unattended_install  # noqa: E402


def _sibling(name):
    """Load a sibling scenario file by path (scenarios/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(os.path.dirname(os.path.abspath(__file__)), name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_first = _sibling("installed_firstrun")
API_PY, _write_tmp = _first.API_PY, _first._write_tmp

# every operational value of the scenario in one place
SATA_SIZE, NVME_SIZE = "2G", "2G"
POLL_MINUTES = 1                 # settings floor allows it; the poller also polls once at start
APPEAR_SECS = 240                # first poll + both disks listed


def define(args):
    P = PROJECTS["patronus"]
    answers, key = make_answers("patronus")
    fw = NodeSpec(name="fw", mem=int(args.get("mem", 3072)), cpus=2, iso=args["iso"], iso_media="usb", firmware="uefi",
                  disks=[Disk("24G")], extra_drives=[(answers, "usb")], ssh_key=key, login_password=PW, console_menu_key="8", boot_timeout=420,
                  nics=[Nic("user", forwards={}), Nic("lan", mac="52:54:00:01:00:01")])

    def run(m):
        fw = m.fw

        def api(method, path, body=None, timeout=240):
            arg = "-" if body is None else "'" + json.dumps(body).replace("'", "'\\''") + "'"
            out = fw.succeed(f"python3 /tmp/fwapi.py {method} {path} {arg} https://127.0.0.1:{P['port']} {P['web_user']} '{PW}'", timeout=timeout)
            head, _, rest = out.strip().partition("\n")
            code = int(head.split()[1])
            try:
                return code, json.loads(rest)
            except ValueError:
                return code, rest

        def disks():
            code, d = api("GET", "/api/v1/smart")
            return d.get("devices", []) if code == 200 and isinstance(d, dict) else []

        m.phase("install the firewall")
        unattended_install(m, fw)

        # the SMART disks are attached only for the installed boot: the unattended installer must never see a second candidate disk
        tmp = tempfile.mkdtemp(prefix="vmtest-smart-")
        sata, nvme = os.path.join(tmp, "sata.img"), os.path.join(tmp, "nvme.img")
        subprocess.check_call(["qemu-img", "create", "-q", "-f", "raw", sata, SATA_SIZE])
        subprocess.check_call(["qemu-img", "create", "-q", "-f", "raw", nvme, NVME_SIZE])
        fw.eject_media()
        fw.spec.extra_drives = [(sata, "ide"), (nvme, "nvme")]

        m.phase("first boot of the installed disk")
        fw.start()
        m.check("fw-boots-to-login", fw.q.expect(r"login:", fw.T(420)), "")
        fw.wait_for_shell()
        fw.wait_for_unit(P["svc"], 300)
        m.check(f"{P['svc']}-active", True, fw.init.name)
        fw.wait_until_succeeds(f"timeout 3 bash -c ': </dev/tcp/127.0.0.1/{P['port']}'", 120, 3)
        fw.put_file(_write_tmp(API_PY), "/tmp/fwapi.py")

        m.phase("1. smartctl is a package-owned part of the image")
        owner = fw.succeed("qfile -Cq $(command -v smartctl)").strip()
        m.check("smartctl-owned-by-smartmontools", owner == "sys-apps/smartmontools", owner)
        code, st = api("GET", "/api/v1/smart")
        m.check("smart-api-answers-while-off", code == 200 and st.get("enabled") is False and st.get("smartctl_installed") is True, f"{code} {str(st)[:300]}")

        m.phase("2. switched on: both emulated disks are listed with health PASSED")
        code, r = api("PUT", "/api/svc/smart", {"enabled": True, "poll_minutes": POLL_MINUTES})
        m.check("smart-enabled-through-the-api", code == 200, f"{code} {str(r)[:300]}")
        seen = {}
        end = time.time() + APPEAR_SECS
        while time.time() < end:
            seen = {d["protocol"]: d for d in disks() if d.get("protocol") in ("ata", "nvme")}
            if "ata" in seen and "nvme" in seen:
                break
            time.sleep(10)
        m.check("sata-disk-listed", "ata" in seen, str(list(seen)))
        m.check("nvme-disk-listed", "nvme" in seen, str(list(seen)))
        for proto, d in sorted(seen.items()):
            m.check(f"{proto}-health-passed", d.get("health") == "PASSED" and d.get("level") == "ok", f"{d.get('name')} {d.get('health')} {d.get('level')} {d.get('reasons')}")
        poller = fw.execute("pgrep -fc '[p]atronus.* smart run'")[1].strip()
        m.check("poller-runs-under-the-init-system", poller not in ("", "0"), f"{fw.init.name}: {poller} process(es)")

        m.phase("3. the virtio system disk is not claimed to have S.M.A.R.T.")
        virt = [d for d in disks() if d.get("name", "").startswith("vd")]
        m.check("virtio-disk-has-no-health-claim", all(d.get("health") is None and d.get("smart_available") is False for d in virt), str(virt)[:300])

        m.phase("4. self-test request")
        if "ata" in seen:
            name = seen["ata"]["name"]
            code, r = api("POST", f"/api/v1/smart/{name}/test", {"type": "short"})
            m.check("short-test-accepted", code in (200, 202), f"{code} {str(r)[:200]}")
            code, r = api("POST", f"/api/v1/smart/{name}/test", {"type": "format"})
            m.check("unknown-test-type-refused", code == 400, f"{code} {str(r)[:200]}")

        m.phase("5. after a reboot the poller lists the disks again")
        fw.succeed("sync")
        fw.reboot(420)
        fw.wait_for_unit(P["svc"], 300)
        fw.wait_until_succeeds(f"timeout 3 bash -c ': </dev/tcp/127.0.0.1/{P['port']}'", 120, 3)
        fw.put_file(_write_tmp(API_PY), "/tmp/fwapi.py")
        end = time.time() + APPEAR_SECS
        protos = set()
        while time.time() < end:
            protos = {d["protocol"] for d in disks() if d.get("health") == "PASSED"}
            if {"ata", "nvme"} <= protos:
                break
            time.sleep(10)
        m.check("both-disks-back-after-reboot", {"ata", "nvme"} <= protos, str(sorted(protos)))
        fw.screenshot("fw-smart-after-reboot")

    return Test("installed-smart", nodes=[fw], networks=[Network("lan")], run=run, timeout=3600,
                description="installed Patronus: S.M.A.R.T. poller lists an emulated SATA and NVMe disk as PASSED, refuses claims for virtio, survives a reboot")
