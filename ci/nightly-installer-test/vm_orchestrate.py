#!/usr/bin/env python3
"""
Host-side orchestration for the Patronus nightly realistic installer test.

Runs inside the job container of the `kvm-x86_64` runner (rw-man-01, the one
CI host with /dev/kvm; see ctg-infrastructure ci-runners/rw-man-kvm) and
drives QEMU/KVM directly - no UTM, no GUI session, no Apple Events.

What it does (all real, no simulation):
  1. Creates a fresh 8 GiB qcow2 disk and a per-run copy of the OVMF
     UEFI variable store.
  2. Boots an x86_64 q35 VM (KVM-accelerated, `-cpu host`) from the
     remastered Alpine ISO built earlier in the job. The ISO's cmdline
     pulls our apkovl, whose start script runs the REAL patronus-install
     unattended against /dev/vda: real GPT partitioning, a real
     `zpool create` for the ZFS root, GRUB on the ESP.
  3. Collects the guest's reports (LIVE_BOOT_START, INSTALL_DONE rc=0,
     POST_INSTALL_ZPOOL) over a small HTTP server here; the guest reaches it
     at 10.0.2.2 through QEMU user networking, which maps to this
     container's loopback.
  4. The guest reboots; QEMU runs with -no-reboot so that ends phase 1.
     Phase 2 cold-boots the same disk + NVRAM with the install media
     REMOVED, so the only way to come up is the freshly installed
     GRUB/UEFI entry. The installed system's start script reports
     SECOND_BOOT_OK with the live zpool state, then powers off.
  5. Prints both serial console logs and fails with a clear reason at the
     first missing milestone (or immediately if QEMU dies early).
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import time

HTTP_PORT = 8788
WORKDIR = os.environ.get("CI_WORKDIR", "/tmp/patronus-vm-test")
MEM_MB = int(os.environ.get("VM_MEM_MB", "4096"))
CPUS = int(os.environ.get("VM_CPUS", "4"))
LIVE_BOOT_TIMEOUT_S = int(os.environ.get("LIVE_BOOT_TIMEOUT_S", "600"))
INSTALL_TIMEOUT_S = int(os.environ.get("INSTALL_TIMEOUT_S", "1800"))
SECOND_BOOT_TIMEOUT_S = int(os.environ.get("SECOND_BOOT_TIMEOUT_S", "600"))

OVMF_CODE_CANDIDATES = [
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
]
OVMF_VARS_CANDIDATES = [
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
]

events = []
events_lock = threading.Lock()


class ReportHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WORKDIR, **kw)

    def log_message(self, fmt, *args):
        sys.stderr.write("[http] " + (fmt % args) + "\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        with events_lock:
            events.append((time.time(), body))
        print(f"[guest-report] {body}", flush=True)
        self.send_response(200)
        self.end_headers()


def first_existing(paths, what):
    for p in paths:
        if os.path.isfile(p):
            return p
    raise SystemExit(f"{what} not found (tried {paths}); install the 'ovmf' package")


def check_kvm():
    if not os.path.exists("/dev/kvm"):
        raise SystemExit(
            "/dev/kvm is missing in this job container. This job must run on the "
            "kvm-x86_64 runner (rw-man-01, container option --device=/dev/kvm); "
            "refusing to fall back to TCG software emulation, which never finishes."
        )
    try:
        fd = os.open("/dev/kvm", os.O_RDWR)
        os.close(fd)
    except OSError as e:
        raise SystemExit(f"/dev/kvm present but not usable: {e}")
    print("[host] /dev/kvm usable - KVM acceleration available", flush=True)


def find_event(predicate):
    with events_lock:
        for _, body in events:
            if predicate(body):
                return body
    return None


def wait_for_event(predicate, timeout_s, label, proc, serial_log):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        body = find_event(predicate)
        if body is not None:
            return body
        if proc.poll() is not None:
            # QEMU exited; give in-flight reports a moment, then decide.
            time.sleep(2)
            body = find_event(predicate)
            if body is not None:
                return body
            dump_serial(serial_log)
            raise SystemExit(f"QEMU exited (rc={proc.returncode}) before: {label}\nEvents so far: {events}")
        time.sleep(2)
    dump_serial(serial_log)
    raise SystemExit(f"TIMEOUT ({timeout_s}s) waiting for: {label}\nEvents so far: {events}")


def dump_serial(path, max_lines=400):
    try:
        with open(path, "rb") as f:
            data = f.read().decode("utf-8", "replace").splitlines()
    except OSError as e:
        print(f"[host] could not read {path}: {e}", flush=True)
        return
    shown = data[-max_lines:]
    print(f"[host] ==== {os.path.basename(path)}: last {len(shown)} of {len(data)} lines ====", flush=True)
    for line in shown:
        print(line)
    print("[host] ==== end serial ====", flush=True)


def qemu_cmd(disk, code, vars_fd, serial_log, iso=None):
    cmd = [
        "qemu-system-x86_64",
        "-name", "patronus-nightly",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", str(CPUS),
        "-m", str(MEM_MB),
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_fd}",
        "-drive", f"file={disk},if=none,id=hd0,format=qcow2",
        "-device", f"virtio-blk-pci,drive=hd0,bootindex={1 if iso else 0}",
        "-netdev", "user,id=n0",
        "-device", "virtio-net-pci,netdev=n0",
        "-device", "virtio-rng-pci",
        "-serial", f"file:{serial_log}",
        "-display", "none",
        "-monitor", "none",
        "-no-reboot",
    ]
    if iso:
        cmd += [
            "-drive", f"file={iso},if=none,id=cd0,media=cdrom,readonly=on",
            "-device", "ide-cd,drive=cd0,bus=ide.0,bootindex=0",
        ]
    return cmd


def start_qemu(cmd):
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.Popen(cmd)


def stop_qemu(proc, grace_s):
    try:
        proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        print(f"[host] QEMU still running after {grace_s}s - killing it", flush=True)
        proc.kill()
        proc.wait()


def main():
    iso = os.path.abspath(sys.argv[1])
    check_kvm()
    os.makedirs(WORKDIR, exist_ok=True)
    code = first_existing(OVMF_CODE_CANDIDATES, "OVMF code")
    vars_src = first_existing(OVMF_VARS_CANDIDATES, "OVMF vars")
    vars_fd = os.path.join(WORKDIR, "OVMF_VARS.fd")
    shutil.copyfile(vars_src, vars_fd)
    disk = os.path.join(WORKDIR, "disk.qcow2")
    subprocess.run(["qemu-img", "create", "-f", "qcow2", disk, "8G"], check=True)
    serial1 = os.path.join(WORKDIR, "serial-install.log")
    serial2 = os.path.join(WORKDIR, "serial-second-boot.log")

    server = http.server.ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ReportHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[host] report/file server on :{HTTP_PORT}, serving {WORKDIR}", flush=True)

    result = {"ok": False}
    proc = None
    try:
        t0 = time.time()
        proc = start_qemu(qemu_cmd(disk, code, vars_fd, serial1, iso=iso))
        wait_for_event(lambda b: "LIVE_BOOT_START" in b, LIVE_BOOT_TIMEOUT_S, "live ISO boot", proc, serial1)
        print(f"[host] live system up after {time.time() - t0:.0f}s", flush=True)
        done = wait_for_event(lambda b: "INSTALL_DONE" in b, INSTALL_TIMEOUT_S, "installer completion", proc, serial1)
        if "rc=0" not in done:
            dump_serial(serial1)
            raise SystemExit(f"Installer reported non-zero exit: {done}")
        zp = wait_for_event(lambda b: "POST_INSTALL_ZPOOL" in b, 120, "post-install zpool report", proc, serial1)
        if "ONLINE" not in zp:
            dump_serial(serial1)
            raise SystemExit(f"zpool not ONLINE after install: {zp}")
        print(f"[host] REAL install verified after {time.time() - t0:.0f}s, zpool ONLINE", flush=True)
        # The guest reboots itself; -no-reboot turns that into a QEMU exit.
        stop_qemu(proc, 120)
        proc = None
        dump_serial(serial1, max_lines=150)

        t1 = time.time()
        proc = start_qemu(qemu_cmd(disk, code, vars_fd, serial2, iso=None))
        second = wait_for_event(lambda b: "SECOND_BOOT_OK" in b, SECOND_BOOT_TIMEOUT_S,
                                "second boot (installed system, no install media attached)", proc, serial2)
        if "ONLINE" not in second:
            dump_serial(serial2)
            raise SystemExit(f"second boot came up but zpool not ONLINE: {second}")
        print(f"[host] REAL boot of the installed system verified after {time.time() - t1:.0f}s", flush=True)
        stop_qemu(proc, 60)
        proc = None
        dump_serial(serial2, max_lines=200)
        result = {"ok": True, "install_evidence": zp, "reboot_evidence": second}
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        server.shutdown()

    print(json.dumps(result))
    if not result["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
