#!/usr/bin/env python3
"""
Host-side orchestration for the Patronus nightly realistic installer
test. Runs on beauxbatons (macOS, arm64) as a step of the
`nightly-realistic-installer-test` Forgejo Actions workflow, on the
`macos-host` (host-execution, not docker) runner label, because it
needs real Apple Events access to utmctl — which only works inside the
logged-in GUI session a LaunchAgent-run runner has, never over plain
SSH.

What it actually does (all real, no simulation):
  1. Creates a fresh small (8GB) QEMU x86_64 VM bundle under UTM.
  2. Boots it from a remastered Alpine Linux ISO (built earlier in the
     workflow) that unattended-installs Patronus onto the VM's virtual
     disk: real GPT partitioning, real `zpool create` for the ZFS root.
  3. Verifies the install really finished (exit code + zpool status)
     via a report the guest POSTs to a tiny HTTP server we run here,
     over the VM's slirp NAT (guest always reaches host at 10.0.2.2) --
     chosen instead of the UTM guest agent because that agent isn't
     present on a bare live ISO.
  4. Lets the guest reboot for real, off the now-installed disk via
     its real GRUB/UEFI boot entry, and waits for a second report that
     proves the second boot actually came up, still showing the real
     zpool.
  5. Tears the VM and its disk down afterward (disk budget hygiene).
"""
import http.server
import json
import os
import plistlib
import shutil
import subprocess
import sys
import threading
import time
import uuid

UTMCTL = "/Applications/UTM.app/Contents/MacOS/utmctl"
QEMU_IMG = "/Users/rbf/rustinion-verify/homebrew/bin/qemu-img"
# UTM's own bundled qemu-img (Contents/Frameworks/qemu-img.framework/qemu-img)
# is shipped as an MH_DYLIB Mach-O (a real shared library, per `file`/`lipo`),
# not a standalone executable - the kernel refuses to execve() it at all
# ("Exec format error", confirmed directly), it's meant to be dlopen'd by
# UTM's own GUI process internally, not shelled out to. Use a real
# standalone qemu-img from Homebrew instead.
UTM_DOCS = os.path.expanduser(
    "~/Library/Containers/com.utmapp.UTM/Data/Documents"
)
# Stage newly-built VM bundles OUTSIDE UTM's sandboxed container. Our
# process (launched via launchd, not the UTM app itself) cannot write
# directly into ~/Library/Containers/com.utmapp.UTM/Data/Documents -
# that's enforced by the app sandbox at the kernel level, independent
# of ordinary TCC grants like Full Disk Access, and confirmed the hard
# way (PermissionError on os.makedirs there). Build the bundle in a
# plain external directory instead, then hand it to the already-running
# UTM app via `open -a UTM <path>`, same as before - UTM importing a
# file via LaunchServices' open event is a legitimate user-intent
# action the sandbox allows, unlike an arbitrary external process
# writing into the container directly.
UTM_EXTERNAL_STAGING = os.path.expanduser(
    "~/.forgejo-runner-data/utm-external-vms"
)

HTTP_PORT = 8788
RUN_ID = os.environ.get("CI_RUN_ID", uuid.uuid4().hex[:8])
VM_NAME = f"patronus-nightly-{RUN_ID}"
WORKDIR = os.environ.get("CI_WORKDIR", "/tmp/patronus-vm-test")
TOTAL_TIMEOUT_S = int(os.environ.get("CI_TOTAL_TIMEOUT_S", "1800"))

events = []
events_lock = threading.Lock()


class ReportHandler(http.server.BaseHTTPRequestHandler):
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

    def do_GET(self):
        # Serves the apkovl / modloop files for the guest to fetch.
        return super().do_GET()


def run(cmd, **kw):
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


def sanity_check_utmctl():
    out = subprocess.run([UTMCTL, "list"], capture_output=True, text=True)
    combined = (out.stdout or "") + (out.stderr or "")
    if "does not work from SSH sessions" in combined:
        print(combined)
        raise SystemExit(
            "ARCHITECTURE CHECK FAILED: utmctl is not usable from this "
            "job's execution context (looks like an SSH-only session, "
            "not the LaunchAgent's GUI session). Host-execution label "
            "is not actually reaching the GUI session."
        )
    print("utmctl list OK (host-exec / GUI session confirmed reachable):")
    print(combined)


def build_vm_bundle(iso_path, disk_size_gb=8):
    os.makedirs(UTM_EXTERNAL_STAGING, exist_ok=True)
    vm_dir = os.path.join(UTM_EXTERNAL_STAGING, f"{VM_NAME}.utm")
    data_dir = os.path.join(vm_dir, "Data")
    os.makedirs(data_dir, exist_ok=True)

    disk_uuid = str(uuid.uuid4()).upper()
    disk_name = f"{disk_uuid}.qcow2"
    disk_path = os.path.join(data_dir, disk_name)
    run([QEMU_IMG, "create", "-f", "qcow2", disk_path, f"{disk_size_gb}G"])

    cd_name = "install.iso"
    shutil.copyfile(iso_path, os.path.join(data_dir, cd_name))

    cfg = {
        "Backend": "QEMU",
        "ConfigurationVersion": 4,
        "Display": [
            {
                "DownscalingFilter": "Linear",
                "DynamicResolution": True,
                "Hardware": "virtio-ramfb",
                "NativeResolution": False,
                "UpscalingFilter": "Nearest",
            }
        ],
        "Drive": [
            {
                "Identifier": str(uuid.uuid4()).upper(),
                "ImageName": cd_name,
                "ImageType": "CD",
                "Interface": "USB",
                "InterfaceVersion": 1,
                "ReadOnly": True,
            },
            {
                "Identifier": disk_uuid,
                "ImageName": disk_name,
                "ImageType": "Disk",
                "Interface": "VirtIO",
                "InterfaceVersion": 1,
                "ReadOnly": False,
            },
        ],
        "Information": {
            "IconCustom": False,
            "Name": VM_NAME,
            "UUID": str(uuid.uuid4()).upper(),
        },
        "Input": {
            "MaximumUsbShare": 3,
            "UsbBusSupport": "3.0",
            "UsbSharing": False,
        },
        "Network": [
            {
                "Hardware": "virtio-net-pci",
                "IsolateFromHost": False,
                "MacAddress": "52:54:00:%02x:%02x:%02x" % (
                    os.urandom(1)[0], os.urandom(1)[0], os.urandom(1)[0]
                ),
                # "Shared" is UTM's vmnet-based NAT (a separate, variable
                # gateway, and on macOS needs its own entitlements/daemon).
                # The build job bakes the guest's callback URLs as
                # http://10.0.2.2:$HTTP_PORT/... (see iso_remaster.sh) -
                # that address is QEMU's own usermode-networking gateway,
                # which is what UTM's "Emulated" mode actually is. Every
                # earlier run of this pipeline died before ever reaching a
                # real boot (runner misrouting, then buffering, then a
                # host-dir permission issue), so this mismatch - present
                # since the very first commit of this file - never
                # mattered until now: the guest booted fine but had
                # nowhere real to phone home to.
                "Mode": "Emulated",
                "PortForward": [],
            }
        ],
        "QEMU": {
            "AdditionalArguments": [],
            "BalloonDevice": False,
            "DebugLog": False,
            "Hypervisor": True,
            "PS2Controller": False,
            "RNGDevice": True,
            "RTCLocalTime": False,
            "TPMDevice": False,
            "TSO": False,
            "UEFIBoot": True,
        },
        "Serial": [
            {
                "Mode": "TcpServer",
                "Target": "Auto",
                "TcpPort": 48788,
                "WaitForConnection": False,
                "RemoteConnectionAllowed": False,
            }
        ],
        "Sharing": {
            "ClipboardSharing": False,
            "DirectoryShareMode": "None",
            "DirectoryShareReadOnly": True,
        },
        "Sound": [],
        "System": {
            "Architecture": "x86_64",
            "CPU": "default",
            "CPUCount": 2,
            "CPUFlagsAdd": [],
            "CPUFlagsRemove": [],
            "ForceMulticore": False,
            "JITCacheSize": 0,
            "MemorySize": 2048,
            "Target": "q35",
        },
    }

    with open(os.path.join(vm_dir, "config.plist"), "wb") as f:
        plistlib.dump(cfg, f)

    # Make UTM (already running in the GUI session) register the bundle.
    subprocess.run(["open", "-a", "UTM", vm_dir], check=False)
    time.sleep(5)
    return vm_dir, cfg["Information"]["UUID"]


def find_vm_uuid_by_name(name, retries=10):
    for _ in range(retries):
        out = subprocess.run([UTMCTL, "list"], capture_output=True, text=True)
        for line in out.stdout.splitlines():
            if name in line:
                return line.split()[0]
        time.sleep(2)
    raise SystemExit(f"VM '{name}' never showed up in `utmctl list`:\n{out.stdout}\n{out.stderr}")


def wait_for_event(predicate, timeout_s, label):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with events_lock:
            for ts, body in events:
                if predicate(body):
                    return body
        time.sleep(3)
    raise SystemExit(f"TIMEOUT waiting for: {label}\nEvents so far: {events}")


SERIAL_PORT = 48788
serial_log_path = None


def capture_serial(host_port, log_path, stop_event):
    """Connects to the VM's TCP-server serial backend and tees
    everything it sends (the guest's ttyS0, which the kernel cmdline
    already targets via console=ttyS0,115200) to a log file - our only
    real window into what the guest is actually doing during boot,
    since there's no VNC/screenshot capability available here."""
    import socket
    for _ in range(30):
        if stop_event.is_set():
            return
        try:
            sock = socket.create_connection(("127.0.0.1", host_port), timeout=2)
            break
        except OSError:
            time.sleep(1)
    else:
        print(f"[serial] could not connect to serial TCP server on :{host_port}", flush=True)
        return
    print(f"[serial] connected to guest serial console on :{host_port}", flush=True)
    with open(log_path, "ab") as f, sock:
        sock.settimeout(1)
        while not stop_event.is_set():
            try:
                data = sock.recv(4096)
                if not data:
                    break
                f.write(data)
                f.flush()
            except socket.timeout:
                continue
            except OSError:
                break


def main():
    iso_path = sys.argv[1]
    os.makedirs(WORKDIR, exist_ok=True)

    sanity_check_utmctl()

    global serial_log_path
    serial_log_path = os.path.join(WORKDIR, f"serial-{RUN_ID}.log")
    open(serial_log_path, "wb").close()
    serial_stop = threading.Event()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ReportHandler)
    # Serve files (apkovl/modloop) from the same dir the caller staged.
    os.chdir(WORKDIR)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[host] report server up on :{HTTP_PORT}, serving {WORKDIR}")

    vm_dir, cfg_uuid = build_vm_bundle(iso_path)
    vm_uuid = find_vm_uuid_by_name(VM_NAME)
    print(f"[host] VM registered: {VM_NAME} -> {vm_uuid}")

    result = {"vm": VM_NAME, "ok": False}
    try:
        run([UTMCTL, "start", vm_uuid])

        serial_thread = threading.Thread(
            target=capture_serial, args=(SERIAL_PORT, serial_log_path, serial_stop), daemon=True
        )
        serial_thread.start()

        wait_for_event(lambda b: "LIVE_BOOT_START" in b, 600, "live ISO boot")
        done = wait_for_event(lambda b: "INSTALL_DONE" in b, TOTAL_TIMEOUT_S, "installer completion")
        if "rc=0" not in done:
            raise SystemExit(f"Installer reported non-zero exit: {done}")
        zpool_ev = wait_for_event(lambda b: "POST_INSTALL_ZPOOL" in b, 60, "post-install zpool report")
        if "state: ONLINE" not in zpool_ev and "ONLINE" not in zpool_ev:
            raise SystemExit(f"zpool not ONLINE after install: {zpool_ev}")
        print(f"[host] REAL install verified, real zpool ONLINE: {zpool_ev}")

        second = wait_for_event(lambda b: "SECOND_BOOT_OK" in b, 600, "second boot (installed system) report")
        print(f"[host] REAL reboot into installed system verified: {second}")

        result["ok"] = True
        result["install_evidence"] = zpool_ev
        result["reboot_evidence"] = second
    finally:
        serial_stop.set()
        time.sleep(0.5)
        try:
            with open(serial_log_path, "rb") as f:
                serial_data = f.read()
            print(f"[host] ==== captured guest serial console ({len(serial_data)} bytes) ====", flush=True)
            sys.stdout.buffer.write(serial_data)
            sys.stdout.flush()
            print("[host] ==== end guest serial console ====", flush=True)
        except OSError as e:
            print(f"[host] could not read serial log: {e}", flush=True)
        subprocess.run([UTMCTL, "stop", vm_uuid], capture_output=True)
        time.sleep(3)
        subprocess.run([UTMCTL, "delete", vm_uuid], capture_output=True)
        shutil.rmtree(vm_dir, ignore_errors=True)
        server.shutdown()

    print(json.dumps(result))
    if not result["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
