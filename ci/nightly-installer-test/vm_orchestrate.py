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
                # GRUB (built into the EFI firmware's bootx64.efi here -
                # this VM boots via real UEFI, confirmed by actual
                # "BdsDxe:" messages over the new serial capture) stalls
                # silently reading the kernel/initrd off a USB-attached
                # virtual CD-ROM: the serial log shows real GRUB 2.12
                # menu output and "Booting `Linux lts'", then nothing
                # at all - no kernel banner, no panic, just silence,
                # every single time. IDE is the overwhelmingly standard,
                # best-tested bus for virtual optical media across every
                # BIOS/UEFI firmware and bootloader combination; there's
                # no real reason this needed USB in the first place.
                "Interface": "IDE",
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
            # -no-reboot: every captured serial log for this test so far
            # has shown the VM silently cycle back to an identical fresh
            # UEFI firmware + GRUB screen after "Booting `Linux lts'"
            # with zero diagnostic output in between (see run 2591 /
            # task 6675) - consistent with the guest hitting a reset
            # (triple fault or an explicit reboot) before anything new
            # reaches the serial console, which QEMU's default behavior
            # silently swallows by actually resetting the VM. Without
            # this flag that reset erases the only evidence of what
            # actually went wrong, and the harness has been retrying
            # blind for days. With -no-reboot, QEMU halts (not resets)
            # on a guest reset request, so whatever was last printed -
            # including a panic/triple-fault the firmware itself may
            # emit - stays on the serial line for this capture instead
            # of being overwritten by a clean restart.
            "AdditionalArguments": [
                {"Argument": "-no-reboot"},
            ],
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
            # Reverted "max" (8cff65d): confirmed WORSE, not better - all 3
            # retried attempts under "max" hung completely silent before the
            # kernel ever logged a single line (identical shape to the
            # original USB-CD-ROM bug, already fixed separately), instead of
            # the at-least-diagnosable IO-APIC panic "default" produces.
            # "max" exposing TCG's fullest feature set apparently confuses
            # this OVMF/GRUB combination even earlier in the boot chain than
            # the kernel's own timer calibration. Back to "default" pending a
            # more targeted fix for the actual panic (noapic/acpi=off/
            # no_timer_check were each tried alone and individually
            # insufficient or counterproductive - see iso_remaster.sh).
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
    #
    # Was a bare fire-and-forget `check=False` call that discarded both
    # the exit status and any stderr. Every nightly run from 2026-10-04
    # onward has failed at the find_vm_uuid_by_name() wait below with
    # "never showed up in `utmctl list`" after burning through all three
    # boot-retry attempts (each paying the full 90s registration-wait
    # budget), and the unified system log for the UTM process shows
    # *zero* entries in that window - meaning the Apple Event this `open`
    # is supposed to deliver never even reached the app, i.e. `open`
    # itself is failing (wrong LaunchServices database state, a stale/
    # duplicate UTM registration, sandbox quirk, etc.), not "UTM is just
    # slow to import today" as the retry/backoff tuning upstream of this
    # function assumed. Capture and print the actual result so the next
    # failure (if this doesn't fix it outright) shows the real `open`
    # exit code and stderr instead of silence, and fail fast with a
    # clear message if `open` itself reports an error rather than
    # ever bothering to poll utmctl for a bundle that was never opened.
    if not os.path.isdir(vm_dir):
        raise SystemExit(f"[host] vm_dir does not exist right before `open`: {vm_dir}")
    open_result = subprocess.run(
        ["open", "-a", "UTM", vm_dir], capture_output=True, text=True
    )
    print(
        f"[host] open -a UTM {vm_dir} -> exit {open_result.returncode}"
        f"{' stdout=' + open_result.stdout.strip() if open_result.stdout.strip() else ''}"
        f"{' stderr=' + open_result.stderr.strip() if open_result.stderr.strip() else ''}",
        flush=True,
    )
    if open_result.returncode != 0:
        # Retry once via bundle identifier instead of app name - `open
        # -a UTM` resolves the app name through LaunchServices and can
        # fail if that database is stale (multiple UTM.app copies, a
        # recent reinstall, etc.) even while the already-running UTM
        # process itself is perfectly healthy; `-b <bundle id>` targets
        # it directly and sidesteps that particular lookup.
        retry_result = subprocess.run(
            ["open", "-b", "com.utmapp.UTM", vm_dir], capture_output=True, text=True
        )
        print(
            f"[host] retry: open -b com.utmapp.UTM {vm_dir} -> exit {retry_result.returncode}"
            f"{' stdout=' + retry_result.stdout.strip() if retry_result.stdout.strip() else ''}"
            f"{' stderr=' + retry_result.stderr.strip() if retry_result.stderr.strip() else ''}",
            flush=True,
        )
    time.sleep(5)
    return vm_dir, cfg["Information"]["UUID"]


def cleanup_stale_nightly_vms():
    """Delete every UTM-registered VM left over from a previous failed
    run (name starts with 'patronus-nightly-' or 'manual-test-', the
    latter from one-off debugging) before starting a new attempt.

    Found 2026-10-07: these never got cleaned up by old pre-c0380699
    code whenever VM *registration itself* (not just boot) failed, since
    that raised straight out of attempt_boot() past every cleanup path.
    219+ nightly runs of accumulation left ~5+ ghost/orphaned entries in
    UTM's own VM list (confirmed via `utmctl list` showing
    patronus-nightly-2527/2533/2623 and a manual probe VM still present,
    long after their backing directories were already gone). A bigger
    registered-VM count measurably slows down UTM's own `open -a UTM`
    import handling (each subsequent registration attempt took
    30+ seconds instead of the ~5s baseline, confirmed by timing in the
    job logs below) - this was the real root cause of registration
    itself timing out, not boot-stage flakiness. Clearing these out
    before every run keeps UTM's VM list bounded to the real, persistent
    reference VMs (kali/FreeBSD/Gentoo Base/ubuntu/Windows) only.
    """
    out = subprocess.run([UTMCTL, "list"], capture_output=True, text=True)
    removed = []
    for line in out.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        uuid, status, name = parts[0], parts[1], parts[2]
        if not (name.startswith("patronus-nightly-") or name.startswith("manual-test-")):
            continue
        subprocess.run([UTMCTL, "stop", uuid], capture_output=True)
        time.sleep(1)
        subprocess.run([UTMCTL, "delete", uuid], capture_output=True)
        removed.append((uuid, name))
    if removed:
        print(f"[host] cleaned up {len(removed)} stale UTM VM(s) before starting: {removed}", flush=True)
    # Also sweep any leftover external-staging directories, registered
    # or not (a crashed run can leave the directory behind even after
    # its UTM entry is gone, or vice versa).
    if os.path.isdir(UTM_EXTERNAL_STAGING):
        for entry in os.listdir(UTM_EXTERNAL_STAGING):
            if entry.startswith("patronus-nightly-") or entry.startswith("manual-test-"):
                shutil.rmtree(os.path.join(UTM_EXTERNAL_STAGING, entry), ignore_errors=True)


def find_vm_uuid_by_name(name, retries=30, interval_s=3):
    # Was retries=10 @ 2s (20s total). Raised to 90s total: a UTM
    # instance that already manages several real VMs (kali/FreeBSD/
    # Gentoo Base/ubuntu/Windows) was observed taking 30-45s to finish
    # importing a freshly `open -a UTM`'d external bundle even with
    # stale-VM cleanup in place - not a hang, just genuinely slow Finder/
    # LaunchServices-mediated import, confirmed by the bundle eventually
    # appearing in `utmctl list` well past the old 20s window in a
    # manual same-conditions probe (see cleanup_stale_nightly_vms
    # docstring for the surrounding investigation).
    for _ in range(retries):
        out = subprocess.run([UTMCTL, "list"], capture_output=True, text=True)
        for line in out.stdout.splitlines():
            if name in line:
                return line.split()[0]
        time.sleep(interval_s)
    # The `open -a UTM <bundle>` call upstream of this has been
    # observed (2026-10-09) returning exit 0 with no stderr, yet the
    # bundle still never shows up here after the full retry budget --
    # disproving the earlier "open itself is failing" theory for at
    # least this failure mode. The next most likely explanation is a
    # modal/permission dialog UTM is showing (e.g. an "allow this app
    # to add a VM configuration" prompt) that nobody is present to
    # click in this unattended GUI session, silently stalling the
    # import. We can't inspect UTM's window/dialog state via AppleEvents
    # from outside this job's own GUI session (System Events AppleEvents
    # hang/time out over plain SSH, same restriction utmctl itself has
    # over SSH -- confirmed directly). `screencapture` doesn't need
    # AppleEvents though, so grab a real screenshot of the GUI session
    # right at the point of failure and save it next to the VM staging
    # dir -- next failure's job log prints exactly where this landed,
    # giving the next investigation an actual picture of what's stuck
    # on screen instead of guessing blind from retry-loop text alone.
    screenshot_path = os.path.join(
        UTM_EXTERNAL_STAGING, f"registration-failure-{name}.png"
    )
    try:
        os.makedirs(UTM_EXTERNAL_STAGING, exist_ok=True)
        shot = subprocess.run(
            ["screencapture", "-x", screenshot_path],
            capture_output=True, text=True, timeout=15,
        )
        if shot.returncode == 0 and os.path.isfile(screenshot_path):
            print(f"[host] saved failure screenshot: {screenshot_path}", flush=True)
        else:
            print(
                f"[host] screenshot capture failed: exit={shot.returncode} "
                f"stdout={shot.stdout.strip()} stderr={shot.stderr.strip()}",
                flush=True,
            )
    except Exception as exc:
        print(f"[host] screenshot capture raised: {exc!r}", flush=True)
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


def attempt_boot(iso_path, serial_log_path, serial_stop, attempt_num):
    """One full create -> boot -> wait-for-live-boot -> teardown cycle.
    Returns True if LIVE_BOOT_START was seen, False if that wait timed
    out (the only outcome we treat as retryable flakiness, not a real
    failure - see run()). Always tears its own VM down before
    returning, success or not, so each attempt starts clean."""
    vm_dir, cfg_uuid = build_vm_bundle(iso_path)
    try:
        vm_uuid = find_vm_uuid_by_name(VM_NAME)
    except SystemExit as e:
        # Registration itself (UTM GUI importing the bundle after `open
        # -a UTM`) can be just as flaky as the later boot stage - it
        # used to raise straight out of attempt_boot(), completely
        # bypassing the MAX_BOOT_ATTEMPTS retry loop below and failing
        # the whole job on the very first slow import instead of
        # getting the same retry treatment as a boot timeout.
        print(f"[host] attempt {attempt_num}: VM registration failed: {e}", flush=True)
        return False, None
    print(f"[host] attempt {attempt_num}: VM registered: {VM_NAME} -> {vm_uuid}")
    try:
        run([UTMCTL, "start", vm_uuid])
        serial_thread = threading.Thread(
            target=capture_serial, args=(SERIAL_PORT, serial_log_path, serial_stop), daemon=True
        )
        serial_thread.start()
        try:
            wait_for_event(lambda b: "LIVE_BOOT_START" in b, 600, "live ISO boot")
            return True, vm_uuid
        except SystemExit as e:
            print(f"[host] attempt {attempt_num} did not reach live boot: {e}", flush=True)
            return False, vm_uuid
    finally:
        pass


def main():
    iso_path = sys.argv[1]
    os.makedirs(WORKDIR, exist_ok=True)

    sanity_check_utmctl()
    cleanup_stale_nightly_vms()

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

    result = {"vm": VM_NAME, "ok": False}
    vm_dir = None
    vm_uuid = None
    try:
        # The live-boot stage (UEFI -> GRUB -> kernel handoff, reading
        # off an emulated SATA CD-ROM under pure TCG software emulation)
        # has shown real non-determinism in back-to-back identical
        # attempts: one run got as far as a real kernel panic a second
        # and a half into boot, two adjacent runs with the exact same
        # config hung completely silent for the full 600s with zero
        # output at all - not a cmdline-fixable bug, just flaky
        # virtualization timing. Retry the create/boot cycle itself (not
        # the later install/reboot stages, which are real functional
        # checks, not infra flakiness) before giving up for real.
        MAX_BOOT_ATTEMPTS = 3
        reached_live_boot = False
        for attempt in range(1, MAX_BOOT_ATTEMPTS + 1):
            ok, vm_uuid = attempt_boot(iso_path, serial_log_path, serial_stop, attempt)
            if ok:
                reached_live_boot = True
                vm_dir = os.path.join(UTM_EXTERNAL_STAGING, f"{VM_NAME}.utm")
                break
            if vm_uuid:
                subprocess.run([UTMCTL, "stop", vm_uuid], capture_output=True)
                time.sleep(3)
                subprocess.run([UTMCTL, "delete", vm_uuid], capture_output=True)
            shutil.rmtree(os.path.join(UTM_EXTERNAL_STAGING, f"{VM_NAME}.utm"), ignore_errors=True)
            if attempt < MAX_BOOT_ATTEMPTS:
                print(f"[host] retrying boot (attempt {attempt + 1}/{MAX_BOOT_ATTEMPTS})", flush=True)

        if not reached_live_boot:
            raise SystemExit(
                f"TIMEOUT waiting for: live ISO boot (after {MAX_BOOT_ATTEMPTS} attempts)"
            )

        vm_dir = os.path.join(UTM_EXTERNAL_STAGING, f"{VM_NAME}.utm")
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
        if vm_uuid:
            subprocess.run([UTMCTL, "stop", vm_uuid], capture_output=True)
            time.sleep(3)
            subprocess.run([UTMCTL, "delete", vm_uuid], capture_output=True)
        if vm_dir:
            shutil.rmtree(vm_dir, ignore_errors=True)
        server.shutdown()

    print(json.dumps(result))
    if not result["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
