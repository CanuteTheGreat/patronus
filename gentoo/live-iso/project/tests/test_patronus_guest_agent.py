"""Patronus project layer: app-emulation/qemu-guest-agent is in the x86_64/aarch64 package set and is enabled only
inside KVM/QEMU guests (virtio port org.qemu.guest_agent.0), on OpenRC and systemd."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.join(HERE, "..")
COMMON = os.path.join(PROJECT, "..", "common")
SCRIPT = os.path.join(PROJECT, "overlay/usr/libexec/patronus-qga-enable")
PKG = "app-emulation/qemu-guest-agent"


def pkglist(arch, init="openrc"):
    out = subprocess.run(["sh", os.path.join(COMMON, "pkglist.sh"), os.path.join(PROJECT, "packages.txt")],
                         capture_output=True, text=True, env={**os.environ, "INIT": init},
                         check=True).stdout
    return out.split()


def run(init, sysfs, devdir):
    env = {**os.environ, "PATRONUS_SYSFS": sysfs, "PATRONUS_DEVDIR": devdir, "PATRONUS_INIT": init, "PATRONUS_DRYRUN": "1"}
    return subprocess.run(["sh", SCRIPT], capture_output=True, text=True, env=env, check=True).stdout


class GuestAgent(unittest.TestCase):
    def test_package_atom_listed_for_both_arches(self):
        txt = open(os.path.join(PROJECT, "packages.txt")).read().splitlines()
        self.assertIn("x86_64? " + PKG, txt)
        self.assertIn("aarch64? " + PKG, txt)
        # pkglist.sh keeps the atom only on those arches (this runner's arch is one of them or riscv64)
        import platform
        has = PKG in pkglist(platform.machine())
        self.assertEqual(has, platform.machine() in ("x86_64", "aarch64"))

    def test_nothing_enabled_without_the_agent_port(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "class/virtio-ports/vport0p1"))
        open(os.path.join(d, "class/virtio-ports/vport0p1/name"), "w").write("com.example.other\n")
        for init in ("openrc", "systemd"):
            self.assertEqual(run(init, d, os.path.join(d, "dev")), "")
        self.assertEqual(run("openrc", os.path.join(d, "nosuch"), os.path.join(d, "dev")), "")

    def test_enabled_on_openrc_and_systemd_when_the_port_exists(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "class/virtio-ports/vport1p1"))
        open(os.path.join(d, "class/virtio-ports/vport1p1/name"), "w").write("org.qemu.guest_agent.0\n")
        self.assertEqual(run("systemd", d, os.path.join(d, "dev")), "systemctl enable --now qemu-guest-agent.service\n")
        self.assertEqual(run("openrc", d, os.path.join(d, "dev")),
                         "rc-update add qemu-guest-agent default\nrc-service qemu-guest-agent start\n")

    def test_devnode_alone_is_enough(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "dev/virtio-ports"))
        open(os.path.join(d, "dev/virtio-ports/org.qemu.guest_agent.0"), "w").close()
        self.assertIn("qemu-guest-agent", run("openrc", os.path.join(d, "none"), os.path.join(d, "dev")))

    def test_boot_hooks_exist_for_both_inits(self):
        ov = os.path.join(PROJECT, "overlay")
        self.assertTrue(os.access(os.path.join(ov, "etc/local.d/60-patronus-qga.start"), os.X_OK))
        unit = os.path.join(ov, "usr/lib/systemd/system/patronus-qga.service")
        self.assertIn("ConditionVirtualization=vm", open(unit).read())
        self.assertTrue(os.path.islink(os.path.join(ov, "usr/lib/systemd/system/multi-user.target.wants/patronus-qga.service")))


if __name__ == "__main__":
    unittest.main()
