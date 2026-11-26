"""Patronus project layer: S.M.A.R.T. disk health (USE=smart) needs smartctl in the image on every arch and both inits,
and the net-firewall/patronus ebuild turns the flag into the cargo feature, the web feature and the smartmontools
dependency (a flag that is not wired through installs a page that can never read a disk)."""
import os
import platform
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.join(HERE, "..")
COMMON = os.path.join(PROJECT, "..", "common")
EBUILD_DIR = os.path.join(PROJECT, "..", "..", "net-firewall", "patronus")
PKG = "sys-apps/smartmontools"


def pkglist(init):
    out = subprocess.run(["sh", os.path.join(COMMON, "pkglist.sh"), os.path.join(PROJECT, "packages.txt")],
                         capture_output=True, text=True, env={**os.environ, "INIT": init}, check=True).stdout
    return out.split()


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class Smart(unittest.TestCase):
    def test_smartmontools_in_the_image_for_both_inits(self):
        txt = _read(os.path.join(PROJECT, "packages.txt")).splitlines()
        self.assertIn(PKG, txt, "unconditional (every arch)")
        for init in ("openrc", "systemd"):
            self.assertIn(PKG, pkglist(init), f"{init} on {platform.machine()}")

    def test_ebuild_wires_the_flag_through(self):
        eb = _read(os.path.join(EBUILD_DIR, "patronus-9999.ebuild"))
        self.assertIn("+smart", eb, "on by default: a disk-health page is the point of an appliance")
        self.assertIn("smart? ( sys-apps/smartmontools )", eb)
        self.assertIn('$(usex smart "smart" "")', eb, "cargo feature")
        self.assertIn("use smart && webfeatures+=( smart )", eb, "web feature")
        self.assertIn('flag name="smart"', _read(os.path.join(EBUILD_DIR, "metadata.xml")))

    def test_the_poller_runs_as_the_generic_daemon_unit(self):
        # no new unit: `patronus smart run` is a patronus-daemon@smart instance, present for both inits
        files = os.path.join(EBUILD_DIR, "files")
        self.assertTrue(os.path.exists(os.path.join(files, "patronus-daemon@.service")))
        self.assertTrue(os.path.exists(os.path.join(files, "patronus-daemon.initd")))


if __name__ == "__main__":
    unittest.main()
