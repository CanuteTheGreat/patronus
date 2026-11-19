"""Patronus project layer: the Wi-Fi uplink (station-mode WAN, USE=wifi-client) needs wpa_supplicant in the image on
every arch and both inits, and the net-firewall/patronus ebuild ships its per-device service (patronus-wpa) for OpenRC
and systemd. The image's iwd (common package list) is kept off an uplink's radio by the product (wifi_client.rs)."""
import os
import platform
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.join(HERE, "..")
COMMON = os.path.join(PROJECT, "..", "common")
EBUILD_DIR = os.path.join(PROJECT, "..", "..", "net-firewall", "patronus")
PKG = "net-wireless/wpa_supplicant"


def pkglist(init):
    out = subprocess.run(["sh", os.path.join(COMMON, "pkglist.sh"), os.path.join(PROJECT, "packages.txt")],
                         capture_output=True, text=True, env={**os.environ, "INIT": init}, check=True).stdout
    return out.split()


class WifiUplink(unittest.TestCase):
    def test_wpa_supplicant_in_the_image_for_both_inits(self):
        txt = open(os.path.join(PROJECT, "packages.txt")).read().splitlines()
        self.assertIn(PKG, txt, "unconditional (every arch)")
        for init in ("openrc", "systemd"):
            self.assertIn(PKG, pkglist(init), f"{init} on {platform.machine()}")

    def test_ebuild_ships_the_uplink_service_for_both_inits(self):
        files = os.path.join(EBUILD_DIR, "files")
        unit = open(os.path.join(files, "patronus-wpa@.service")).read()
        initd = open(os.path.join(files, "patronus-wpa.initd")).read()
        self.assertIn("EnvironmentFile=/var/lib/patronus/net/svc/patronus-wpa.%i.env", unit)
        self.assertIn('ENVFILE="/var/lib/patronus/net/svc/patronus-wpa.${DEV}.env"', initd)
        self.assertTrue(initd.startswith("#!/sbin/openrc-run"))
        eb = open(os.path.join(EBUILD_DIR, "patronus-9999.ebuild")).read()
        self.assertIn('use wifi-client && systemd_dounit "${FILESDIR}/patronus-wpa@.service"', eb)
        self.assertIn('use wifi-client && newinitd "${FILESDIR}/patronus-wpa.initd" patronus-wpa', eb)
        self.assertIn("+wifi-client", eb, "on by default: the router tier carries the Wi-Fi uplink")
        self.assertIn("wifi-client? ( net-wireless/wpa_supplicant net-wireless/iw )", eb)


if __name__ == "__main__":
    unittest.main()
