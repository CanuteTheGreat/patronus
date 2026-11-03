"""Patronus installer filesystem/encryption policy (owner rules 2026-10-29 + 2026-11-03), checked against the real profile.toml
and the vendored installer (common/)."""
import os, sys, tomllib, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LI = os.path.join(HERE, "..", "..", "common", "overlay", "usr", "lib", "live-installer")
sys.path.insert(0, LI)
from liveinst import hwprofile, system, tpmunlock  # noqa: E402

PROFILE = tomllib.load(open(os.path.join(HERE, "..", "overlay", "etc", "live-installer", "profile.toml"), "rb"))
PROFILE.setdefault("default_hostname", "patronus.localdomain")


class PatronusFs(unittest.TestCase):
    def test_zfs_offered_first_ext4_last(self):
        self.assertEqual(PROFILE["filesystems"][0], "zfs")
        self.assertEqual(PROFILE["filesystems"][-1], "ext4")

    def test_no_prompt_variants(self):
        self.assertNotIn("xfs-luks", PROFILE["filesystems"])
        self.assertEqual(PROFILE["encryption"], "tpm-or-none")

    def test_no_ondisk_swap(self):
        self.assertFalse(PROFILE["portable_swap"])
        self.assertEqual(PROFILE["swap_mb"], 0)

    def test_default_matrix(self):
        f = PROFILE["filesystems"]
        for ram, zfs_ok, want in ((16384, True, "zfs"), (8192, True, "zfs"), (4096, True, "xfs"), (2048, True, "xfs"), (16384, False, "xfs"), (4096, False, "xfs")):
            self.assertEqual(hwprofile.choose_fs(f, ram, None, zfs_ok)[0], want, (ram, zfs_ok))

    def test_ext4_never_default(self):
        for ram in (512, 2048, 4096, 8192, 32768):
            for ok in (True, False):
                self.assertNotEqual(hwprofile.choose_fs(PROFILE["filesystems"], ram, None, ok)[0], "ext4")

    def test_encryption_decision(self):
        c = {"fs": "zfs"}
        system.apply_encryption_policy(PROFILE, c, (True, "tpm ok"))
        self.assertEqual((c["zfs_encrypt"], c["zfs_keymode"], c["zfs_passphrase"]), (True, "tpm", ""))
        system.apply_encryption_policy(PROFILE, c, (False, "no TPM 2.0 device"))
        self.assertFalse(c["zfs_encrypt"])
        self.assertIn("NOT encrypted", c["enc_why"])

    def test_answer_file_passphrase_rejected(self):
        c = {"fs": "zfs", "enc_passphrase_given": True, "disks": ["/dev/vda"], "zfs_raid": "single"}
        base = system.default_config(PROFILE)
        base.update(c)
        errs = system.validate_config(PROFILE, base, unattended=True, require_secret=False)
        self.assertTrue([e for e in errs if "never asks for a disk passphrase" in e], errs)


if __name__ == "__main__":
    unittest.main()
