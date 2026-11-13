"""Patronus' installed-system os-release (written by the vendored live-iso common/setup-rootfs.sh) passes the installed-system rules.
Owner 2026-11-12 found live/installer wording and the private Forgejo URL on an installed system; Patronus shared that script and
lagged behind the Horcrux master (fixed by sync-common.sh --from). This keeps it from regressing or lagging again."""
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SETUP = os.path.join(HERE, "..", "..", "gentoo", "live-iso", "common", "setup-rootfs.sh")
sys.path.insert(0, HERE)
import check_os_release as osr  # noqa: E402


class PatronusOsRelease(unittest.TestCase):
    def render(self):
        m = re.search(r"cat > /usr/lib/os-release <<OSR\n(.*?)\nOSR\n", open(SETUP).read(), re.S)
        assert m, "os-release heredoc not found in setup-rootfs.sh"
        return subprocess.run(["bash", "-c", "PROJECT=patronus PROJECT_TITLE=Patronus; cat <<OSR\n" + m.group(1) + "\nOSR"], capture_output=True, text=True, check=True).stdout

    def test_clean(self):
        self.assertEqual(osr.check(self.render(), product="patronus", need_version=False), [])

    def test_old_text_is_caught(self):
        old = 'NAME="Patronus"\nID=patronus\nPRETTY_NAME="Patronus (Gentoo-based live/installer)"\nHOME_URL="https://git.canutethegreat.com/CanuteTheGreat/patronus"\n'
        self.assertTrue(osr.check(old, product="patronus", need_version=False))


if __name__ == "__main__":
    unittest.main()
