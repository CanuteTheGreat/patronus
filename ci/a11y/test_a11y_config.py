"""Self-test of the accessibility gate's inputs: pinned axe-core, page list, allowlist hygiene."""
import hashlib
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, "a11y-config.json")))
ALLOW = json.load(open(os.path.join(HERE, CFG["allowlist"])))["entries"]


class A11yConfig(unittest.TestCase):
    def test_axe_is_vendored_and_pinned(self):
        src = open(os.path.join(HERE, CFG["axe_file"]), "rb").read()
        self.assertEqual(hashlib.sha256(src).hexdigest(), CFG["axe_sha256"])
        self.assertIn(CFG["axe_version"].encode(), src[:400])
        self.assertTrue(os.path.exists(os.path.join(HERE, "vendor", "LICENSE")))

    def test_ten_pages_both_widths_both_schemes(self):
        ids = [p["id"] for p in CFG["pages"]]
        self.assertGreaterEqual(len(ids), 10)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sorted(CFG["viewports"]), ["desktop", "phone"])
        self.assertEqual(sorted(CFG["schemes"]), ["dark", "light"])
        self.assertEqual(CFG["viewports"]["desktop"][0], 1280)
        self.assertEqual(CFG["viewports"]["phone"][0], 390)

    def test_threshold_blocks_serious_and_critical(self):
        self.assertTrue({"serious", "critical"} <= set(CFG["fail_impacts"]))

    def test_optional_pages_name_an_ebuild_use_flag_that_is_off_by_default(self):
        # "feature" lets the gate skip a page the build does not serve: only for USE flags that are NOT "+"-default,
        # so a default page can never be skipped silently.
        eb = open(os.path.join(HERE, "..", "..", "gentoo", "net-firewall", "patronus", "patronus-9999.ebuild")).read()
        m = re.search(r'^IUSE="([^"]*)"', eb, re.M)
        self.assertIsNotNone(m)
        flags = m.group(1).split()
        for p in CFG["pages"]:
            if "feature" in p:
                self.assertIn(p["feature"], flags, p)
                self.assertNotIn("+" + p["feature"], flags, p)

    def test_allowlist_entries_are_justified(self):
        known = {p["id"] for p in CFG["pages"]} | {"*"}
        for e in ALLOW:
            self.assertTrue(e.get("rule") and e.get("reason") and len(e["reason"]) > 30, e)
            self.assertIn(e.get("page"), known, e)


if __name__ == "__main__":
    unittest.main()
