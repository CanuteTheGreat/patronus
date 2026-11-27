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

    def test_allowlist_entries_are_justified(self):
        known = {p["id"] for p in CFG["pages"]} | {"*"}
        for e in ALLOW:
            self.assertTrue(e.get("rule") and e.get("reason") and len(e["reason"]) > 30, e)
            self.assertIn(e.get("page"), known, e)

    def test_feature_pages_are_built_into_the_gate_image(self):
        # The gate runs against the Gentoo Docker image built with rust-ci.yml's
        # USE_ALL; a page whose USE flag is missing there is a 404 ("page did not render").
        wf = open(os.path.join(HERE, "..", "..", ".forgejo", "workflows", "rust-ci.yml")).read()
        m = re.search(r'USE_ALL="([^"]*)"', wf)
        self.assertIsNotNone(m, "USE_ALL not found in rust-ci.yml")
        use_all = set(m.group(1).split())
        for p in CFG["pages"]:
            if p["path"].startswith("/svc/"):
                self.assertIn("use", p, f"feature page {p['id']} must name its USE flag")
            if "use" in p:
                self.assertIn(p["use"], use_all, f"page {p['id']} needs USE={p['use']} in rust-ci.yml USE_ALL")


if __name__ == "__main__":
    unittest.main()
