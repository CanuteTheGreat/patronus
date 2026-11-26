"""Patronus console-menu items, interface-role sync and update channel (installer profile), checked against the real
profile.toml, the vendored installer (common/) and the CLI they call."""
import os, re, sys, tomllib, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LI = os.path.join(HERE, "..", "..", "common", "overlay", "usr", "lib", "live-installer")
sys.path.insert(0, LI)
from liveinst import consolemenu as CM, updchan  # noqa: E402

ROOT = os.path.join(HERE, "..", "..", "..", "..")
PROFILE = tomllib.load(open(os.path.join(HERE, "..", "overlay", "etc", "live-installer", "profile.toml"), "rb"))
CLI_MAIN = open(os.path.join(ROOT, "crates", "patronus-cli", "src", "main.rs")).read()
SHIPPED_TOML = open(os.path.join(ROOT, "gentoo", "net-firewall", "patronus", "files", "patronus.toml")).read()

# `patronus <sub> <action>` -> the clap variant that must exist in main.rs (kebab-case of the Rust names)
CLI = {("firewall", "log"): r"enum FirewallCommands \{.*?\bLog \{", ("update", "channel"): r"enum UpdateCommands \{.*?\bChannel \{",
       ("update", "check"): r"enum UpdateCommands \{.*?\bCheck \{", ("update", "status"): r"enum UpdateCommands \{.*?\bStatus,",
       ("update", "apply"): r"enum UpdateCommands \{.*?\bApply \{", ("config", "revisions"): r"enum ConfigCommands \{.*?\bRevisions,",
       ("config", "rollback"): r"enum ConfigCommands \{.*?\bRollback \{", ("import", "pfsense"): r"enum ImportWhat \{.*?\bPfsense \{",
       ("interfaces", "assign"): r"enum InterfacesCommands \{.*?\bAssign \{", ("apply",): r"enum Commands \{.*?\n    Apply \{"}


def argvs(it):
    return [it["run"]] + ([it["show"]] if "show" in it else []) + CM.then_list(it)


class PatronusConsole(unittest.TestCase):
    def test_items_parse_and_follow_the_built_in_ones(self):
        items, bad = CM.console_items(PROFILE, [k for k, _ in CM.Console.MENU])
        self.assertEqual(bad, [])
        self.assertEqual([i["key"] for i in items], [str(n) for n in range(15, 21)])

    def test_every_item_calls_an_existing_cli_command(self):
        items, _ = CM.console_items(PROFILE, [k for k, _ in CM.Console.MENU])
        seen = set()
        for it in items:
            for a in argvs(it):
                if a[0] != "patronus":
                    continue
                key = tuple(a[1:3]) if len(a) > 2 and not a[2].startswith("-") else (a[1],)
                self.assertIn(key, CLI, f"{it['title']}: {a}")
                self.assertRegex(CLI_MAIN, re.compile(CLI[key], re.S), f"no `patronus {' '.join(key)}` in the CLI")
                seen.add(key)
        for want in (("firewall", "log"), ("update", "channel"), ("update", "apply"), ("config", "rollback"), ("import", "pfsense")):
            self.assertIn(want, seen)

    def test_roles_sync_command_exists(self):
        argv = PROFILE["roles_sync_cmd"]
        self.assertEqual(argv[:3], ["patronus", "interfaces", "assign"])
        self.assertRegex(CLI_MAIN, re.compile(CLI[("interfaces", "assign")], re.S))
        self.assertIn("from_bootstrap: bool", CLI_MAIN)
        self.assertIn("--from-bootstrap", argv)

    def test_answer_is_one_argument(self):
        items, _ = CM.console_items(PROFILE, [k for k, _ in CM.Console.MENU])
        imp = next(i for i in items if i["key"] == "20")
        self.assertEqual(CM.fill_argv(imp["run"], "/mnt/a b;reboot"), ["patronus", "import", "pfsense", "/mnt/a b;reboot", "--plan"])

    def test_update_channel_written_into_the_shipped_file(self):
        self.assertTrue(updchan.enabled(PROFILE))
        self.assertEqual(updchan.default(PROFILE), "stable")
        self.assertEqual(PROFILE["update_channel_file"], "/etc/patronus/patronus.toml")
        for ch in PROFILE["update_channels"]:
            self.assertRegex(CLI_MAIN + open(os.path.join(ROOT, "crates", "patronus-cli", "src", "commands", "update.rs")).read(),
                             "stable, testing or development")
            t = updchan.apply_toml(SHIPPED_TOML, ch)
            d = tomllib.loads(t)
            self.assertEqual(d["update"]["channel"], ch)
            self.assertEqual(d["network"], tomllib.loads(SHIPPED_TOML)["network"])     # the rest of the file is untouched
        self.assertEqual(set(PROFILE["update_channel_info"]), set(PROFILE["update_channels"]))

    def test_opt_interfaces_key_is_read_by_the_product(self):
        t = CM.apply_roles(SHIPPED_TOML, "eth0", "eth1", ["eth2", "eth3"])
        self.assertEqual(tomllib.loads(t)["network"]["opt_interfaces"], ["eth2", "eth3"])
        defaults_rs = open(os.path.join(ROOT, "crates", "patronus-config", "src", "defaults.rs")).read()
        self.assertIn("opt_interfaces: Vec<String>", defaults_rs)


if __name__ == "__main__":
    unittest.main()
