#!/usr/bin/env python3
"""hwprofile.py: the data-driven per-device hardware profile tool (docs/hardware-support.md).

  hwprofile.py env <profile.toml>        shell assignments (HW_*) for build/assemble scripts: eval "$(hwprofile.py env P)"
  hwprofile.py get <profile.toml> <key>  one value, key = section.key (e.g. device.openwrt_board)
  hwprofile.py validate [profile.toml..] schema + tier-minimum + duplicate checks (default: every profiles/hw/*.toml)
  hwprofile.py list [--json]             one row per device with its status level (feeds the downloads page)
  hwprofile.py matrix [--status L,..]    JSON build matrix for CI (one entry per device; filter by status level)
  hwprofile.py gen <profiles.json> <board-id> [--out DIR]
                                         skeleton profile from OpenWrt's per-target profiles.json (status untested)

Python 3, standard library only. tomllib is used when present (3.11+); older interpreters (the CI images) use a small
built-in parser for the TOML subset the profiles use (tables, strings, ints, bools, one-line arrays and inline tables).
"""
import json
import os
import re
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PROFILES = os.path.join(ROOT, "profiles")
LEVELS = ("tested", "builds", "untested")


def _scalar(s):
    s = s.strip()
    if s.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"$', s)
        if not m:
            raise ValueError("bad string: " + s)
        return json.loads('"' + m.group(1) + '"')
    if s in ("true", "false"):
        return s == "true"
    if re.match(r"^[+-]?\d[\d_]*$", s):
        return int(s.replace("_", ""))
    if re.match(r"^[+-]?\d[\d_]*\.\d+$", s):
        return float(s.replace("_", ""))
    raise ValueError("unsupported TOML value: " + s)


def _split_top(s):
    """split on commas that are outside quotes/brackets"""
    out, depth, q, cur, i = [], 0, False, "", 0
    while i < len(s):
        c = s[i]
        if q:
            cur += c
            if c == "\\":
                cur += s[i + 1]
                i += 1
            elif c == '"':
                q = False
        elif c == '"':
            q = True
            cur += c
        elif c in "[{":
            depth += 1
            cur += c
        elif c in "]}":
            depth -= 1
            cur += c
        elif c == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        out.append(cur)
    return out


def _value(s):
    s = s.strip()
    if s.startswith("["):
        return [_value(x) for x in _split_top(s[1:-1])]
    if s.startswith("{"):
        d = {}
        for part in _split_top(s[1:-1]):
            k, v = part.split("=", 1)
            d[k.strip()] = _value(v)
        return d
    return _scalar(s)


def _strip_comment(line):
    q = False
    for i, c in enumerate(line):
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            q = not q
        elif c == "#" and not q:
            return line[:i]
    return line


def mini_toml(text):
    root, cur = {}, None
    cur = root
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        m = re.match(r"^\[([A-Za-z0-9_.\-]+)\]$", line)
        if m:
            cur = root
            for part in m.group(1).split("."):
                cur = cur.setdefault(part, {})
            continue
        if "=" not in line:
            raise ValueError("line %d: cannot parse: %s" % (n, raw))
        k, v = line.split("=", 1)
        cur[k.strip()] = _value(v)
    return root


def load_toml(path):
    with open(path, "rb") as f:
        raw = f.read()
    if not os.environ.get("HWPROFILE_NO_TOMLLIB"):
        try:
            import tomllib
            return tomllib.loads(raw.decode())
        except ImportError:
            pass
    return mini_toml(raw.decode())


def load_profile(path):
    p = load_toml(path)
    p["_path"] = path
    return p


def tiers():
    return load_toml(os.path.join(PROFILES, "tiers.toml"))["tier"]


def archs():
    return load_toml(os.path.join(PROFILES, "arch.toml"))["arch"]


def all_profiles():
    d = os.path.join(PROFILES, "hw")
    return [load_profile(os.path.join(d, f)) for f in sorted(os.listdir(d)) if f.endswith(".toml")]


def derived(p):
    """values computed from the profile + arch table, so scripts never rebuild a name by hand"""
    dev, ow = p.get("device", {}), p.get("openwrt", {})
    board = dev.get("openwrt_board", "")
    board_id = board.replace(",", "_")
    d = {"board_id": board_id, "sysupgrade_dir": "sysupgrade-" + board_id}
    if ow.get("release") and ow.get("target") and ow.get("subtarget"):
        d["stock_sysupgrade"] = "openwrt-%s-%s-%s-%s-squashfs-sysupgrade.bin" % (
            ow["release"], ow["target"], ow["subtarget"], board_id)
        d["kernel_label"] = "OpenWrt %s %s/%s" % (ow["release"], ow["target"], ow["subtarget"])
    a = archs().get(ow.get("arch_packages", ""), {})
    for k, v in a.items():
        d["arch_" + k] = v
    return d


def fmt(v):
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v)


def flatten(p):
    out = {}

    def walk(prefix, d):
        for k, v in d.items():
            if k.startswith("_"):
                continue
            key = (prefix + "_" if prefix else "") + re.sub(r"[^A-Za-z0-9]", "_", k)
            if isinstance(v, dict):
                walk(key, v)
            else:
                out[key] = fmt(v)

    walk("", p)
    for k, v in derived(p).items():
        out[k] = fmt(v)
    return {"HW_" + k.upper(): v for k, v in out.items()}


def validate_one(p, seen):
    errs, path = [], os.path.basename(p["_path"])
    T = tiers()
    dev, st, ow = p.get("device", {}), p.get("status", {}), p.get("openwrt", {})
    for k in ("id", "vendor", "model", "openwrt_board"):
        if not dev.get(k):
            errs.append("device.%s is required" % k)
    for k in ("target", "subtarget", "release", "arch_packages"):
        if not ow.get(k):
            errs.append("openwrt.%s is required" % k)
    if dev.get("id"):
        if dev["id"] in seen:
            errs.append("device.id %r also used by %s" % (dev["id"], seen[dev["id"]]))
        seen[dev["id"]] = path
    if ow.get("target") and not path.startswith(ow["target"] + "-"):
        errs.append("file name must start with the OpenWrt target (%s-...)" % ow["target"])
    if ow.get("arch_packages") and ow["arch_packages"] not in archs():
        errs.append("openwrt.arch_packages %r is not in profiles/arch.toml" % ow["arch_packages"])
    if st.get("level") not in LEVELS:
        errs.append("status.level must be one of %s" % "/".join(LEVELS))
    tier = p.get("tier")
    if tier not in T:
        errs.append("tier must be one of %s" % "/".join(T))
    else:
        for key, field in (("ram_mb", "min_ram_mb"), ("flash_mb", "min_flash_mb")):
            if not isinstance(p.get(key), int) or p[key] <= 0:
                errs.append("%s must be a positive integer" % key)
            elif p[key] < T[tier][field]:
                errs.append("%s=%s is below the %s tier minimum %s" % (key, p[key], tier, T[tier][field]))
        a = archs().get(ow.get("arch_packages", ""), {})
        if a and a.get("patronus_arch") not in T[tier]["arch"]:
            errs.append("arch %s is not allowed on the %s tier (%s)" % (a.get("patronus_arch"), tier, T[tier]["arch"]))
    if st.get("level") == "tested" and not st.get("evidence"):
        errs.append("status.level=tested needs status.evidence (what was run on real hardware)")
    if "nor" in p:
        for k in ("firmware_kib", "data_min_kib", "margin_kib"):
            if not isinstance(p["nor"].get(k), int):
                errs.append("nor.%s must be an integer" % k)
    return ["%s: %s" % (path, e) for e in errs]


def cmd_validate(args):
    ps = [load_profile(a) for a in args] if args else all_profiles()
    seen, errs = {}, []
    for p in ps:
        errs += validate_one(p, seen)
    for e in errs:
        print("FAIL " + e)
    print("%d profile(s), %d error(s)" % (len(ps), len(errs)))
    return 1 if errs else 0


def row(p):
    d, o, s = p["device"], p["openwrt"], p["status"]
    return {"id": d["id"], "vendor": d["vendor"], "model": d["model"], "variant": d.get("variant", ""),
            "tier": p["tier"], "target": "%s/%s" % (o["target"], o["subtarget"]), "arch": derived(p).get("arch_patronus_arch"),
            "ram_mb": p["ram_mb"], "flash_mb": p["flash_mb"], "status": s["level"], "init": p.get("init", [])}


def cmd_list(args):
    rows = [row(p) for p in all_profiles()]
    if "--json" in args:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            print("%-10s %-9s %-22s %-28s %4dMB/%4dMB %s" % (r["status"], r["tier"], r["target"], r["vendor"] + " " + r["model"],
                                                           r["ram_mb"], r["flash_mb"], ",".join(r["init"])))
    return 0


def cmd_matrix(args):
    want = None
    if "--status" in args:
        want = args[args.index("--status") + 1].split(",")
    m = []
    for p in all_profiles():
        if want and p["status"]["level"] not in want:
            continue
        r = row(p)
        d = derived(p)
        for init in p.get("init", ["openrc", "systemd"]):
            m.append({"device": r["id"], "profile": os.path.relpath(p["_path"], ROOT), "tier": r["tier"],
                      "arch_group": p["openwrt"]["arch_packages"], "rust_target": d.get("arch_rust_target"),
                      "init": init})
    print(json.dumps({"include": m}))
    return 0


def cmd_env(args):
    for k, v in sorted(flatten(load_profile(args[0])).items()):
        print("%s=%s" % (k, shlex.quote(v)))
    return 0


def cmd_get(args):
    p = load_profile(args[0])
    cur = p
    for part in args[1].split("."):
        cur = cur[part]
    print(" ".join(map(str, cur)) if isinstance(cur, list) else cur)
    return 0


def cmd_gen(args):
    src, board_id = args[0], args[1]
    out = args[args.index("--out") + 1] if "--out" in args else os.path.join(PROFILES, "hw")
    if re.match(r"^https?://", src):
        import urllib.request
        req = urllib.request.Request(src, headers={"User-Agent": "patronus-hwprofile/1.0"})
        d = json.load(urllib.request.urlopen(req, timeout=60))
    else:
        d = json.load(open(src))
    prof = d["profiles"][board_id]
    target, sub = d["target"].split("/")
    ap = d["arch_packages"]
    a = archs().get(ap)
    if not a:
        print("arch_packages %s is not in profiles/arch.toml: add it first (musl ld.so name, rust target)" % ap, file=sys.stderr)
        return 2
    title = prof["titles"][0]
    board = prof.get("supported_devices", [board_id.replace("_", ",", 1)])[0]
    model = title.get("model") or title.get("title", board_id)
    variant = title.get("variant", "")
    limits = prof.get("file_size_limits", {})
    sysu = [i for i in prof["images"] if i["type"] == "sysupgrade"]
    slug = re.sub(r"[^a-z0-9]+", "-", ("%s %s %s" % (title.get("vendor", ""), model, variant)).lower()).strip("-")
    name = "%s-%s.toml" % (target, slug)
    tier = a["default_tier"]
    lines = [
        '# GENERATED by ci/hw-profile/hwprofile.py gen from OpenWrt %s %s profiles.json. Fill in the TODO values from the' % (d["version_number"], d["target"]),
        '# OpenWrt Table of Hardware / the device data sheet, then raise status.level only with real evidence.',
        'schema = 1',
        'tier = "%s"' % tier,
        'ram_mb = %d   # TODO: confirm (OpenWrt ToH); placeholder is the tier minimum' % tiers()[tier]["min_ram_mb"],
        'flash_mb = %d   # TODO: confirm; placeholder is the tier minimum' % tiers()[tier]["min_flash_mb"],
        'init = ["openrc", "systemd"]',
        '',
        '[device]',
        'id = "%s"' % re.sub(r"[^a-z0-9]+", "-", board_id.lower()),
        'vendor = %s' % json.dumps(title.get("vendor", "")),
        'model = %s' % json.dumps(model),
        'variant = %s' % json.dumps(variant),
        'openwrt_board = %s' % json.dumps(board),
        'hostname = "patronus"',
        '',
        '[openwrt]',
        'release = "%s"' % d["version_number"],
        'target = "%s"' % target,
        'subtarget = "%s"' % sub,
        'arch_packages = "%s"' % ap,
        'kernel = "%s"' % d.get("linux_kernel", {}).get("version", ""),
    ]
    if sysu:
        lines.append('stock_sha256 = "%s"' % sysu[0]["sha256"])
    if limits:
        lines += ['', '# from OpenWrt file_size_limits (bytes): the image/kernel partition budgets of this board',
                  '[limits]'] + ['%s_bytes = %d' % (k, v) for k, v in sorted(limits.items())]
    lines += ['', '[status]', 'level = "untested"', 'evidence = ""', '']
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, name)
    if os.path.exists(path):
        print("refusing to overwrite " + path, file=sys.stderr)
        return 2
    open(path, "w").write("\n".join(lines))
    print(path)
    return 0


def main(argv):
    cmds = {"env": cmd_env, "get": cmd_get, "validate": cmd_validate, "list": cmd_list, "matrix": cmd_matrix, "gen": cmd_gen}
    if len(argv) < 2 or argv[1] not in cmds:
        print(__doc__)
        return 2
    return cmds[argv[1]](argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
