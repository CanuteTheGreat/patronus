#!/usr/bin/env python3
"""publish-pins.py: upload the artefacts of build-owrt.sh to Forgejo generic packages and move the embedded tier's pins to them.

  publish-pins.py --version 6.12.118-1 --ax1800 <out>/bin/qualcommax/ipq60xx [--virt <out>/bin/armsr/armv8] [--wifi-tar FILE] [--no-upload]

Packages (anonymous download, token only for upload; FORGEJO_TOKEN from the env or ~/.hermes/state/forgejo.env):
  patronus-owrt-kernel-ax1800/<version>/  sysupgrade.bin, SDK tar, the kmod apks of the board closure (names `<pkg>-<kver>-r1.apk`)
  patronus-owrt-kernel-virt/<version>/    armsr kernel .bin, the kmod apks of the virt closure
  patronus-wifi-kmods/<tag>/              the rebuilt Wi-Fi modules tar (build-kmods.sh)
Pins rewritten in place: ci/embedded-aarch64/ax1800/{stock.pin,kmods.pin,wifi-kmods/sdk.pin,wifi-kmods/wifi-kmods.pin}. The kmod closure per
target is the set of names already pinned in kmods.pin (a changed closure fails loudly: a name missing from the build output).
"""
import argparse, hashlib, os, re, sys, urllib.error, urllib.request

BASE = "https://git.canutethegreat.com/api/packages/CanuteTheGreat/generic"
HERE = os.path.dirname(os.path.abspath(__file__))
PIN = os.path.join(HERE, "..", "embedded-aarch64", "ax1800")
REL = re.search(r"^OWRT_REL=(.+)$", open(os.path.join(PIN, "stock.pin")).read(), re.M).group(1)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def token():
    t = os.environ.get("FORGEJO_TOKEN")
    if t:
        return t
    for line in open(os.path.expanduser("~/.hermes/state/forgejo.env")):
        m = re.match(r"(?:export )?FORGEJO_TOKEN=['\"]?([^'\"\r\n]+)", line)
        if m:
            return m.group(1)
    sys.exit("no FORGEJO_TOKEN")


def upload(pkg, ver, path, name, do):
    url = "%s/%s/%s/%s" % (BASE, pkg, ver, name)
    if do:
        req = urllib.request.Request(url, data=open(path, "rb").read(), method="PUT",
                                     headers={"Authorization": "token " + token(), "User-Agent": "hermes-scripts/1.0", "Content-Type": "application/octet-stream"})
        try:
            urllib.request.urlopen(req, timeout=600).read()
        except urllib.error.HTTPError as e:
            if e.code != 409:   # already there: generic packages are immutable per version
                raise
        # prove the anonymous download is the same file
        r = urllib.request.Request(url, headers={"User-Agent": "hermes-scripts/1.0"})
        h = hashlib.sha256()
        with urllib.request.urlopen(r, timeout=600) as resp:
            for b in iter(lambda: resp.read(1 << 20), b""):
                h.update(b)
        if h.hexdigest() != sha(path):
            sys.exit("upload check failed for " + url)
    return url


def rewrite(path, subs):
    s = open(path).read()
    for pat, rep in subs:
        s, n = re.subn(pat, rep, s, flags=re.M)
        if n == 0:
            sys.exit("pin %s: no match for %s" % (path, pat))
    open(path, "w").write(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--ax1800")
    ap.add_argument("--virt")
    ap.add_argument("--wifi-tar")
    ap.add_argument("--no-upload", action="store_true")
    a = ap.parse_args()
    up = not a.no_upload
    kp = open(os.path.join(PIN, "kmods.pin")).read()
    kver = a.version.rsplit("-", 1)[0]
    new_kmod_lines = []
    base = {}
    for tgt, d, pkg in (("board", a.ax1800, "patronus-owrt-kernel-ax1800"), ("virt", a.virt, "patronus-owrt-kernel-virt")):
        if not d:
            for l in kp.splitlines():
                if l.startswith(tgt + " "):
                    new_kmod_lines.append(l)
            continue
        names = [l.split()[1] for l in kp.splitlines() if l.startswith(tgt + " ")]
        for n in names:
            f = os.path.join(d, "packages", "%s-%s-r1.apk" % (n, kver))
            if not os.path.exists(f):
                sys.exit("closure member %s missing in %s" % (n, d))
            upload(pkg, a.version, f, os.path.basename(f), up)
            new_kmod_lines.append("%s %s %s" % (tgt, n, sha(f)))
        base[tgt] = "%s/%s/%s" % (BASE, pkg, a.version)
    # stock.pin
    st = []
    if a.ax1800:
        sy = [f for f in os.listdir(a.ax1800) if f.endswith("glinet_gl-ax1800-squashfs-sysupgrade.bin")][0]
        nm = "openwrt-%s-qualcommax-ipq60xx-glinet_gl-ax1800-squashfs-sysupgrade.bin" % REL   # same file name as OpenWrt's own (ci/hw-profile derives it); the content is our rebuild, the package version carries the kernel
        u = upload("patronus-owrt-kernel-ax1800", a.version, os.path.join(a.ax1800, sy), nm, up)
        st += [(r"^OWRT_SYSUPGRADE=.*", "OWRT_SYSUPGRADE=" + nm), (r"^OWRT_SYSUPGRADE_URL=.*", "OWRT_SYSUPGRADE_URL=" + u),
               (r"^OWRT_SYSUPGRADE_SHA256=.*", "OWRT_SYSUPGRADE_SHA256=" + sha(os.path.join(a.ax1800, sy)))]
        sdk = [f for f in os.listdir(a.ax1800) if f.startswith("openwrt-sdk-")][0]
        su = upload("patronus-owrt-kernel-ax1800", a.version, os.path.join(a.ax1800, sdk), sdk, up)
        rewrite(os.path.join(PIN, "wifi-kmods", "sdk.pin"), [(r"^SDK_URL=.*", "SDK_URL=" + su), (r"^SDK_SHA256=.*", "SDK_SHA256=" + sha(os.path.join(a.ax1800, sdk)))])
    if a.virt:
        kb = [f for f in os.listdir(a.virt) if f.endswith("generic-kernel.bin")][0]
        nm = "openwrt-%s-armsr-armv8-generic-kernel.bin" % REL
        u = upload("patronus-owrt-kernel-virt", a.version, os.path.join(a.virt, kb), nm, up)
        st += [(r"^OWRT_VIRT_KERNEL=.*", "OWRT_VIRT_KERNEL=" + nm), (r"^OWRT_VIRT_KERNEL_URL=.*", "OWRT_VIRT_KERNEL_URL=" + u),
               (r"^OWRT_VIRT_KERNEL_SHA256=.*", "OWRT_VIRT_KERNEL_SHA256=" + sha(os.path.join(a.virt, kb)))]
    if st:
        rewrite(os.path.join(PIN, "stock.pin"), st)
    if a.ax1800:   # the hardware profile must agree with stock.pin (tests/run.sh checks it)
        prof = os.path.join(HERE, "..", "..", "profiles", "hw", "qualcommax-gl-ax1800.toml")
        rewrite(prof, [(r'^(kernel\s+= \{ source = )"[^"]*"(, version = )"[^"]*"', r'\1"openwrt-tag-rebuilt-fit"\2"%s"' % kver),
                       (r'^(kernel\s+= )"[^"]*"', r'\1"%s"' % kver),
                       (r'^(stock_sha256\s+= )"[^"]*"', r'\1"%s"' % sha(os.path.join(a.ax1800, sy)))])
    # kmods.pin: header lines + sha lines
    head = [l for l in kp.splitlines() if not re.match(r"^(board|virt) ", l)]
    out = []
    for l in head:
        if l.startswith("KMOD_URL_board=") and "board" in base:
            l = "KMOD_URL_board=" + base["board"]
        if l.startswith("KMOD_URL_virt=") and "virt" in base:
            l = "KMOD_URL_virt=" + base["virt"]
        if l.startswith("KMOD_VERSION="):
            l = "KMOD_VERSION=%s-r1" % kver
        out.append(l)
    open(os.path.join(PIN, "kmods.pin"), "w").write("\n".join(out + new_kmod_lines) + "\n")
    if a.wifi_tar:
        tag = re.search(r"wifi-kmods-(.+)\.tar$", os.path.basename(a.wifi_tar)).group(1)
        u = upload("patronus-wifi-kmods", tag, a.wifi_tar, os.path.basename(a.wifi_tar), up)
        rewrite(os.path.join(PIN, "wifi-kmods", "wifi-kmods.pin"), [(r"^WIFI_KMODS_TAG=.*", "WIFI_KMODS_TAG=" + tag), (r"^WIFI_KMODS_URL=.*", "WIFI_KMODS_URL=" + u),
                                                                   (r"^WIFI_KMODS_SHA256=.*", "WIFI_KMODS_SHA256=" + sha(a.wifi_tar))])
    print("pins moved to kernel", kver)


main()
