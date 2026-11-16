#!/usr/bin/env python3
"""ubi-layout.py: read the layout of a UBI image (factory.ubi / ubinize output), standard library only.

  ubi-layout.py show <image.ubi>                    JSON: geometry + volumes (id, name, type, flags, reserved/used PEBs)
  ubi-layout.py check <image.ubi> [--profile P]     the image matches what the GL-AX1800 boots: PEB/LEB/min I/O from the
                                                    profile's [nand] table, volumes kernel=0, rootfs=1 (the kernel command
                                                    line pins root=/dev/ubiblock0_1) and rootfs_data=2 with autoresize;
                                                    kernel starts with a FIT header, rootfs with a squashfs superblock.
  ubi-layout.py extract <image.ubi> <volume> <out>  the volume's data (LEB order), e.g. to compare with the sysupgrade parts

Format (Linux drivers/mtd/ubi/ubi-media.h): every PEB starts with an EC header ('UBI#', vid_hdr_offset, data_offset),
data PEBs carry a VID header ('UBI!', vol_id, lnum, data_size) at vid_hdr_offset; the volume table lives in the two
layout volume PEBs (vol_id 0x7fffefff), 128 records of 172 bytes. Exit 0 = ok, 1 = check failed, 2 = usage/parse error.
"""
import json
import os
import struct
import sys

EC_MAGIC, VID_MAGIC = b"UBI#", b"UBI!"
LAYOUT_VOL = 0x7FFFEFFF
VTBL_REC = 172
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROFILE = os.path.join(HERE, "..", "..", "..", "profiles", "hw", "qualcommax-gl-ax1800.toml")


def parse(path, peb=None):
    data = open(path, "rb").read()
    if data[:4] != EC_MAGIC:
        raise ValueError("%s: no UBI EC header at offset 0" % path)
    vid_off, data_off, seq = struct.unpack(">II I", data[16:28])
    if peb is None:
        # PEB size: distance to the next EC header
        peb = next((o for o in (2 ** k for k in range(14, 21)) if data[o:o + 4] == EC_MAGIC), None)
        if peb is None:
            raise ValueError("cannot find the PEB size")
    if len(data) % peb:
        raise ValueError("image size %d is not a multiple of the PEB size %d" % (len(data), peb))
    lebs, vtbl = {}, None
    for i in range(len(data) // peb):
        b = data[i * peb:(i + 1) * peb]
        if b[:4] != EC_MAGIC:
            raise ValueError("PEB %d: no EC header" % i)
        v = b[vid_off:vid_off + 64]
        if v[:4] != VID_MAGIC:
            continue  # free (erased) PEB
        vol_type = v[5]
        vol_id, lnum = struct.unpack(">II", v[8:16])
        data_size = struct.unpack(">I", v[20:24])[0]
        payload = b[data_off:]
        if vol_id == LAYOUT_VOL:
            vtbl = vtbl or payload
            continue
        lebs.setdefault(vol_id, {})[lnum] = (payload, data_size, vol_type)
    if vtbl is None:
        raise ValueError("no layout volume (volume table)")
    vols = []
    for n in range(128):
        r = vtbl[n * VTBL_REC:(n + 1) * VTBL_REC]
        reserved, align, pad, vtype, upd, name_len = struct.unpack(">IIIBBH", r[:16])
        if reserved == 0:
            continue
        name = r[16:16 + name_len].decode()
        flags = r[144]
        vols.append({"id": n, "name": name, "type": "dynamic" if vtype == 1 else "static", "reserved_pebs": reserved,
                     "autoresize": bool(flags & 1), "used_lebs": len(lebs.get(n, {}))})
    return {"peb": peb, "leb": peb - data_off, "min_io": vid_off, "vid_hdr_offset": vid_off, "data_offset": data_off,
            "image_seq": seq, "pebs": len(data) // peb, "volumes": vols}, lebs


def extract(lebs, vol_id):
    out = b""
    for lnum in sorted(lebs.get(vol_id, {})):
        out += lebs[vol_id][lnum][0]
    return out


def profile_nand(path):
    sys.path.insert(0, os.path.join(HERE, "..", "..", "hw-profile"))
    import hwprofile  # noqa: E402
    return hwprofile.load_profile(path)["nand"]


def check(path, prof_path):
    nand = profile_nand(prof_path)
    info, lebs = parse(path, nand["peb_bytes"])
    errs = []
    for k, want in (("peb", nand["peb_bytes"]), ("leb", nand["leb_bytes"]), ("min_io", nand["min_io"])):
        if info[k] != want:
            errs.append("%s is %d, the board needs %d" % (k, info[k], want))
    by = {v["name"]: v for v in info["volumes"]}
    for name, vid in (("kernel", 0), ("rootfs", 1), ("rootfs_data", 2)):
        if name not in by:
            errs.append("volume %s is missing" % name)
        elif by[name]["id"] != vid:
            errs.append("volume %s has id %d, the board needs %d" % (name, by[name]["id"], vid))
    if "rootfs_data" in by and not by["rootfs_data"]["autoresize"]:
        errs.append("rootfs_data must carry the autoresize flag (it takes the rest of the flash on first attach)")
    if "kernel" in by and extract(lebs, by["kernel"]["id"])[:4] != b"\xd0\x0d\xfe\xed":
        errs.append("kernel volume does not start with a FIT (FDT) header")
    if "rootfs" in by and extract(lebs, by["rootfs"]["id"])[:4] != b"hsqs":
        errs.append("rootfs volume does not start with a squashfs superblock")
    total = nand["ubi_mtd_bytes"] // nand["peb_bytes"]
    if info["pebs"] > total - nand["reserved_pebs"]:
        errs.append("image has %d PEBs, the partition holds %d usable" % (info["pebs"], total - nand["reserved_pebs"]))
    for e in errs:
        print("FAIL " + e)
    print("ubi-layout: %s: PEB %d LEB %d min I/O %d, %d PEBs; %s" % (
        os.path.basename(path), info["peb"], info["leb"], info["min_io"], info["pebs"],
        ", ".join("%s=%d(%d PEBs%s)" % (v["name"], v["id"], v["reserved_pebs"], ",autoresize" if v["autoresize"] else "")
                  for v in info["volumes"])))
    return 1 if errs else 0


def main(a):
    try:
        if len(a) >= 2 and a[0] == "show":
            print(json.dumps(parse(a[1])[0], indent=1))
            return 0
        if len(a) >= 2 and a[0] == "check":
            return check(a[1], a[a.index("--profile") + 1] if "--profile" in a else DEFAULT_PROFILE)
        if len(a) == 4 and a[0] == "extract":
            info, lebs = parse(a[1])
            v = next((v for v in info["volumes"] if v["name"] == a[2]), None)
            if v is None:
                print("no volume " + a[2], file=sys.stderr)
                return 2
            open(a[3], "wb").write(extract(lebs, v["id"]))
            return 0
    except (ValueError, OSError, struct.error) as e:
        print("ubi-layout: %s" % e, file=sys.stderr)
        return 2
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
