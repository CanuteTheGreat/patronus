#!/usr/bin/env python3
"""fwmeta.py: append OpenWrt fwtool image metadata to a sysupgrade image, or read it back.

OpenWrt's `sysupgrade -T` refuses an image without it ("Image metadata not present").
Format (OpenWrt package/system/fwtool): struct fwimage_header (u32 version = 0, u32 flags = 0), the metadata
JSON, then a 16-byte big-endian trailer
  magic 'FWx0' | crc32 | type (1 = FWIMAGE_INFO) | 3 pad bytes | size (header + JSON + trailer)
where crc32 = ~zlib.crc32(every byte before the trailer). Checked against the 25.12.6 GL-AR750S image.

usage: fwmeta.py add <image> <board> [--version V]   (supported_devices = <board>)
       fwmeta.py show <image>
"""
import json
import struct
import sys
import zlib

MAGIC = 0x46577830  # 'FWx0'
INFO = 1


def trailer_for(data: bytes, payload: bytes) -> bytes:
    crc = ~zlib.crc32(data + payload) & 0xFFFFFFFF
    return struct.pack(">IIB3xI", MAGIC, crc, INFO, len(payload) + 16)


def add(path: str, board: str, version: str = "embedded") -> None:
    data = open(path, "rb").read()
    if read(data) is not None:
        raise SystemExit(f"{path}: already has metadata")
    meta = {
        "metadata_version": "1.1",
        "compat_version": "1.0",
        "supported_devices": [board],
        "version": {"dist": "Patronus", "version": version, "board": board.replace(",", "_")},
    }
    payload = b"\0" * 8 + (json.dumps(meta) + "\n").encode()  # fwimage_header, then the JSON
    with open(path, "ab") as f:
        f.write(payload + trailer_for(data, payload))


def read(data: bytes):
    """The metadata dict, or None. Raises on a trailer with a bad CRC."""
    if len(data) < 16:
        return None
    magic, crc, typ, size = struct.unpack(">IIB3xI", data[-16:])
    if magic != MAGIC or typ != INFO or size < 16 or size > len(data):
        return None
    if ~zlib.crc32(data[:-16]) & 0xFFFFFFFF != crc:
        raise ValueError("fwtool trailer CRC mismatch")
    payload = data[len(data) - size : -16]
    if len(payload) < 8 or payload[:8] != b"\0" * 8:
        raise ValueError("fwtool metadata without the fwimage_header")
    return json.loads(payload[8:])


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "add":
        v = sys.argv[sys.argv.index("--version") + 1] if "--version" in sys.argv else "embedded"
        add(sys.argv[2], sys.argv[3], v)
    elif len(sys.argv) == 3 and sys.argv[1] == "show":
        print(json.dumps(read(open(sys.argv[2], "rb").read())))
    else:
        raise SystemExit(__doc__)
