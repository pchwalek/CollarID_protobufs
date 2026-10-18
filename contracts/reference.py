"""Reference implementation of the CollarID contracts (contracts/collarid_contracts.json).

The vectors (test_vectors/contracts_v1.json) are made from this file by
make_vectors.py, and every repo that implements one of these contracts runs
its own code over the same vectors. This file is the arbiter: when two
implementations disagree, the one that disagrees with this is wrong, or this
is, and then the vectors change first.

Standard library only. Ported from the implementations in use on 2026-10-16:
the website's js/u5-ota.js and js/wb-ota.js, the flash station's
ble_update.py, the radio firmware's custom_stm.c, the server's decoder.py.
"""

import json
import os
import re
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_PATH = os.path.join(HERE, "collarid_contracts.json")


def load_spec(path=SPEC_PATH):
    with open(path) as fh:
        return json.load(fh)


SPEC = load_spec()
DFU = SPEC["dfu"]
CAPS = SPEC["caps"]


# ── CRC-32 (reflected 0xEDB88320, init and final 0xFFFFFFFF) ──────────────
def crc32(data):
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


# ── protobuf: the two fields the Bluetooth contracts need ─────────────────
def _varint(buf, i):
    val = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return val & 0xFFFFFFFF, i


def _enc_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _skip(buf, i, wire):
    if wire == 0:
        _, i = _varint(buf, i)
    elif wire == 2:
        n, i = _varint(buf, i)
        i += n
    elif wire == 5:
        i += 4
    elif wire == 1:
        i += 8
    else:
        i = len(buf)
    return i


def encode_special_mode(code):
    """BlePacket{ schedule_config_packet (field 2) { special_mode (field 3) = code } }."""
    inner = b"\x18" + _enc_varint(code)
    return b"\x12" + _enc_varint(len(inner)) + inner


def decode_special_mode(data):
    """special_mode out of a BlePacket, or None when absent."""
    data, i = bytes(data), 0
    while i < len(data):
        tag, i = _varint(data, i)
        field, wire = tag >> 3, tag & 7
        if field == 2 and wire == 2:
            length, i = _varint(data, i)
            end = i + length
            while i < end:
                t2, i = _varint(data, i)
                if t2 >> 3 == 3 and t2 & 7 == 0:
                    return _varint(data, i)[0]
                i = _skip(data, i, t2 & 7)
            return None
        i = _skip(data, i, wire)
    return None


def mtu_of_publish(code):
    """The MTU a radio publishes on entering DFU (0x4D54xxxx), or None."""
    if code is None or (code >> 16) != DFU["mtu_publish_tag"]:
        return None
    return code & 0xFFFF


def payload_for_mtu(mtu, cap):
    """Frame payload for a published MTU: one ATT write is MTU-3, a frame adds 11."""
    return max(20, min(cap, mtu - 3 - DFU["frame_overhead"]))


def encode_status_version(version):
    """BlePacket{ system_state_packet (field 3) { firmware_version (field 6) } }."""
    v = version.encode()
    inner = b"\x32" + _enc_varint(len(v)) + v
    return b"\x1a" + _enc_varint(len(inner)) + inner


def parse_status_version(data):
    data, i = bytes(data), 0
    while i < len(data):
        tag, i = _varint(data, i)
        field, wire = tag >> 3, tag & 7
        if field == 3 and wire == 2:
            length, i = _varint(data, i)
            end = i + length
            while i < end:
                t2, i = _varint(data, i)
                if t2 >> 3 == 6 and t2 & 7 == 2:
                    n, i = _varint(data, i)
                    return data[i:i + n].decode("utf-8", "replace")
                i = _skip(data, i, t2 & 7)
            return None
        i = _skip(data, i, wire)
    return None


def build_of_version(version):
    """Collars report 'b<build> <hash>'."""
    m = re.match(SPEC["version_report"]["pattern"], (version or "").strip())
    return int(m.group(1)) if m else None


def build_of_image(image, tag):
    """The single '<tag>:<n>:' stamp in an image (FWBUILD, RADIOBUILD), or None."""
    found = {int(m.group(1)) for m in re.finditer(re.escape(tag).encode() + rb":(\d+):", bytes(image))}
    return found.pop() if len(found) == 1 else None


# ── the capability characteristic ─────────────────────────────────────────
def parse_caps(raw):
    """-> {present, fmt, bits, family, build, kind}.

    raw None: no characteristic, the older radio. Formats 1-2 are the MkII
    Mesh radio (no family byte); format 3 adds the family at byte 4, format
    4 the build (u32 LE) at bytes 5-8."""
    fam_names = {v: k for k, v in CAPS["families"].items()}
    out = {"present": False, "fmt": 0, "bits": 0, "family": None, "build": None, "kind": "older"}
    if raw is None:
        return out
    raw = bytes(raw)
    out["present"] = True
    if len(raw) < 4 or raw[0:2] != CAPS["magic"].encode():
        out["kind"] = "unknown"
        return out
    out["fmt"], out["bits"] = raw[2], raw[3]
    if raw[2] >= CAPS["format_family"]:
        fam = raw[CAPS["family_offset"]] if len(raw) > CAPS["family_offset"] else None
        out["family"] = fam if fam in fam_names else None
    else:
        out["family"] = CAPS["families"]["wb5m"]
    if raw[2] >= CAPS["format_build"] and len(raw) >= CAPS["build_offset"] + 4:
        out["build"] = int.from_bytes(raw[CAPS["build_offset"]:CAPS["build_offset"] + 4], "little")
    out["kind"] = fam_names.get(out["family"], "unknown")
    return out


def caps_bytes(fmt, bits, family=None, build=None):
    """What a radio answers (the radio firmware's side)."""
    b = CAPS["magic"].encode() + bytes([fmt, bits])
    if fmt >= CAPS["format_family"]:
        b += bytes([family])
    if fmt >= CAPS["format_build"]:
        b += (build or 0).to_bytes(4, "little")
    return b


# ── the main chip's update stream (relayed by the radio) ──────────────────
def u5_stream(image, git_hash=""):
    """32-byte 'U5FW' header + image (js/u5-ota.js buildStream)."""
    h = bytearray(DFU["u5_header_len"])
    h[0:4] = DFU["u5_magic"].encode()
    h[4] = DFU["u5_header_version"]
    h[5] = SPEC["dfu"]["targets"]["u5"]
    h[8:12] = len(image).to_bytes(4, "little")
    h[12:16] = crc32(image).to_bytes(4, "little")
    gh = (git_hash or "")[:8].encode("ascii", "ignore")
    h[16:16 + len(gh)] = gh
    h[28:32] = crc32(bytes(h[:28])).to_bytes(4, "little")
    return bytes(h) + bytes(image)


def pad_to_batches(image, payload):
    """0xFF so header + image is a whole number of batches (js/u5-ota.js padToBatches)."""
    batch = payload * DFU["batch_frames"]
    pad = (batch - ((DFU["u5_header_len"] + len(image)) % batch)) % batch
    return bytes(image) + b"\xff" * pad


def data_frame(seq, chunk):
    """[0x11][seq u32 LE][len u16 LE][payload][crc32 of everything before]."""
    f = bytes([DFU["frame_data"]]) + seq.to_bytes(4, "little") + len(chunk).to_bytes(2, "little") + bytes(chunk)
    return f + crc32(f).to_bytes(4, "little")


def frames(stream, payload):
    return [data_frame(i, stream[off:off + payload]) for i, off in enumerate(range(0, len(stream), payload))]


def radio_start_frame(target, image):
    """[0x10][target][len u32 LE][image crc u32 LE][crc32 of the first 10 bytes] (js/wb-ota.js)."""
    h = bytes([DFU["frame_start"], target]) + len(image).to_bytes(4, "little") + crc32(image).to_bytes(4, "little")
    return h + crc32(h).to_bytes(4, "little")


# ── ErrorFlags.flag ───────────────────────────────────────────────────────
def error_flag_keys(word):
    """The keys of the bits set in an ErrorFlags.flag word, low bit first.
    A set bit no allocation names comes back as 'bit<n>'."""
    names = {b["bit"]: b["key"] for b in SPEC["error_flags"]["bits"]}
    return [names.get(i, f"bit{i}") for i in range(32) if word >> i & 1]
