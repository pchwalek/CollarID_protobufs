#!/usr/bin/env python3
"""Make test_vectors/contracts_v1.json from reference.py.

    python3 make_vectors.py          # write it
    python3 make_vectors.py --check  # exit 1 if it is stale

Every repo that implements one of these contracts runs its own code over
these cases (contracts/README.md lists who runs which). Bytes are lower-case
hex. Images are small and made by a rule (image_bytes) so the file stays
readable; each case also carries the image itself.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate  # noqa: E402
import reference as R  # noqa: E402

OUT = os.path.join(os.path.dirname(HERE), "test_vectors", "contracts_v1.json")


def image_bytes(n, seed):
    """A deterministic test image: byte i = (i * 37 + seed) & 0xFF."""
    return bytes((i * 37 + seed) & 0xFF for i in range(n))


def build_image(spec):
    """An image from its rule: {length, seed, patch: [[offset, hex], ...]}.
    Every implementation rebuilds it the same way, so the vectors stay small
    while the images are real-sized (a main-chip image must be >= 100 KB with
    a plausible stack pointer and reset vector; a radio image must carry the
    slot tag at 0x143, or MCUboot's magic for the other radio)."""
    img = bytearray(image_bytes(spec["length"], spec["seed"]))
    for off, h in spec.get("patch", []):
        b = bytes.fromhex(h)
        img[off:off + len(b)] = b
    return bytes(img)


# A main chip's vector table: SP 0x20140000, reset vector 0x08000201.
U5_HEAD = [[0, "0000142001020008"]]
# A MkII Mesh radio app: the OTA tag pointer 0x0800xxxx at 0x140.
WB5M_HEAD = [[0x140, "34120008"]]
# The other radio: MCUboot's image header magic.
NRF_HEAD = [[0, "3db8f396"]]


def hx(b):
    return None if b is None else bytes(b).hex()


def make():
    S = R.SPEC
    D = S["dfu"]
    v = {"version": 1, "contracts_sha256": generate.sha256(S),
         "about": "Made by contracts/make_vectors.py from contracts/reference.py. Do not edit by hand."}

    # special_mode. "special_mode": the codes a host sends and a radio answers
    # (one byte each); every implementation encodes and decodes them.
    # "special_mode_decode": what a host only ever reads: the radio's MTU
    # publish (a multi-byte varint), a large code, an empty packet, another
    # field only, special_mode after another field.
    codes = [D["special_mode"][k] for k in ("enter", "ready", "restart", "wb_done", "wb_fail")]
    v["special_mode"] = [{"code": c, "bytes": hx(R.encode_special_mode(c))} for c in codes]
    v["special_mode_decode"] = [{"bytes": hx(R.encode_special_mode(c)), "code": c}
                                for c in ((D["mtu_publish_tag"] << 16) | 185, (D["mtu_publish_tag"] << 16) | 247, 300)]
    v["special_mode_decode"] += [
        {"bytes": "", "code": None},
        {"bytes": "1a00", "code": None},
        {"bytes": "1204080118" + "02", "code": 2},
    ]
    # MTU publish -> payloads
    v["mtu"] = []
    for code in [(D["mtu_publish_tag"] << 16) | m for m in (23, 104, 185, 247, 517)] + [D["special_mode"]["ready"]]:
        mtu = R.mtu_of_publish(code)
        v["mtu"].append({"code": code, "mtu": mtu,
                         "u5_payload": None if mtu is None else R.payload_for_mtu(mtu, D["u5_payload_cap"]),
                         "radio_payload": None if mtu is None else R.payload_for_mtu(mtu, D["radio_payload_cap"])})

    # how a collar reports its build
    v["status_version"] = []
    for ver in ("b511 b4dd479", "b512 e5f77f6-dirty", "b7 x", "dev", "", "build 511"):
        raw = R.encode_status_version(ver)
        v["status_version"].append({"bytes": hx(raw), "version": ver, "build": R.build_of_version(ver)})
    v["status_version"].append({"bytes": "1202180a", "version": None, "build": None})
    v["image_build"] = [
        {"tag": "FWBUILD", "image": hx(b"\x00junk FWBUILD:511: more"), "build": 511},
        {"tag": "RADIOBUILD", "image": hx(b"RADIOBUILD:157:\x00"), "build": 157},
        {"tag": "FWBUILD", "image": hx(b"FWBUILD:511: and FWBUILD:512:"), "build": None},
        {"tag": "FWBUILD", "image": hx(b"FWBUILD:511: FWBUILD:511:"), "build": 511},
        {"tag": "FWBUILD", "image": hx(b"no stamp here"), "build": None},
        {"tag": "RADIOBUILD", "image": hx(b"FWBUILD:511:"), "build": None},
    ]

    # the capability characteristic
    fam = S["caps"]["families"]
    cases = [None, R.caps_bytes(1, 0x01), R.caps_bytes(2, 0x07), R.caps_bytes(3, 0x07, fam["wb5m"]),
             R.caps_bytes(3, 0x07, fam["nrf54l15"]), R.caps_bytes(3, 0x07, 0x09),
             R.caps_bytes(4, 0x07, fam["wb5m"], 157), R.caps_bytes(4, 0x07, fam["nrf54l15"], 3),
             R.caps_bytes(4, 0x07, fam["wb5m"], 0x01020304), b"CP\x03\x07", b"XY\x03\x07\x01", b"C"]
    v["caps"] = [dict(bytes=hx(c), **R.parse_caps(c)) for c in cases]

    # the main chip's update stream. "mtu": what the radio publishes on entry
    # (None: nothing, the 96 B fallback); the payload follows from it.
    v["u5_stream"] = []
    for n, seed, mtu, gh in ((102700, 11, None, "b4dd479"), (102700, 11, 247, ""), (110000, 3, 185, "e5f77f6a"),
                             (102400 + 928, 5, 110, "12345678")):
        # ...and the build stamp every real image carries (the station refuses one without).
        ispec = {"length": n, "seed": seed, "patch": U5_HEAD + [[n - 16, b"FWBUILD:900:".hex()]]}
        img = build_image(ispec)
        payload = D["payload_fallback"] if mtu is None else R.payload_for_mtu(mtu, D["u5_payload_cap"])
        padded = R.pad_to_batches(img, payload)
        stream = R.u5_stream(padded, gh)
        fr = R.frames(stream, payload)
        v["u5_stream"].append({
            "image": ispec, "image_crc32": R.crc32(img), "git_hash": gh, "mtu": mtu, "payload": payload,
            "padded_len": len(padded), "header": hx(stream[:D["u5_header_len"]]),
            "stream_len": len(stream), "stream_crc32": R.crc32(stream),
            "frames": len(fr), "first_frame": hx(fr[0]), "last_frame": hx(fr[-1]),
            "end_frame": hx(bytes([D["frame_end"]])),
        })

    # the radio's own update: START, the first DATA frame, END. "mtu" as above
    # (None: no publish, the radio default of 96 B).
    v["radio_start"] = []
    for n, seed, target, mtu, head in ((4000, 7, D["targets"]["wb5m"], None, WB5M_HEAD),
                                       (4000, 7, D["targets"]["nrf54l15"], None, NRF_HEAD),
                                       (15000, 9, D["targets"]["wb5m"], 247, WB5M_HEAD)):
        ispec = {"length": n, "seed": seed, "patch": head}
        img = build_image(ispec)
        payload = D["payload_fallback"] if mtu is None else R.payload_for_mtu(mtu, D["radio_payload_cap"])
        v["radio_start"].append({"image": ispec, "image_crc32": R.crc32(img), "target": target, "mtu": mtu,
                                 "payload": payload,
                                 "start_frame": hx(R.radio_start_frame(target, img)),
                                 "last_frame": hx(R.frames(img, payload)[-1]),
                                 "first_frame": hx(R.data_frame(0, img[:payload])),
                                 "frames": len(R.frames(img, payload)),
                                 "end_frame": hx(bytes([D["frame_end"]]))})

    # ErrorFlags.flag
    # old: words = [0, 0x80, 0x81, 0xFF, 1 << 8, (1 << 13) | (1 << 14), (1 << 10) | 0x80, (1 << 9) | (1 << 11) | (1 << 12),
    # old:          1 << 15, 0x7FFF, 1 << 31]
    # 1 << 15 is charge_held_off since 2026-10-18; 1 << 16 is now the first free bit.
    words = [0, 0x80, 0x81, 0xFF, 1 << 8, (1 << 13) | (1 << 14), (1 << 10) | 0x80, (1 << 9) | (1 << 11) | (1 << 12),
             1 << 15, (1 << 14) | (1 << 15), 0x7FFF, 0xFFFF, 1 << 16, 1 << 31]
    v["error_flags"] = [{"word": w, "keys": R.error_flag_keys(w)} for w in words]

    # CONFIG.CSV
    cfg = S.get("config_csv")
    if isinstance(cfg, dict) and "vectors" in cfg:
        v["config_csv"] = cfg["vectors"]
    return v


def render():
    return json.dumps(make(), indent=1, ensure_ascii=False) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    text = render()
    old = open(OUT).read() if os.path.exists(OUT) else None
    if a.check:
        print("vectors are current" if old == text else "vectors are stale: run make_vectors.py")
        return 0 if old == text else 1
    if old != text:
        with open(OUT, "w") as fh:
            fh.write(text)
        print(f"wrote {OUT}")
    else:
        print("vectors already current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
