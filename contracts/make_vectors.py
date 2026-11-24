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
    # 1 << 16 is no_release_unit; 1 << 17 saving_power, 1 << 18 low_battery_sleep;
    # 1 << 19 is the first free bit.
    # old: words = [..., 0x1FFFF, 1 << 17, 1 << 31]   (17 was the first free bit until 2026-11-18)
    words = [0, 0x80, 0x81, 0xFF, 1 << 8, (1 << 13) | (1 << 14), (1 << 10) | 0x80, (1 << 9) | (1 << 11) | (1 << 12),
             1 << 15, (1 << 14) | (1 << 15), 0x7FFF, 0xFFFF, 1 << 16, (1 << 15) | (1 << 16), 0x1FFFF, 1 << 17,
             1 << 18, (1 << 17) | (1 << 18), (1 << 8) | (1 << 17), 0x7FFFF, 1 << 19, 1 << 31]
    v["error_flags"] = [{"word": w, "keys": R.error_flag_keys(w)} for w in words]

    # Low-battery hibernation thresholds. "valid": the rails' rule on a pair of
    # whole numbers. "from_csv": the pair a CONFIG.CSV's two rows give (null =
    # the row is missing), read as strtol reads it.
    B = S["battery_thresholds"]
    pairs = [(B["hibernate_default"], B["resume_default"]), (5, 10), (40, 45), (40, 60), (4, 10), (41, 60),
             (5, 9), (35, 61), (30, 34), (30, 35), (20, 20), (25, 20), (0, 0), (15, 50), (100, 100)]
    v["battery_thresholds_valid"] = [{"hibernate": h, "resume": r, "valid": R.battery_thresholds_valid(h, r)}
                                     for h, r in pairs]
    texts = [(None, None), ("10", "20"), ("15", "30"), (" 25", "40 "), ("3", "8"), ("99", "99"), ("-5", "-1"),
             ("40", "20"), ("12", None), (None, "12"), ("30", None), ("abc", "xyz"), ("", ""), ("7.9", "15.5"),
             ("+8", "+18"), ("20%", "35%"), ("99999999999999999999", "1")]
    v["battery_thresholds_from_csv"] = [{"hibernate": h, "resume": r, "want": R.battery_thresholds_from_csv(h, r)}
                                        for h, r in texts]

    # Saving power before hibernation (2026-11-18). "saving_band_valid": the
    # rails' rule on a band; "saving_band_from_csv": the band a CONFIG.CSV row
    # gives (null = the row is missing); "saving_next": the stage after a
    # reading; "hibernate_now": the low-battery sleep, with and without a
    # Spotter's hold; "spotter_held"; "saving_gps_refresh_wait_s".
    bands = [B["saving_band_default"], 0, 1, 15, 16, -1, 5.5, True, "5", None, 10]
    v["saving_band_valid"] = [{"band": b, "valid": R.saving_band_valid(b)} for b in bands]
    btexts = [None, "5", "0", "15", "16", "-3", " 7", "10 ", "abc", "", "4.9", "+12", "99999999999999999999"]
    v["saving_band_from_csv"] = [{"band": t, "want": R.saving_band_from_csv(t)} for t in btexts]
    cases = []
    for hib, band in ((10, 5), (10, 0), (25, 5), (40, 15), (5, 1), (10, 15)):
        for pct in sorted({hib - 1, hib, hib + 1, hib + band - 1, hib + band, hib + band + 1,
                           hib + band + 4, hib + band + 5, hib + band + 6, 100, 0}):
            for was in (False, True):
                cases.append({"hibernate": hib, "band": band, "pct": pct, "was_saving": was,
                              "saving": R.saving_next(hib, band, pct, was)})
    v["saving_next"] = cases
    hcases = []
    for hib in (5, 10, 40):
        for pct in (0, 2, 3, 4, hib - 1, hib, hib + 1, 100):
            for held in (False, True):
                hcases.append({"pct": pct, "hibernate": hib, "spotter_held": held,
                               "hibernate_now": R.hibernate_now(pct, hib, held)})
    v["hibernate_now"] = hcases
    hold = B["spotter_hold_s"]
    v["spotter_held"] = [{"session_open": so, "find_mode": fm, "since_contact_s": sc,
                          "held": R.spotter_held(so, fm, sc)}
                         for so, fm, sc in ((False, False, None), (True, False, None), (False, True, None),
                                            (False, False, 0), (False, False, hold - 1), (False, False, hold),
                                            (False, False, hold + 1), (True, True, 10**6))]
    v["saving_gps_refresh_wait_s"] = [{"failures": n, "wait_s": R.saving_gps_refresh_wait_s(n)}
                                      for n in (0, 1, 2, 3, 4, 10)]

    # Schedule zone (2026-11-23). "zone_valid": the rails' rule; "zone_from_csv":
    # the two CONFIG.CSV rows read (null = missing); "zone_offset": for each zone
    # of the list, every clock change 2026-2030 one second before, on and one
    # second after, plus mid-January and mid-July noon UTC each year: the
    # offset in quarter hours, the local epoch, summer time, and the next change.
    v["zone_valid"] = [{"std_qh": a, "dst": b, "valid": R.zone_valid(a, b)}
                       for a, b in ((0, 0), (-28, 1), (-28, 0), (4, 2), (40, 3), (48, 4), (22, 0),
                                    (-48, 0), (56, 0), (-49, 0), (57, 0), (0, 5), (0, -1), (-20, 99))]
    v["zone_from_csv"] = [{"std_qh": a, "dst": b, "want": list(R.zone_from_csv(a, b))}
                          for a, b in ((None, None), ("-28", "1"), ("-28", "0"), ("4", "2"), (" 40", "3 "),
                                       ("-60", "1"), ("70", "0"), ("abc", "9"), ("", ""), ("22", "4.5"))]
    zones = (("America/Denver", -28, 1), ("America/Phoenix", -28, 0), ("America/St_Johns", -14, 1),
             ("Europe/Berlin", 4, 2), ("Europe/London", 0, 2), ("Australia/Sydney", 40, 3),
             ("Pacific/Auckland", 48, 4), ("Asia/Kolkata", 22, 0))
    zrows = []
    for name, std, dst in zones:
        ts = set()
        for y in range(2026, 2031):
            jan = R._days_from_civil(y, 1, 15) * 86400 + 43200
            jul = R._days_from_civil(y, 7, 15) * 86400 + 43200
            ts.update((jan, jul))
            r = R.zone_rule(dst)
            if r:
                for k in ("start", "end"):
                    t = R.zone_edge_utc(y, r[k], std)
                    ts.update((t - 1, t, t + 1))
        for t in sorted(ts):
            zrows.append({"zone": name, "std_qh": std, "dst": dst, "utc": t,
                          "offset_qh": R.zone_offset_qh(t, std, dst),
                          "local": R.zone_local_epoch(t, std, dst),
                          "summer": R.zone_summer(t, std, dst),
                          "next_change": R.zone_next_change_utc(t, std, dst)})
    v["zone_offset"] = zrows

    # CONFIG.CSV
    cfg = S.get("config_csv")
    if isinstance(cfg, dict) and "vectors" in cfg:
        v["config_csv"] = cfg["vectors"]

    if "direct_regions" in S:
        v["direct_regions"] = make_direct_regions()
    return v


# ── Direct-radio regions (2026-11-17) ─────────────────────────────────────
#
# Every implementation (the C engine, the website's JS, the app's TS, the
# server's Python) runs these. Sweep rows are arrays (the "columns" say
# what each holds) to keep the file small; reasons, classes and how-codes are
# the names of direct_regions.reasons / classes / convert_how.

# collarID_thread docs/CONTRACT_direct_regions.md section 5, as written
# there: (rule set, in (sf, bw, kHz), out (sf, bw, kHz), why). The reference
# decides; a row that disagrees is reported, not changed here.
DR_CONTRACT_TABLE = [
    ("US915", (7, 125, 915000), (9, 500, 915000), "US vector"),
    ("US915", (9, 125, 902000), (11, 500, 903000), "US vector, whole MHz"),
    ("US915", (9, 125, 928000), (11, 500, 927000), "US vector"),
    ("US915", (9, 500, 868000), (9, 500, 915000), "outside the band: default channel"),
    ("EU868", (9, 125, 868000), (9, 125, 868100), "straddles L and M: M's grid is nearer"),
    ("EU868", (9, 125, 869000), (9, 125, 869000), "legal in N (0.1 %): kept"),
    ("EU868", (9, 500, 915000), (9, 125, 869525), "outside: default channel"),
    ("EU868", (9, 250, 869525), (8, 125, 869525), "O allows 125 only"),
    ("AU915", (9, 500, 915000), (9, 500, 916000), "half of it below 915 MHz"),
    ("AU915", (7, 125, 915000), (7, 125, 916000), "whole MHz kept"),
    ("BR915", (9, 125, 910000), (9, 500, 916000), "between the two bands: default channel"),
    ("BR915", (9, 125, 905000), (11, 500, 905000), "in the low band: 500 kHz"),
    ("JP920", (9, 250, 921000), (10, 500, 921000), "250 kHz not allowed: wider"),
    ("KR920", (9, 125, 922000), (9, 125, 922100), "onto the 200 kHz grid"),
    ("RU868", (9, 125, 868000), (9, 125, 868900), "outside: default channel"),
]

# CONTRACT_us_500khz.md section 3: (sf, kHz, MHz) -> (sf, kHz, MHz), unchanged.
DR_US500 = [
    ((7, 125, 915), (9, 500, 915)), ((8, 125, 915), (10, 500, 915)), ((9, 125, 915), (11, 500, 915)),
    ((10, 125, 915), (12, 500, 915)), ((11, 125, 915), (12, 500, 915)), ((12, 125, 915), (12, 500, 915)),
    ((7, 250, 915), (8, 500, 915)), ((12, 250, 915), (12, 500, 915)), ((9, 500, 915), (9, 500, 915)),
    ((9, 125, 902), (11, 500, 903)), ((9, 125, 928), (11, 500, 927)),
]

# A rule set that exists only here: it makes every branch the real table
# does not reach happen (a send limit a 64-byte frame can miss, so FRAME_TIME
# and convert's step 5; a band too narrow for its bandwidth; nearest-centre
# ties on distance, then e.i.r.p., then lo; a grid that does not start at lo;
# a power floor (a send_at_floor profile sends at it, an "unusable" one does not); a small
# budget). Implementations that take a rule-set object run it; the others
# skip it.
DR_SYNTHETIC = {
    "id": 99, "key": "TEST", "name": "synthetic: the vectors only", "bands": [
        {"name": "A", "lo_khz": 900000, "hi_khz": 900400, "bw_khz": [125], "grid_base_khz": 900050,
         "grid_step_khz": 100, "eirp_cdbm": 1400, "conducted_dbm": 30, "budget_ms_per_h": 1000, "lbt_dbm": -70,
         "lbt_ms": 5, "max_send_ms": 300, "pause_ms": 50},
        {"name": "B", "lo_khz": 900400, "hi_khz": 901000, "bw_khz": [250, 500], "grid_base_khz": None,
         "grid_step_khz": None, "eirp_cdbm": 2000, "conducted_dbm": 20, "budget_ms_per_h": 0, "lbt_dbm": None,
         "lbt_ms": None, "max_send_ms": 0, "pause_ms": 0},
        {"name": "C", "lo_khz": 901000, "hi_khz": 901200, "bw_khz": [500], "grid_base_khz": None,
         "grid_step_khz": None, "eirp_cdbm": 3000, "conducted_dbm": 30, "budget_ms_per_h": 0, "lbt_dbm": None,
         "lbt_ms": None, "max_send_ms": 0, "pause_ms": 0},
        {"name": "D", "lo_khz": 905000, "hi_khz": 906000, "bw_khz": [125, 250], "grid_base_khz": None,
         "grid_step_khz": None, "eirp_cdbm": 1400, "conducted_dbm": 30, "budget_ms_per_h": 6000, "lbt_dbm": None,
         "lbt_ms": None, "max_send_ms": 1000, "pause_ms": 100},
        {"name": "E", "lo_khz": 906000, "hi_khz": 907000, "bw_khz": [125], "grid_base_khz": None,
         "grid_step_khz": None, "eirp_cdbm": 2000, "conducted_dbm": 30, "budget_ms_per_h": 0, "lbt_dbm": None,
         "lbt_ms": None, "max_send_ms": 0, "pause_ms": 0},
        {"name": "F", "lo_khz": 907000, "hi_khz": 908000, "bw_khz": [125], "grid_base_khz": None,
         "grid_step_khz": None, "eirp_cdbm": 2000, "conducted_dbm": 30, "budget_ms_per_h": 0, "lbt_dbm": None,
         "lbt_ms": None, "max_send_ms": 0, "pause_ms": 0}],
    "default": {"freq_khz": 905500, "bw_khz": 125, "sf": 9},
    "wake": {"freq_hz": 906500000, "bw_khz": 125, "sf": 7, "sf_long": 10},
}

DR_TOA_LENGTHS = (0, 1, 14, 18, 25, 30, 38, 51, 64, 128, 255)
DR_MAX_SENDS = (0, 50, 100, 300, 1000, 4000)
DR_YAGI = {"gain_cdbi": 1200, "min_dbm": -9, "max_dbm": 22}   # a Spotter with a 12 dBi Yagi
# Mk III as it was until 2026-11-17 noon: +16..+27 dBm, below its floor it
# does not send. It keeps the POWER_FLOOR path covered.
DR_MK3_UNUSABLE = {"gain_cdbi": 90, "min_dbm": 16, "max_dbm": 27, "below_floor": "unusable"}
# Mk III as it was the afternoon of 2026-11-17: +16..+27 dBm, below its floor
# it sends at +16. collar_mk3 now goes down to +9 (the SX1262's reduced PA
# configuration into a 26 dB amplifier) and is below its floor nowhere in
# the table, so this profile keeps the send_at_floor path covered.
DR_FLOOR_16 = {"gain_cdbi": 90, "min_dbm": 16, "max_dbm": 27, "below_floor": "send_at_floor"}

# CONTRACT_direct_regions.md section 3 (2026-11-17): a device below its
# floor sends at it when its profile says so. (rule set, band, device, cap,
# usable, allowed, why).
DR_BELOW_FLOOR_CASES = [
    ("EU868", 0, DR_FLOOR_16, 16, True, 15, "EU band K, 25 mW: sends at its +16 floor"),
    ("EU868", 1, DR_FLOOR_16, 16, True, 15, "EU band L, 25 mW"),
    ("EU868", 2, DR_FLOOR_16, 16, True, 15, "EU band M, 25 mW"),
    ("EU868", 3, DR_FLOOR_16, 16, True, 15, "EU band N, 25 mW"),
    ("EU868", 5, DR_FLOOR_16, 16, True, 15, "EU band Q, 25 mW"),
    ("JP920", 0, DR_FLOOR_16, 16, True, 13, "Japan: 20 mW into the antenna"),
    ("KR920", 0, DR_FLOOR_16, 16, True, 13, "Korea"),
    ("VN920", 0, DR_FLOOR_16, 16, True, 15, "Vietnam"),
    ("EU868", 4, DR_FLOOR_16, 27, True, 28, "EU band O, 500 mW: its own max"),
    ("EU868", 2, "collar_mk3", 15, True, 15, "Mk III (+9..+28): the band's own +15, not at its floor"),
    ("JP920", 0, "collar_mk3", 13, True, 13, "Mk III in Japan: +13"),
    ("KR920", 0, "collar_mk3", 13, True, 13, "Mk III in Korea: +13"),
    ("VN920", 0, "collar_mk3", 15, True, 15, "Mk III in Vietnam: +15"),
    ("EU868", 4, "collar_mk3", 28, True, 28, "Mk III in EU band O, 500 mW: +28"),
    ("EU868", 2, "collar_wio", 15, True, 15, "the Wio board goes down to -9: unchanged"),
    ("EU868", 2, DR_MK3_UNUSABLE, 15, False, 15, "an 'unusable' profile: does not send (POWER_FLOOR)"),
    ("JP920", 0, DR_MK3_UNUSABLE, 13, False, 13, "an 'unusable' profile in Japan"),
]


def _dr_sweep_freqs(r):
    """Every band edge +-1 kHz, every channel edge (lo + h, hi - h) +-1 for each
    bandwidth, grid points near the edges and one off the grid, whole MHz in
    the middle and one kHz off, the default and wake channels, and a few
    frequencies outside every band."""
    fs = {433000, 868000, 915000, 923000, r["default"]["freq_khz"], r["wake"]["freq_hz"] // 1000}
    for b in r["bands"]:
        lo, hi = b["lo_khz"], b["hi_khz"]
        fs |= {lo - 1, lo, lo + 1, hi - 1, hi, hi + 1}
        for bw in R.DR_BANDWIDTHS:
            h = R.dr_half_khz(bw)
            fs |= {lo + h - 1, lo + h, lo + h + 1, hi - h - 1, hi - h, hi - h + 1}
        if b["grid_step_khz"]:
            base, step = b["grid_base_khz"], b["grid_step_khz"]
            for edge in (lo + 63, hi - 63):
                g = base + ((edge - base) // step) * step
                fs |= {g, g + step, g + 1}
        mid = (lo + hi) // 2
        fs |= {mid // 1000 * 1000, mid // 1000 * 1000 + 1, mid}
    return sorted(f for f in fs if f > 0)


def _dr_rs_name(r):
    return r["key"] if isinstance(r, dict) else r


def make_direct_regions():
    DR = R.DR
    reasons, hows, classes = list(DR["reasons"]), list(DR["convert_how"]), list(DR["classes"])
    out = {"about": "Direct-radio regions (CONTRACT_direct_regions.md). rule_set is the DirectRegion id; "
                    "0 is no region. Reasons, how-codes and classes are names, or (in sweep rows) indexes "
                    "into direct_regions.reasons / convert_how. 'device' names a profile of "
                    "direct_regions.devices or is {gain_cdbi, min_dbm, max_dbm[, below_floor]} (no below_floor = "
                    "unusable). allowed_dbm is dr_power_allowed. The synthetic section's rule set exists only here.",
           "table_sha256": generate.dr_sha256(R.SPEC), "reasons": reasons, "convert_how": hows,
           "classes": classes, "fit_reasons": list(DR["fit_reasons"])}

    # section 5's table, as the contract writes it, and what the reference says
    rows = []
    for key, i, o, why in DR_CONTRACT_TABLE:
        got = R.dr_convert(key, *i)
        rows.append({"rule_set": R.dr_rule_set(key)["id"], "key": key, "in": list(i), "out": list(got[:3]),
                     "how": got[3], "contract_out": list(o), "agrees": tuple(got[:3]) == o, "why": why})
    out["contract_table"] = rows

    out["us500"] = []
    for i, o in DR_US500:
        got = R.to_us500(*i)
        assert got == o, ("CONTRACT_us_500khz.md section 3 no longer holds", i, got, o)
        assert R.us500_allowed(*o)
        out["us500"].append({"in_mhz": list(i), "out_mhz": list(got), "in_allowed": R.us500_allowed(*i)})

    # the sweep: every rule set x every frequency x 125/250/500 kHz x SF7..12,
    # check with the generic device and convert
    sweep_check, sweep_convert = [], []
    rule_sets = [r["id"] for r in DR["rule_sets"]]
    for rid in [0, 16] + rule_sets:
        r = R.dr_rule_set(rid)
        freqs = _dr_sweep_freqs(r) if r else [868000, 915000]
        for f in freqs:
            for bw in R.DR_BANDWIDTHS:
                codes = [reasons.index(R.dr_check(rid, sf, bw, f)) for sf in range(7, 13)]
                sweep_check.append([rid, bw, f, codes])
                conv = []
                for sf in range(7, 13):
                    s, b, nf, how = R.dr_convert(rid, sf, bw, f)
                    assert R.dr_check(rid, s, b, nf) == "OK", (rid, sf, bw, f)        # converted is legal
                    assert R.dr_convert(rid, s, b, nf)[3] == "kept", (rid, sf, bw, f)  # and stays
                    conv += [s, b, nf, hows.index(how)]
                sweep_convert.append([rid, bw, f, conv])
    out["check_sweep"] = {"columns": ["rule_set", "bw_khz", "freq_khz", "reason codes for SF7..12 (generic device)"],
                          "rows": sweep_check}
    out["convert_sweep"] = {"columns": ["rule_set", "bw_khz", "freq_khz",
                                        "for SF7..12 in turn: sf', bw', freq', how code"],
                            "rows": sweep_convert}

    # odd inputs: a bandwidth that is not 125/250/500 is read as the next one up
    odd = []
    for rid, sf, bw, f in ((1, 9, 62, 915000), (1, 12, 62, 915000), (2, 9, 62, 869525), (2, 9, 41, 868000),
                           (2, 9, 300, 869000), (2, 9, 1000, 869525), (3, 9, 0, 915000), (7, 9, 31, 921000),
                           (1, 9, 125, 0), (2, 7, 125, 4294967295)):
        s, b, nf, how = R.dr_convert(rid, sf, bw, f)
        odd.append({"rule_set": rid, "sf": sf, "bw_khz": bw, "freq_khz": f,
                    "check": R.dr_check(rid, sf, bw, f), "out": [s, b, nf], "how": how})
    out["odd_inputs"] = odd

    # each named device (and a Yagi) on a legal channel of every band
    dev_rows = []
    for r in DR["rule_sets"]:
        for i, b in enumerate(r["bands"]):
            bw = min(b["bw_khz"])
            f = R._dr_nearest_centre(b, bw, (b["lo_khz"] + b["hi_khz"]) // 2)
            for dev in list(DR["devices"]) + [DR_YAGI, DR_MK3_UNUSABLE, DR_FLOOR_16]:
                dev_rows.append({"rule_set": r["id"], "band": i, "sf": 9, "bw_khz": bw, "freq_khz": f,
                                 "device": dev, "reason": R.dr_check(r["id"], 9, bw, f, dev)})
    out["check_devices"] = dev_rows

    caps = []
    devices = list(DR["devices"]) + [DR_YAGI, DR_MK3_UNUSABLE, DR_FLOOR_16, {"gain_cdbi": 0, "min_dbm": 0, "max_dbm": 30},
                                     {"gain_cdbi": -300, "min_dbm": -9, "max_dbm": 22},
                                     {"gain_cdbi": 1215, "min_dbm": 2, "max_dbm": 22},
                                     {"gain_cdbi": 1215, "min_dbm": 2, "max_dbm": 22, "below_floor": "send_at_floor"}]
    for r in DR["rule_sets"]:
        for i in range(len(r["bands"])):
            for dev in devices:
                cap, usable = R.dr_power_cap(r["id"], i, dev)
                caps.append({"rule_set": r["id"], "band": i, "device": dev, "cap_dbm": cap, "usable": usable,
                             "allowed_dbm": R.dr_power_allowed(r["id"], i, dev)})
    for rid, band in ((0, 0), (1, -1), (1, 1), (16, 0)):
        cap, usable = R.dr_power_cap(rid, band, "collar_mk3")
        caps.append({"rule_set": rid, "band": band, "device": "collar_mk3", "cap_dbm": cap, "usable": usable,
                     "allowed_dbm": R.dr_power_allowed(rid, band, "collar_mk3")})
    out["power_caps"] = caps

    # Mk III below its floor (section 3, 2026-11-17), each with a legal channel of the band
    out["below_floor"] = []
    for key, band, dev, cap_w, usable_w, allowed_w, why in DR_BELOW_FLOOR_CASES:
        r = R.dr_rule_set(key)
        b = r["bands"][band]
        bw = min(b["bw_khz"])
        f = R._dr_nearest_centre(b, bw, (b["lo_khz"] + b["hi_khz"]) // 2)
        cap, usable = R.dr_power_cap(key, band, dev)
        allowed = R.dr_power_allowed(key, band, dev)
        assert (cap, usable, allowed) == (cap_w, usable_w, allowed_w), (key, band, why, cap, usable, allowed)
        out["below_floor"].append({"rule_set": r["id"], "key": key, "band": band, "band_name": b["name"],
                                   "device": dev, "sf": 9, "bw_khz": bw, "freq_khz": f, "cap_dbm": cap,
                                   "usable": usable, "allowed_dbm": allowed,
                                   "reason": R.dr_check(key, 9, bw, f, dev), "why": why})

    out["band_of"] = []
    for rid, f, bw in ((2, 868100, 125), (2, 868000, 125), (2, 869525, 125), (2, 869525, 250), (2, 869525, 500),
                       (2, 867100, 125), (2, 864000, 500), (2, 863062, 125), (2, 863063, 125), (2, 870000, 125),
                       (1, 915000, 125), (1, 902249, 500), (1, 902250, 500), (4, 910000, 500), (4, 916000, 500),
                       (7, 920563, 125), (0, 915000, 500), (16, 915000, 500)):
        out["band_of"].append({"rule_set": rid, "freq_khz": f, "bw_khz": bw, "band": R.dr_band_of(rid, f, bw)})

    out["toa"] = {"columns": ["sf", "bw_khz", "bytes", "us"],
                  "rows": [[sf, bw, n, R.dr_toa_us(sf, bw, n)] for sf in range(7, 13)
                           for bw in R.DR_BANDWIDTHS for n in DR_TOA_LENGTHS]
                  + [[6, 125, 10, 0], [13, 125, 10, 0], [9, 200, 10, 0], [9, 125, 256, 0]]}
    out["max_len"] = {"columns": ["sf", "bw_khz", "max_send_ms", "len"],
                      "rows": [[sf, bw, ms, R.dr_max_len(sf, bw, ms)] for sf in range(7, 13)
                               for bw in R.DR_BANDWIDTHS for ms in DR_MAX_SENDS]
                      + [[6, 125, 4000, -1], [9, 62, 0, -1]]}
    out["band_limits"] = []
    for r in DR["rule_sets"]:
        for i in range(len(r["bands"])):
            lbt, lim = R.dr_lbt(r["id"], i), R.dr_send_limit(r["id"], i)
            out["band_limits"].append({
                "rule_set": r["id"], "band": i, "lbt": list(lbt) if lbt else None, "send_limit": list(lim) if lim else None,
                "max_len": [[sf, bw, R.dr_band_max_len(r["id"], i, sf, bw)] for sf in range(7, 13) for bw in r["bands"][i]["bw_khz"]],
                "limit_normal_ms": R.dr_air_limit_ms(r["id"], i, "normal"),
                "limit_beacon_ms": R.dr_air_limit_ms(r["id"], i, "beacon")})

    out["air"] = [_dr_air_case(*c) for c in _dr_air_cases()]
    out["schedule_need"] = [_dr_need_case(*c) for c in _dr_need_cases()]

    out["region_resolve"] = []
    for setting, lw, f in ([(s, None, 0) for s in range(0, 17)] +
                           [(255, None, 915000), (4294967295, 0, 915000), (16, 2, 868000)] +
                           [(0, lw, 0) for lw in (0, 1, 2, 3, 255)] +
                           [(0, None, f) for f in (0, 433000, 862999, 863000, 868100, 869525, 870000, 870001,
                                                    901999, 902000, 915000, 920000, 928000, 928001)] +
                           [(7, 0, 868000), (15, 2, 915000), (0, 0, 868000)]):
        out["region_resolve"].append({"setting": setting, "lorawan_region": lw, "freq_khz": f,
                                      "region": R.dr_region_resolve(setting, lw, f)})

    out["wake_channels"] = []
    for rid in [0] + rule_sets + [16]:
        for lr in (False, True):
            w = R.dr_wake_channel(rid, lr)
            out["wake_channels"].append({"rule_set": rid, "long_range": lr, "channel": w})
            if w:
                assert R.dr_check(rid, w["sf"], w["bw_khz"], w["freq_hz"] // 1000) == "OK", (rid, lr)
    out["defaults"] = []
    for rid in [0] + rule_sets + [16]:
        sf, bw, f = R.dr_default_channel(rid)
        assert R.dr_check(rid, sf, bw, f) == "OK", rid
        out["defaults"].append({"rule_set": rid, "sf": sf, "bw_khz": bw, "freq_khz": f})
    out["freq_fields"] = [{"freq_khz": f, "frequency": m, "frequency_khz": k,
                           "reads_back": R.dr_freq_from_fields(m, k)}
                          for f in (0, 433000, 868000, 868100, 868499, 868500, 869500, 869525, 902250, 915000,
                                    922100, 923400, 999999)
                          for m, k in [R.dr_freq_to_fields(f)]]
    for row in out["freq_fields"]:
        assert row["reads_back"] == row["freq_khz"]
    out["freq_read"] = [{"frequency": m, "frequency_khz": k, "freq_khz": R.dr_freq_from_fields(m, k)}
                        for m, k in ((915, 0), (870, 869525), (0, 0), (868, 868100), (915, 915000), (0, 869525))]

    out["synthetic"] = _dr_synthetic()
    return out


def _dr_air_cases():
    """(name, rule set, [(op, band, now_s, ms or None, class or None)]):
    record / used / wait, on one account each."""
    K, M, O = 0, 2, 4         # EU868 bands K (3600 ms/h), M (36000), O (360000)
    return [
        ("EU K: normal may use 2700 of 3600 ms, beacons all of it", "EU868", [
            ("record", K, 0, 2000, None), ("used", K, 10, None, None),
            ("wait", K, 10, 700, "normal"), ("wait", K, 10, 701, "normal"), ("wait", K, 10, 800, "beacon"),
            ("wait", K, 10, 1600, "beacon"), ("wait", K, 10, 1601, "beacon"), ("wait", K, 10, 2700, "normal"),
            ("wait", K, 10, 2701, "normal"), ("wait", K, 10, 3600, "beacon"), ("wait", K, 10, 3601, "beacon"),
            ("wait", K, 10, 0, "normal")]),
        ("the 61-minute edge: a minute is counted until the 61st minute after it starts", "EU868", [
            ("record", K, 59, 1000, None), ("used", K, 59, None, None), ("used", K, 3599, None, None),
            ("used", K, 3600, None, None), ("used", K, 3659, None, None), ("used", K, 3660, None, None),
            ("wait", K, 3659, 2000, "normal"), ("wait", K, 3600, 2000, "normal"), ("wait", K, 3660, 2000, "normal"),
            ("wait", K, 3659, 1700, "normal")]),
        ("the oldest minutes leave first, as many as needed", "EU868", [
            ("record", K, 0, 1000, None), ("record", K, 600, 1000, None), ("record", K, 1200, 1000, None),
            ("used", K, 1500, None, None), ("wait", K, 1500, 500, "normal"), ("wait", K, 1500, 1700, "normal"),
            ("wait", K, 1500, 2700, "normal"), ("wait", K, 1500, 2700, "beacon"), ("wait", K, 4200, 1700, "normal"),
            ("used", K, 4200, None, None), ("used", K, 4800, None, None), ("used", K, 4860, None, None)]),
        ("a slot is reused 61 minutes on: the old minute is gone", "EU868", [
            ("record", K, 0, 500, None), ("record", K, 3660, 700, None), ("used", K, 3660, None, None),
            ("record", K, 3661, 100, None), ("used", K, 3700, None, None), ("used", K, 7320, None, None)]),
        ("several sends in one minute add up", "EU868", [
            ("record", M, 120, 400, None), ("record", M, 150, 400, None), ("record", M, 179, 400, None),
            ("used", M, 179, None, None), ("used", M, 180, None, None), ("wait", M, 200, 26000, "normal"),
            ("wait", M, 200, 26001, "normal"), ("wait", M, 200, 34800, "beacon"), ("wait", M, 200, 34801, "beacon")]),
        ("a jump of hours clears everything", "EU868", [
            ("record", M, 0, 30000, None), ("record", M, 36000, 10, None), ("used", M, 36000, None, None),
            ("wait", M, 36000, 26990, "normal"), ("wait", M, 36000, 26991, "normal")]),
        ("a clock that goes back records into the newest minute", "EU868", [
            ("record", K, 6000, 1000, None), ("record", K, 3000, 500, None), ("used", K, 3000, None, None),
            ("used", K, 6000, None, None), ("wait", K, 3000, 1500, "normal"), ("used", K, 9659, None, None),
            ("used", K, 9660, None, None)]),
        ("bands share the clock, not the time", "EU868", [
            ("record", M, 0, 5000, None), ("record", O, 0, 7000, None), ("used", M, 30, None, None),
            ("used", O, 30, None, None), ("used", K, 30, None, None), ("record", O, 4200, 100, None),
            ("used", M, 4200, None, None), ("used", O, 4200, None, None)]),
        ("the beacons' reserve: normal sends wait while beacons hold the last 25 %", "EU868", [
            ("record", K, 0, 3000, None), ("wait", K, 30, 0, "normal"), ("wait", K, 30, 1, "normal"),
            ("wait", K, 30, 600, "beacon"), ("wait", K, 30, 601, "beacon")]),
        ("EU O, 10 %: 270000 ms for normal sends, 360000 for beacons", "EU868", [
            ("record", O, 0, 250000, None), ("wait", O, 60, 20000, "normal"), ("wait", O, 60, 20001, "normal"),
            ("wait", O, 60, 110000, "beacon"), ("wait", O, 60, 110001, "beacon"), ("wait", O, 60, 270001, "normal"),
            ("wait", O, 60, 360001, "beacon")]),
        ("India: 90000 ms an hour", "IN865", [
            ("record", 0, 0, 67000, None), ("wait", 0, 1, 500, "normal"), ("wait", 0, 1, 501, "normal"),
            ("wait", 0, 1, 23000, "beacon")]),
        ("a band without a budget is not counted", "US915", [
            ("record", 0, 0, 999999, None), ("used", 0, 0, None, None), ("wait", 0, 0, 999999, "normal")]),
        ("no region counts nothing", 0, [
            ("record", 0, 0, 1000, None), ("used", 0, 0, None, None), ("wait", 0, 0, 1000, "normal")]),
        ("a band the rule set does not have counts nothing", "EU868", [
            ("record", 6, 0, 1000, None), ("used", 6, 0, None, None), ("wait", 6, 0, 10 ** 6, "beacon"),
            ("record", -1, 0, 1000, None), ("used", -1, 0, None, None)]),
        ("the first record starts the clock late", "RU868", [
            ("used", 0, 100000, None, None), ("wait", 0, 100000, 270000, "normal"),
            ("record", 0, 100000, 200000, None), ("wait", 0, 100001, 70000, "normal"),
            ("wait", 0, 100001, 70001, "normal"), ("wait", 0, 100001, 160000, "beacon"),
            ("wait", 0, 100001, 160001, "beacon")]),
    ]


def _dr_air_case(name, rs, steps):
    acct = R.DrAirAccount(rs)
    rows = []
    for op, band, now, ms, cls in steps:
        if op == "record":
            acct.record(band, now, ms)
            rows.append({"op": op, "band": band, "now_s": now, "ms": ms})
        elif op == "used":
            rows.append({"op": op, "band": band, "now_s": now, "want": acct.used_ms(band, now)})
        else:
            rows.append({"op": op, "band": band, "now_s": now, "ms": ms, "class": cls,
                         "want": acct.wait_s(band, now, ms, cls)})
    r = R.dr_rule_set(rs)
    return {"name": name, "rule_set": r["id"] if r else 0, "steps": rows}


def _dr_need_cases():
    """(name, rule set, sf, bw, kHz, reports/h, bytes, lost/h, bytes, find/h, bytes)."""
    return [
        ("EU O, SF9: a report a minute fits", "EU868", 9, 125, 869525, 60, 38, 0, 0, 0, 0),
        ("EU O, SF12: a report a minute fits", "EU868", 12, 125, 869525, 60, 51, 0, 0, 0, 0),
        ("EU O, SF12: two a minute is over 75 %", "EU868", 12, 125, 869525, 120, 51, 0, 0, 0, 0),
        ("EU O, SF12: reports under 75 %, lost-mode beacons take it over", "EU868", 12, 125, 869525, 100, 51,
         60, 25, 0, 0),
        ("EU O, SF12: beacons may use the reserve", "EU868", 12, 125, 869525, 100, 51, 20, 25, 0, 0),
        ("EU N (0.1 %), SF9: six reports an hour", "EU868", 9, 125, 869000, 6, 38, 0, 0, 0, 0),
        ("EU N (0.1 %), SF11: twelve reports an hour", "EU868", 11, 125, 869000, 12, 38, 0, 0, 0, 0),
        ("EU N: find mode for its length", "EU868", 9, 125, 869000, 4, 38, 0, 0, 30, 18),
        ("EU M at 868.1 MHz, 250 kHz", "EU868", 10, 250, 868300, 60, 64, 12, 25, 0, 0),
        ("India at SF12: 1 %... 2.5 %", "IN865", 12, 125, 866000, 30, 38, 12, 25, 0, 0),
        ("Singapore 1 %, SF10", "SG920", 10, 125, 921000, 30, 38, 6, 25, 0, 0),
        ("Thailand 10 %, SF12 at 500 kHz", "TH920", 12, 500, 921000, 360, 64, 60, 25, 120, 18),
        ("Russia 10 %", "RU868", 12, 125, 868900, 120, 38, 0, 0, 0, 0),
        ("US: no budget", "US915", 12, 500, 915000, 3600, 255, 3600, 255, 0, 0),
        ("no region", 0, 9, 125, 869525, 3600, 255, 0, 0, 0, 0),
        ("a channel in no band", "EU868", 9, 500, 915000, 60, 38, 0, 0, 0, 0),
        ("nothing sent", "EU868", 9, 125, 869525, 0, 0, 0, 0, 0, 0),
        ("exactly 75 % fits", "SYNTHETIC", 7, 125, 905500, 0, 0, 0, 0, 0, 0),
    ]


def _dr_need_case(name, rs, sf, bw, f, rph, rb, lph, lb, fph, fb):
    if rs == "SYNTHETIC":
        # D: 6000 ms/h, normal 4500: SF7/125 64 B is 118.016 ms -> 38 reports = 4484.6 ms
        rs = DR_SYNTHETIC
        rph, rb = 38, 64
    got = R.dr_schedule_need(rs, sf, bw, f, rph, rb, lph, lb, fph, fb)
    r = R.dr_rule_set(rs)
    return {"name": name, "rule_set": "synthetic" if r is DR_SYNTHETIC else (r["id"] if r else 0), "sf": sf,
            "bw_khz": bw, "freq_khz": f, "reports_per_h": rph, "report_bytes": rb, "lost_per_h": lph,
            "lost_bytes": lb, "find_per_h": fph, "find_bytes": fb, "want": got}


def _dr_synthetic():
    S = DR_SYNTHETIC
    reasons, hows = list(R.DR["reasons"]), list(R.DR["convert_how"])
    out = {"rule_set": S}
    checks = []
    for sf, bw, f, dev in ((8, 125, 900150, "generic"), (9, 125, 900150, "generic"), (12, 125, 900250, "generic"),
                           (8, 125, 900150, "collar_mk3"), (9, 125, 900150, "collar_mk3"),
                           (9, 125, 900100, "generic"), (9, 250, 900150, "generic"), (9, 500, 900700, "generic"),
                           (9, 500, 900700, "collar_mk3"), (8, 125, 900150, DR_MK3_UNUSABLE),
                           (9, 125, 900150, DR_MK3_UNUSABLE), (9, 500, 900700, DR_MK3_UNUSABLE),
                           (8, 125, 900150, DR_FLOOR_16), (9, 125, 900150, DR_FLOOR_16),
                           (9, 500, 901100, "generic"), (9, 125, 901100, "generic"),
                           (12, 125, 905500, "generic"), (11, 125, 905500, "generic"), (12, 250, 905500, "generic"),
                           (9, 125, 906000, "generic"), (9, 125, 907000, "generic"), (9, 125, 906500, "generic"),
                           (9, 250, 906500, "generic"), (7, 125, 899000, "generic"), (13, 125, 905500, "generic"),
                           (13, 500, 900700, "generic")):
        checks.append({"sf": sf, "bw_khz": bw, "freq_khz": f, "device": dev, "reason": R.dr_check(S, sf, bw, f, dev)})
    out["check"] = checks
    conv = []
    for sf, bw, f in ((12, 250, 900200), (10, 125, 900150), (9, 125, 900200), (9, 125, 900400), (9, 500, 901100),
                      (9, 500, 900200), (9, 125, 906000), (9, 125, 907000), (9, 250, 906000), (12, 125, 905500),
                      (9, 125, 899000), (7, 500, 905000), (12, 500, 906000), (9, 125, 900000)):
        s, b, nf, how = R.dr_convert(S, sf, bw, f)
        assert R.dr_check(S, s, b, nf) in ("OK", "FRAME_TIME"), (sf, bw, f)
        conv.append({"sf": sf, "bw_khz": bw, "freq_khz": f, "out": [s, b, nf], "how": how})
    out["convert"] = conv
    out["sweep"] = []
    for f in _dr_sweep_freqs(S):
        for bw in R.DR_BANDWIDTHS:
            row = [bw, f, [reasons.index(R.dr_check(S, sf, bw, f)) for sf in range(7, 13)], []]
            for sf in range(7, 13):
                s, b, nf, how = R.dr_convert(S, sf, bw, f)
                row[3] += [s, b, nf, hows.index(how)]
            out["sweep"].append(row)
    out["sweep_columns"] = ["bw_khz", "freq_khz", "reason codes for SF7..12 (generic device)",
                            "for SF7..12 in turn: sf', bw', freq', how code"]
    out["power_caps"] = [{"band": i, "device": d, "cap_dbm": R.dr_power_cap(S, i, d)[0],
                          "usable": R.dr_power_cap(S, i, d)[1], "allowed_dbm": R.dr_power_allowed(S, i, d)}
                         for i in range(len(S["bands"]))
                         for d in ("generic", "collar_mk3", "spotter", DR_MK3_UNUSABLE, DR_FLOOR_16)]
    out["band_limits"] = [{"band": i, "lbt": list(R.dr_lbt(S, i)) if R.dr_lbt(S, i) else None,
                           "send_limit": list(R.dr_send_limit(S, i)) if R.dr_send_limit(S, i) else None,
                           "max_len": [[sf, bw, R.dr_band_max_len(S, i, sf, bw)] for sf in range(7, 13)
                                       for bw in S["bands"][i]["bw_khz"]]}
                          for i in range(len(S["bands"]))]
    out["air"] = [_dr_air_case("the synthetic band A: 1000 ms, 750 for normal sends", S, [
        ("record", 0, 0, 700, None), ("wait", 0, 5, 50, "normal"), ("wait", 0, 5, 51, "normal"),
        ("wait", 0, 5, 300, "beacon"), ("wait", 0, 5, 301, "beacon"), ("wait", 0, 5, 751, "normal"),
        ("record", 3, 0, 4000, None), ("wait", 3, 5, 500, "normal"), ("wait", 3, 5, 501, "normal")])]
    out["wake"] = [R.dr_wake_channel(S, lr) for lr in (False, True)]
    out["default"] = list(R.dr_default_channel(S))
    return out


def _compact(v, indent, level):
    """JSON with every array of scalars, and every object whose values are
    scalars or arrays of scalars, on one line (the sweeps stay readable)."""
    scalar = lambda x: not isinstance(x, (dict, list))  # noqa: E731
    flat = lambda x: scalar(x) or (isinstance(x, list) and all(scalar(y) or (isinstance(y, list) and all(map(scalar, y))) for y in x))  # noqa: E731,E501
    one = lambda x: json.dumps(x, ensure_ascii=False,  # noqa: E731
                               separators=(", ", ": ") if isinstance(x, dict) else (",", ":"))
    if isinstance(v, list) and all(flat(x) for x in v) and all(not isinstance(x, list) or all(scalar(y) for y in x) for x in v):
        if all(scalar(x) for x in v):
            return one(v)
    if isinstance(v, dict) and all(flat(x) and not (isinstance(x, list) and any(isinstance(y, list) for y in x)) for x in v.values()):
        return one(v)
    pad, inner = " " * (indent * level), " " * (indent * (level + 1))
    if isinstance(v, list):
        if not v:
            return "[]"
        if all(isinstance(x, list) and all(scalar(y) or (isinstance(y, list) and all(map(scalar, y))) for y in x) for x in v):
            return "[\n" + ",\n".join(inner + one(x) for x in v) + "\n" + pad + "]"
        return "[\n" + ",\n".join(inner + _compact(x, indent, level + 1) for x in v) + "\n" + pad + "]"
    if isinstance(v, dict):
        if not v:
            return "{}"
        return "{\n" + ",\n".join(inner + json.dumps(k, ensure_ascii=False) + ": " + _compact(x, indent, level + 1)
                                   for k, x in v.items()) + "\n" + pad + "}"
    return one(v)


def render():
    v = make()
    dr = v.pop("direct_regions", None)
    text = json.dumps(v, indent=1, ensure_ascii=False)
    if dr is not None:
        # the sections before keep their layout; this one is compact (see _compact)
        assert text.endswith("\n}")
        text = text[:-2] + ',\n "direct_regions": ' + _compact(dr, 1, 1) + "\n}"
    return text + "\n"


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
