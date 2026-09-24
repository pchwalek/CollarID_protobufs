"""Tests for the GPS block v1 reference codec.

    cd reference && python3 -m unittest -v

Standard library only. The last test class runs only when the environment
variable GPS_BLOCK_FIELD_CSV names a local export of field fixes (never part
of the public repository), and is skipped otherwise; it round-trips every
field frame and prints block size statistics, and prints nothing that
identifies a device, a place or a time.

    GPS_BLOCK_FIELD_CSV=/path/to/export.csv python3 -m unittest
"""

import csv
import json
import os
import random
import statistics
import sys
import unittest
from decimal import Decimal
from fractions import Fraction
from math import ceil, floor

import gps_block as g
import make_vectors

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, os.pardir, "test_vectors", "gps_block_v1.json")
FIELD_CSV = os.environ.get("GPS_BLOCK_FIELD_CSV", "")

GATE = 1767225600
U32 = (1 << 32) - 1


def load_vectors():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------ oracles
# Written from the spec text, independently of gps_block's internals.

def spec_formula_bits(fixes, header_epoch):
    """Section 6, informative length formula."""
    kept = [f for f in fixes if not spec_excluded(f)]
    n = len(kept)
    if not 1 <= n <= 32:
        return 0
    wire = spec_wire_order(kept)
    qa = [spec_q(f["lat_e7"]) for f in wire]
    qo = [spec_q(f["lon_e7"]) for f in wire]
    age_w = spec_zz(header_epoch - wire[0]["t"]).bit_length()
    if n == 1:
        return 65 + age_w + 6 * n + 10
    dts = [wire[k - 1]["t"] - wire[k]["t"] for k in range(1, n)]
    lat_w = max(spec_zz(qa[k] - qa[k - 1]) for k in range(1, n)).bit_length()
    lon_w = max(spec_zz(qo[k] - qo[k - 1]) for k in range(1, n)).bit_length()
    dtmin_w = min(dts).bit_length()
    dt_w = max(d - min(dts) for d in dts).bit_length()
    return (65 + age_w + 6 * n + (n - 1).bit_length() + 42 + dtmin_w +
            (n - 1) * (lat_w + lon_w + dt_w))


def spec_zz(x):
    return 2 * x if x >= 0 else -2 * x - 1


def spec_q(v):
    return floor(Fraction(v + 50, 100))


def spec_excluded(f):
    """Section 4; the null island test is on the quantized position."""
    return (not -900000000 <= f["lat_e7"] <= 900000000 or
            not -1800000000 <= f["lon_e7"] <= 1800000000 or
            (spec_q(f["lat_e7"]) == 0 and spec_q(f["lon_e7"]) == 0) or
            f["t"] < GATE)


def spec_ttff(f):
    """Section 4: ttff_s absent (or None) is read as 0."""
    x = f.get("ttff_s")
    return 0 if x is None else x


def spec_wire_order(kept):
    asc = sorted(range(len(kept)), key=lambda i: kept[i]["t"])
    return [kept[i] for i in reversed(asc)]


def spec_h_acc_m(h):
    if not h:
        return None
    if h > 620:
        return 63
    return ceil(Fraction(h, 10))


def spec_projection(fixes):
    """What the server must see after decode(encode(fixes)): section 7 and
    the lossy list. None when the encoder emits nothing (cap aside)."""
    kept = [f for f in fixes if not spec_excluded(f)]
    n = len(kept)
    if not 1 <= n <= 32:
        return None
    wire = spec_wire_order(kept)
    raw = [spec_ttff(f) for f in wire]
    if n == 1:
        ttff = [min(1023, raw[0])]
    else:
        kmax = raw.index(max(raw))                  # raw values, lowest index
        rest = [x for k, x in enumerate(raw) if k != kmax]
        mean = floor(Fraction(sum(rest), len(rest)) + Fraction(1, 2))
        ttff = [min(1023, raw[kmax]) if k == kmax else min(1023, mean)
                for k in range(n)]
    out = []
    for k in reversed(range(n)):                    # oldest first
        f = wire[k]
        lat, lon = 100 * spec_q(f["lat_e7"]), 100 * spec_q(f["lon_e7"])
        out.append({"lat_e7": lat, "lon_e7": lon, "t": f["t"],
                    "h_acc_m": spec_h_acc_m(f.get("h_acc_dm")),
                    "gps_fix_time_s": ttff[k]})
    return out


# ------------------------------------------------------------------ inputs

def random_fixes(rng, valid_only=False):
    """A random batch mixing realistic tracks and hostile extremes."""
    kind = rng.random()
    n = rng.choice([1, 1, 2, 3, 5, 12, 24, 31, 32, 32, rng.randint(1, 32)])
    if not valid_only and rng.random() < 0.05:
        n = rng.choice([0, 33, 34])
    t = rng.choice([GATE, GATE + rng.randint(0, 10**8), U32 - 40 * 3600,
                    1800000000 + rng.randint(0, 10**7)])
    lat = rng.randint(-900000000, 900000000)
    lon = rng.randint(-1800000000, 1800000000)
    fixes = []
    for _ in range(n):
        if kind < 0.5:                              # realistic track
            lat = max(-900000000, min(900000000, lat + rng.randint(-3000, 3000)))
            lon = max(-1800000000, min(1800000000, lon + rng.randint(-4000, 4000)))
            t = min(U32, t + rng.choice([0, 300 + rng.randint(-14, 40),
                                         rng.randint(0, 20000)]))
        elif kind < 0.8:                            # anything in range
            lat = rng.randint(-900000000, 900000000)
            lon = rng.randint(-1800000000, 1800000000)
            t = rng.randint(GATE, U32)
        else:                                       # edges and ties
            lat = rng.choice([900000000, -900000000, 50, -50, 150, -151, 0,
                              lat, rng.randint(-900000000, 900000000)])
            lon = rng.choice([1800000000, -1800000000, 49, -49, 0, lon,
                              rng.randint(-1800000000, 1800000000)])
            t = rng.choice([t, GATE, U32, rng.randint(GATE, U32)])
        h = rng.choice([0, 1, 9, 10, 11, 184, 620, 621, U32,
                        rng.randint(0, 1000), rng.randint(0, U32)])
        ttff = rng.choice([0, 4, 10, 35, 1022, 1023, 1024, U32,
                           rng.randint(0, 2000), rng.randint(0, U32)])
        f = {"lat_e7": lat, "lon_e7": lon, "t": t}
        if ttff or rng.random() < 0.5:
            f["ttff_s"] = ttff                      # else absent = 0
        if h or rng.random() < 0.5:
            f["h_acc_dm"] = h                       # else absent = unknown
        fixes.append(f)
    if not valid_only and fixes and rng.random() < 0.2:
        bad = rng.randrange(len(fixes))
        fixes[bad] = dict(fixes[bad], **rng.choice([
            {"lat_e7": -(1 << 31)}, {"lon_e7": -(1 << 31)},
            {"lat_e7": 0, "lon_e7": 0}, {"lat_e7": 49, "lon_e7": -50},
            {"t": GATE - 1},
            {"lat_e7": 900000001}, {"lon_e7": -1800000001}]))
    if rng.random() < 0.3:
        rng.shuffle(fixes)
    newest = max([f["t"] for f in fixes] or [GATE])
    epoch = rng.choice([newest, newest + rng.randint(0, 2000), newest - 1, 0,
                        U32, rng.randint(0, U32)])
    epoch = max(0, min(U32, epoch))
    return fixes, epoch


def random_valid_inputs(seed, count):
    rng = random.Random(seed)
    out = []
    while len(out) < count:
        fixes, epoch = random_fixes(rng, valid_only=True)
        if spec_projection(fixes) is not None:
            out.append((fixes, epoch))
    return out


# ------------------------------------------------------------------ tests

class Primitives(unittest.TestCase):
    def test_zigzag(self):
        self.assertEqual([g.zz(x) for x in (0, -1, 1, -2, 2)], [0, 1, 2, 3, 4])
        for x in list(range(-1000, 1000)) + [-(1 << 32) + 1, (1 << 33), -(1 << 62)]:
            self.assertEqual(g.unzz(g.zz(x)), x)
            self.assertEqual(g.zz(x), spec_zz(x))

    def test_width(self):
        self.assertEqual([g.W(u) for u in (0, 1, 2, 3, 4, 255, 256)],
                         [0, 1, 2, 2, 3, 8, 9])

    def test_quantization_is_floor(self):
        cases = {50: 1, 49: 0, -50: 0, -51: -1, 150: 2, -150: -1, -151: -2,
                 -123456751: -1234568, -123456750: -1234567,
                 900000000: 9000000, -900000000: -9000000,
                 1800000000: 18000000, -1800000000: -18000000}
        for v, want in cases.items():
            self.assertEqual(g.q(v), want, v)
            self.assertEqual(g.q(v), spec_q(v), v)
            self.assertLessEqual(abs(v - 100 * g.q(v)), 50)

    def test_accuracy_codes(self):
        table = {0: 0, 1: 1, 9: 1, 10: 1, 11: 2, 20: 2, 21: 3, 611: 62,
                 619: 62, 620: 62, 621: 63, 1000: 63, U32: 63}
        for h, code in table.items():
            self.assertEqual(g.acc_code(h), code, h)
        self.assertEqual(g.acc_code(None), 0)
        self.assertIsNone(g.acc_code_to_m(0))
        for code in range(1, 64):                   # 63 is the integer 63
            self.assertIs(type(g.acc_code_to_m(code)), int)
            self.assertEqual(g.acc_code_to_m(code), code)

    def test_exclusion_is_on_the_quantized_position(self):
        base = {"t": 1800000000, "h_acc_dm": 10, "ttff_s": 1}
        table = {(0, 0): True, (49, 49): True, (-50, -50): True,
                 (30, -40): True, (-50, 49): True, (49, -49): True,
                 (50, 0): False, (0, 50): False, (-51, 0): False,
                 (0, -51): False, (50, -50): False, (100, 0): False,
                 (900000000, 0): False, (900000001, 0): True,
                 (-900000000, 0): False, (-900000001, 0): True,
                 (0, 1800000000): False, (0, 1800000001): True,
                 (0, -1800000000): False, (0, -1800000001): True,
                 (-(1 << 31), 5000): True, (5000, -(1 << 31)): True}
        for (lat, lon), want in table.items():
            f = dict(base, lat_e7=lat, lon_e7=lon)
            self.assertIs(g.is_excluded(f), want, (lat, lon))
            self.assertIs(spec_excluded(f), want, (lat, lon))
        ok = dict(base, lat_e7=5000, lon_e7=5000)
        self.assertTrue(g.is_excluded(dict(ok, t=GATE - 1)))
        self.assertFalse(g.is_excluded(dict(ok, t=GATE)))
        self.assertFalse(g.is_excluded({"lat_e7": 5000, "lon_e7": 5000, "t": GATE}))
        for bad in ({"lat_e7": True}, {"t": None}, {"lon_e7": 1.0}):
            with self.assertRaises((TypeError, ValueError)):
                g.is_excluded(dict(ok, **bad))
        rng = random.Random(7)
        for _ in range(20000):
            f = dict(base, lat_e7=rng.choice([rng.randint(-200, 200),
                                              rng.randint(-(1 << 31), (1 << 31) - 1)]),
                     lon_e7=rng.choice([rng.randint(-200, 200),
                                        rng.randint(-(1 << 31), (1 << 31) - 1)]),
                     t=rng.choice([GATE - 1, GATE, rng.randint(0, U32)]))
            self.assertIs(g.is_excluded(f), spec_excluded(f), f)


class InputValidation(unittest.TestCase):
    ok = {"lat_e7": 123456789, "lon_e7": -98765432, "t": 1800000000,
          "h_acc_dm": 1, "ttff_s": 1}

    def test_rejects_bad_types_and_ranges(self):
        bad = [{"lat_e7": True}, {"lat_e7": 1.0}, {"lon_e7": "1"},
               {"t": None}, {"ttff_s": -1}, {"t": 1 << 32},
               {"lat_e7": 1 << 31}, {"lon_e7": -(1 << 31) - 1},
               {"h_acc_dm": -1}, {"h_acc_dm": 1 << 32}, {"ttff_s": 1 << 32},
               {"h_acc_dm": 1.5}]
        for change in bad:
            with self.assertRaises((TypeError, ValueError), msg=change):
                g.gps_block_encode([dict(self.ok, **change)], 1800000000, 180)
        for key in ("lat_e7", "lon_e7", "t"):
            f = dict(self.ok)
            del f[key]
            with self.assertRaises(ValueError):
                g.gps_block_bits([f], 1800000000)
        for epoch in (-1, 1 << 32, 1.0, None, True):
            with self.assertRaises((TypeError, ValueError)):
                g.gps_block_encode([self.ok], epoch, 180)
        with self.assertRaises((TypeError, ValueError)):
            g.gps_block_encode([self.ok], 1800000000, -1)

    def test_invalid_fix_raises_even_if_it_would_be_excluded(self):
        with self.assertRaises(ValueError):
            g.gps_block_encode([self.ok, dict(self.ok, t=GATE - 1, ttff_s=-5)],
                               1800000000, 180)

    def test_h_acc_absent_or_none_is_unknown(self):
        a = dict(self.ok)
        del a["h_acc_dm"]
        b = dict(self.ok, h_acc_dm=None)
        c = dict(self.ok, h_acc_dm=0)
        blocks = {g.gps_block_encode([x], 1800000000, 180) for x in (a, b, c)}
        self.assertEqual(len(blocks), 1)
        self.assertIsNone(g.decode(blocks.pop(), 1800000000)[1][0]["h_acc_m"])

    def test_ttff_absent_or_none_is_zero(self):
        other = dict(self.ok, t=1800000300, ttff_s=9)
        a = dict(self.ok)
        del a["ttff_s"]
        b = dict(self.ok, ttff_s=None)
        c = dict(self.ok, ttff_s=0)
        for batch in ([a], [b], [c]):
            self.assertEqual(g.decode(g.gps_block_encode(batch, 1800000000, 180),
                                      1800000000)[1][0]["gps_fix_time_s"], 0)
        blocks = {g.gps_block_encode([x, other], 1800000400, 180) for x in (a, b, c)}
        self.assertEqual(len(blocks), 1)
        # Wire order [9, 0]: kmax 0, the rest (the absent one) is 0.
        self.assertEqual([f["gps_fix_time_s"] for f in
                          g.decode(blocks.pop(), 1800000400)[1]], [0, 9])

    def test_decode_argument_errors_raise(self):
        with self.assertRaises(TypeError):
            g.decode("00", 0)
        with self.assertRaises((TypeError, ValueError)):
            g.decode(b"\x20", -1)


class Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_vectors()

    def test_vector_file_is_up_to_date(self):
        with open(VECTORS, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), make_vectors.render(),
                             "run make_vectors.py and commit the result")

    def test_encoder_vectors(self):
        for v in self.data["vectors"]:
            with self.subTest(v["name"]):
                fixes, ep, cap = v["fixes"], v["header_epoch"], v["cap"]
                self.assertEqual(g.gps_block_bits(fixes, ep), v["bits"])
                blk = g.gps_block_encode(fixes, ep, cap)
                self.assertEqual(blk.hex() if blk else None, v["hex"])
                if v["hex"] is None:
                    self.assertEqual(v["decoded"], [])
                    continue
                self.assertEqual(len(blk), (v["bits"] + 7) // 8)
                got = g.decode(blk, ep)
                self.assertEqual(got, ("ok", v["decoded"]))
                self.assertEqual(v["decoded"], spec_projection(fixes))
                assert_integer_fixes(self, v["decoded"])
                assert_integer_fixes(self, got[1])

    def test_uncapped_vectors(self):
        n = 0
        for v in self.data["vectors"]:
            if "hex_uncapped" not in v:
                continue
            n += 1
            blk = bytes.fromhex(v["hex_uncapped"])
            self.assertGreater(len(blk), v["cap"])
            self.assertEqual(blk, g.gps_block_encode(v["fixes"], v["header_epoch"], 1 << 20))
            self.assertEqual(g.decode(blk, v["header_epoch"]),
                             ("ok", spec_projection(v["fixes"])))
        self.assertGreaterEqual(n, 1)

    def test_decoder_only_vectors(self):
        for v in self.data["decoder_only"]:
            with self.subTest(v["name"]):
                status, out = g.decode(bytes.fromhex(v["hex"]), v["header_epoch"])
                if v["expect"] in ("ignored", "empty"):
                    self.assertEqual(status, v["expect"], out)
                    if status == "empty":
                        self.assertEqual(out, [])
                else:
                    self.assertEqual((status, out), ("ok", v["expect"]))
                    assert_integer_fixes(self, out)

    def test_formula_and_walk_match_every_vector(self):
        for v in self.data["vectors"]:
            with self.subTest(v["name"]):
                self.assertEqual(spec_formula_bits(v["fixes"], v["header_epoch"]), v["bits"])
                hx = v["hex"] or v.get("hex_uncapped")
                if hx:
                    self.assertEqual(g.walked_bits(bytes.fromhex(hx), v["header_epoch"]),
                                     v["bits"])

    def test_vector_fields(self):
        # Section 9: every vector carries cap and note; hex_uncapped exactly
        # when the cap alone refused; decoded is [] when hex is null.
        for v in self.data["vectors"]:
            with self.subTest(v["name"]):
                self.assertIs(type(v["cap"]), int)
                self.assertIsInstance(v["note"], str)
                self.assertEqual("hex_uncapped" in v,
                                 v["hex"] is None and v["bits"] > 0)
                if v["hex"] is None:
                    self.assertEqual(v["decoded"], [])
        for v in self.data["decoder_only"]:
            with self.subTest(v["name"]):
                self.assertIsInstance(v["why"], str)
                if isinstance(v["expect"], list):
                    assert_integer_fixes(self, v["expect"])

    def test_no_decoded_fix_at_null_island(self):
        for v in self.data["vectors"]:
            for f in v["decoded"]:
                self.assertNotEqual((f["lat_e7"], f["lon_e7"]), (0, 0), v["name"])

    def test_spec_section_9_coverage(self):
        names = {v["name"] for v in self.data["vectors"]}
        dnames = {v["name"] for v in self.data["decoder_only"]}
        required = [
            "single_fix", "n2_identical_positions", "n3_identical_fixes_129_bits",
            "stationary_jitter_n12", "moving_track_n12",
            "southern_western_hemisphere", "half_step_positive",
            "half_step_negative", "equal_timestamps", "unsorted_input",
            "age_zero", "age_minus_one", "age_large_negative",
            "header_epoch_zero", "antimeridian_crossing", "poles_and_180",
            "int32_min_excluded", "null_island_excluded",
            "clock_gate_boundary", "n33_one_excluded_is_n32",
            "near_null_island_excluded", "near_null_island_only",
            "accuracy_code_boundaries", "ttff_saturation_and_tie",
            "ttff_kmax_raw_not_saturated", "ttff_saturated_tie_not_raw_tie",
            "ttff_absent_is_zero", "ttff_absent_single",
            "realistic_n12_hourly_5min", "realistic_n24_hourly_150s",
            "vehicle_n24_near_cap", "moving_n32_over_cap"]
        dec_required = [
            "zero_length", "one_byte", "truncated_header", "nonzero_padding",
            "extra_trailing_byte", "version_0", "version_2",
            "lat0_out_of_range", "delta_walks_past_pole", "ttff_kmax_ge_n",
            "age_w_34", "lat_w_27", "lon_w_28", "dtmin_w_33", "dt_w_33",
            "t0_below_gate", "tk_below_gate", "q_zero_zero_newest",
            "q_zero_zero_after_delta", "over_cap_block_still_decodes"]
        self.assertEqual([n for n in required if n not in names], [])
        self.assertEqual([n for n in dec_required if n not in dnames], [])

    def test_realistic_sizes(self):
        by = {v["name"]: v for v in self.data["vectors"]}
        veh = by["vehicle_n24_near_cap"]
        self.assertTrue(150 <= len(veh["hex"]) // 2 <= 180)
        widths = {n: x for n, _, x in g.layout(veh["fixes"], veh["header_epoch"])
                  if n.endswith("_w")}
        self.assertEqual((widths["lat_w"], widths["lon_w"], widths["dt_w"]), (14, 16, 14))
        over = by["moving_n32_over_cap"]
        self.assertEqual(len(over["decoded"]), 0)
        self.assertEqual(len(g.wire_order(over["fixes"])), 32)
        self.assertGreater(over["bits"], 8 * 180)
        # The decoder does not enforce the cap (section 7).
        big = bytes.fromhex(over["hex_uncapped"])
        self.assertGreater(len(big), g.FIRMWARE_CAP)
        status, out = g.decode(big, over["header_epoch"])
        self.assertEqual((status, len(out)), ("ok", 32))

    def test_vectors_are_synthetic(self):
        # Guard for a public repository: vector times are 2027+ or sit on the
        # clock gate / uint32 limit constants, never in the 2026 field season.
        lo_2027 = 1798761600
        for v in self.data["vectors"]:
            for f in v["fixes"]:
                t = f["t"]
                self.assertTrue(t >= lo_2027 or abs(t - GATE) <= 86400,
                                "%s: t %d" % (v["name"], t))


class Properties(unittest.TestCase):
    def test_formula_equals_walk_10000_random(self):
        for fixes, ep in random_valid_inputs(1, 10000):
            nbits = g.gps_block_bits(fixes, ep)
            self.assertEqual(nbits, spec_formula_bits(fixes, ep))
            blk = g.gps_block_encode(fixes, ep, 1 << 20)
            self.assertEqual(len(blk), (nbits + 7) // 8)
            self.assertEqual(g.walked_bits(blk, ep), nbits)

    def test_roundtrip_is_the_lossy_projection(self):
        rng = random.Random(2)
        seen_refused = seen_ok = 0
        for _ in range(6000):
            fixes, ep = random_fixes(rng)
            want = spec_projection(fixes)
            blk = g.gps_block_encode(fixes, ep, 1 << 20)
            if want is None:
                self.assertEqual(blk, b"")
                self.assertEqual(g.gps_block_bits(fixes, ep), 0)
                seen_refused += 1
                continue
            got = g.decode(blk, ep)
            self.assertEqual(got, ("ok", want))
            assert_integer_fixes(self, got[1])
            seen_ok += 1
        self.assertGreater(seen_refused, 100)
        self.assertGreater(seen_ok, 4000)

    def test_cap_refuses_never_truncates(self):
        rng = random.Random(3)
        for fixes, ep in random_valid_inputs(3, 1500):
            full = g.gps_block_encode(fixes, ep, 1 << 20)
            for cap in (0, len(full) - 1, len(full), len(full) + 1, 180,
                        rng.randint(0, 250)):
                got = g.gps_block_encode(fixes, ep, max(cap, 0))
                self.assertEqual(got, full if len(full) <= max(cap, 0) else b"")

    def test_pad_bits_and_exact_length(self):
        blocks = [(bytes.fromhex(v["hex"]), v["header_epoch"])
                  for v in load_vectors()["vectors"] if v["hex"]]
        blocks += [(g.gps_block_encode(f, e, 1 << 20), e)
                   for f, e in random_valid_inputs(4, 1500)]
        padded = 0
        for blk, ep in blocks:
            nbits = g.walked_bits(blk, ep)
            self.assertIsNotNone(nbits)
            self.assertEqual(len(blk), (nbits + 7) // 8)
            for bit in range(nbits, 8 * len(blk)):      # every pad bit
                bad = bytearray(blk)
                bad[bit // 8] |= 0x80 >> (bit % 8)
                self.assertEqual(g.decode(bytes(bad), ep)[0], "ignored")
                padded += 1
            for extra in (b"\x00", b"\xff", b"\x00\x00"):
                self.assertEqual(g.decode(blk + extra, ep)[0], "ignored")
            for cut in range(1, len(blk)):
                self.assertEqual(g.decode(blk[:cut], ep)[0], "ignored")
        self.assertGreater(padded, 1000)

    def test_decoder_never_raises(self):
        rng = random.Random(5)
        for _ in range(20000):
            n = rng.choice([0, 1, 2, 5, 9, 12, 17, 30, 60, 200])
            blk = bytes(rng.getrandbits(8) for _ in range(n))
            if blk and rng.random() < 0.7:
                blk = bytes([(blk[0] & 0x1F) | 0x20]) + blk[1:]     # version 1
            status, out = g.decode(blk, rng.randint(0, U32))
            self.assertIn(status, ("ok", "empty", "ignored"))
        for fixes, ep in random_valid_inputs(6, 1000):
            blk = bytearray(g.gps_block_encode(fixes, ep, 1 << 20))
            for _ in range(3):
                i = rng.randrange(len(blk))
                blk[i] ^= 1 << rng.randrange(8)
            status, out = g.decode(bytes(blk), ep)
            self.assertIn(status, ("ok", "ignored"))
            if status == "ok":
                for f in out:                    # whatever decodes is in range
                    self.assertTrue(-900000000 <= f["lat_e7"] <= 900000000)
                    self.assertTrue(-1800000000 <= f["lon_e7"] <= 1800000000)
                    self.assertNotEqual((f["lat_e7"], f["lon_e7"]), (0, 0))
                    self.assertTrue(GATE <= f["t"] <= U32)
                    self.assertTrue(0 <= f["gps_fix_time_s"] <= 1023)

    def test_block_with_q_zero_zero_is_corrupt(self):
        # Section 7: a reconstructed fix at q = (0, 0) makes the whole block
        # corrupt, wherever it sits in the block.
        rng = random.Random(8)
        seen = 0
        for fixes, ep in random_valid_inputs(9, 400):
            fields = g.layout(fixes, ep)
            n = len(g.wire_order(fixes))
            k = rng.randrange(n)
            qlat = [g.q(f["lat_e7"]) for f in g.wire_order(fixes)]
            qlon = [g.q(f["lon_e7"]) for f in g.wire_order(fixes)]
            qlat[k] = qlon[k] = 0                   # move fix k onto (0, 0)
            new = {"lat0": g.zz(qlat[0]), "lon0": g.zz(qlon[0])}
            for j in range(1, n):
                new["dlat[%d]" % j] = g.zz(qlat[j] - qlat[j - 1])
                new["dlon[%d]" % j] = g.zz(qlon[j] - qlon[j - 1])
            if n >= 2:
                new["lat_w"] = g.W(max(new["dlat[%d]" % j] for j in range(1, n)))
                new["lon_w"] = g.W(max(new["dlon[%d]" % j] for j in range(1, n)))
            out = []
            for name, w, x in fields:
                if name.startswith("dlat["):
                    w = new["lat_w"]
                elif name.startswith("dlon["):
                    w = new["lon_w"]
                out.append((name, w, new.get(name, x)))
            status, reason = g.decode(g.pack(out), ep)
            self.assertEqual(status, "ignored")
            self.assertIn("(0, 0)", reason)
            seen += 1
        self.assertEqual(seen, 400)

    def test_size_is_not_monotone_in_n(self):
        # Section 6: dropping a fix can grow the block (here: a gap appears in
        # a regular 300 s series, so every row pays dt_w = 9 bits).
        fixes = [{"lat_e7": 100000000 + 7 * k, "lon_e7": 200000000, "t": 1800000000 + 300 * k,
                  "h_acc_dm": 100, "ttff_s": 5} for k in range(10)]
        ep = fixes[-1]["t"]
        all10 = g.gps_block_bits(fixes, ep)
        without = g.gps_block_bits(fixes[:4] + fixes[5:], ep)
        self.assertGreater(without, all10)


def assert_integer_fixes(tc, fixes):
    """Every decoded value is an integer (h_acc_m may be None), never a
    float or a bool, so that 63 is the integer 63 on every consumer."""
    for f in fixes:
        for key in ("lat_e7", "lon_e7", "t", "gps_fix_time_s"):
            tc.assertIs(type(f[key]), int, (key, f))
        tc.assertTrue(f["h_acc_m"] is None or type(f["h_acc_m"]) is int, f)


def _varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            return r, i


def _fields(b):
    i, out = 0, []
    while i < len(b):
        key, i = _varint(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 2:
            ln, i = _varint(b, i)
            v, i = b[i:i + ln], i + ln
        elif wt == 5:
            v, i = b[i:i + 4], i + 4
        elif wt == 1:
            v, i = b[i:i + 8], i + 8
        else:
            raise ValueError("wire type %d" % wt)
        out.append((fn, wt, v))
    return out


def _int32(v):
    v &= (1 << 64) - 1
    v = v - (1 << 64) if v >> 63 else v
    return v


def parse_uplink(raw):
    """Minimal MessagePacket reader: (header.epoch, [fix, ...]) from the
    legacy gps_data entries of a deployment frame."""
    epoch, fixes = 0, []
    for fn, wt, v in _fields(raw):
        if fn == 1 and wt == 2:
            epoch = dict((f, x) for f, w, x in _fields(v) if w == 0).get(3, 0)
        elif fn == 5 and wt == 2:
            for f2, w2, v2 in _fields(v):
                if f2 == 7 and w2 == 2:
                    d = dict((f, x) for f, w, x in _fields(v2) if w == 0)
                    fixes.append({"lat_e7": _int32(d.get(1, 0)),
                                  "lon_e7": _int32(d.get(2, 0)),
                                  "t": d.get(4, 0), "h_acc_dm": d.get(7, 0),
                                  "ttff_s": d.get(5, 0)})
    return epoch, fixes


@unittest.skipUnless(FIELD_CSV and os.path.isfile(FIELD_CSV),
                     "set GPS_BLOCK_FIELD_CSV to a local field export")
class FieldData(unittest.TestCase):
    """Local only, opt-in through GPS_BLOCK_FIELD_CSV. Prints aggregate
    sizes, nothing identifying."""

    def test_field_frames_and_batches(self):
        with open(FIELD_CSV, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))

        def e7(s):
            return int((Decimal(s) * 10 ** 7).to_integral_value())

        frames = {}
        for r in rows:
            frames.setdefault((r["device_uid"], r["packet_index"], r["raw_hex"]), []).append(r)
        per_device = {}
        epoch_of = {}
        n_frames = n_fix = 0
        for (dev, _, raw), rs in frames.items():
            if raw:
                ep, fixes = parse_uplink(bytes.fromhex(raw))
            else:
                fixes = [{"lat_e7": e7(r["lat"]), "lon_e7": e7(r["lon"]),
                          "t": int(r["t"]),
                          "h_acc_dm": int((Decimal(r["h_acc_m"]) * 10).to_integral_value()),
                          "ttff_s": int(r["gps_fix_time_s"])} for r in rs]
                ep = max(f["t"] for f in fixes)
            blk = g.gps_block_encode(fixes, ep, g.FIRMWARE_CAP)
            self.assertTrue(blk)
            self.assertEqual(g.decode(blk, ep), ("ok", spec_projection(fixes)))
            n_frames += 1
            n_fix += len(fixes)
            for f in fixes:
                key = (f["t"], f["lat_e7"], f["lon_e7"])
                per_device.setdefault(dev, {}).setdefault(key, f)
                if raw:
                    epoch_of.setdefault((dev,) + key, ep)

        lines = ["", "field data: %d frames, %d fixes round-tripped" % (n_frames, n_fix),
                 "block bytes over consecutive fixes of one collar "
                 "(non-overlapping runs, a gap over 3 h starts a new run):",
                 "   N  batches  median  p95  max  >180 B"]
        for n in (1, 5, 12, 24, 32):
            sizes = []
            for dev, fx in per_device.items():
                run = []
                for key in sorted(fx, key=lambda k: fx[k]["t"]):
                    f = fx[key]
                    if run and f["t"] - run[-1][1]["t"] > 3 * 3600:
                        run = []
                    run.append((key, f))
                    if len(run) == n:
                        batch = [x for _, x in run]
                        ep = epoch_of.get((dev,) + run[-1][0], run[-1][1]["t"])
                        blk = g.gps_block_encode(batch, ep, 1 << 20)
                        self.assertEqual(g.decode(blk, ep), ("ok", spec_projection(batch)))
                        sizes.append(len(blk))
                        run = []
            sizes.sort()
            p95 = sizes[max(0, ceil(0.95 * len(sizes)) - 1)]
            lines.append("  %2d  %7d  %6.1f  %3d  %3d  %5d" % (
                n, len(sizes), statistics.median(sizes), p95, sizes[-1],
                sum(s > g.FIRMWARE_CAP for s in sizes)))
        sys.stderr.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    unittest.main()
