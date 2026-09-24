#!/usr/bin/env python3
"""Write ../test_vectors/gps_block_v1.json from the reference codec.

    python3 make_vectors.py           rewrite the JSON
    python3 make_vectors.py --check   exit 1 if the checked-in JSON is stale

Deterministic on every platform: fixed seeds, an integer PRNG (SplitMix64) and
only IEEE-exact float operations (+ - * / sqrt), so the file comes out byte
for byte the same. Do not edit the JSON by hand; change this script.

Every track here is SYNTHETIC. The spots are fictional (open ocean, a generic
savanna point, the Arctic, the antimeridian) and every time is in 2027 or
later. What makes the realistic batches realistic is only their statistics,
which were measured on field data and are reproduced by the tables below:
fix spacing and its jitter, step lengths (5-min steps: median about 16 m,
p90 about 50 m, p99 about 180 m), horizontal accuracy (median about 19 m,
nearly all under 30 m), time to fix (median 10 s, p90 35 s) and the age of the
newest fix at uplink (median about 30 s). No field position, time or device id
is in this repository.
"""

import json
import os
import sys

import gps_block as g

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, os.pardir, "test_vectors", "gps_block_v1.json")

CAP = g.FIRMWARE_CAP
GATE = g.CLOCK_GATE_EPOCH
U32 = g.UINT32_MAX
T0 = 1800000000                      # 2027-01-15T08:00:00Z, synthetic

# Fictional spots: (lat_e7, lon_e7, cos(lat) as a constant, not computed).
SAVANNA = (-15000000, 355000000, 0.99966)        # a generic savanna point
OCEAN_SW = (-310000000, -1400000000, 0.85717)    # open South Pacific
ATLANTIC = (100000000, -300000000, 0.98481)      # open mid-Atlantic
ARCTIC = (840000000, 600000000, 0.10453)         # Arctic Ocean
ANTIMERIDIAN = (-200000000, 1799990000, 0.93969) # open ocean at 180 deg

M_PER_E7 = 0.0111319491              # metres per 1e-7 degree of latitude

# Inverse CDFs (probability, value), piecewise linear, shaped like field data.
HACC_DM = [(0.0, 6), (0.1, 68), (0.2, 126), (0.3, 153), (0.4, 173),
           (0.5, 186), (0.6, 194), (0.7, 201), (0.8, 245), (0.9, 276),
           (0.99, 299), (1.0, 300)]
TTFF_S = [(0.0, 1), (0.05, 4), (0.25, 6), (0.5, 10), (0.75, 21), (0.9, 35),
          (0.95, 49), (0.99, 78), (0.999, 300), (1.0, 600)]
JITTER_S = [(0.0, -14), (0.01, -2), (0.05, 4), (0.1, 6), (0.19, 7),
            (0.28, 8), (0.39, 9), (0.49, 10), (0.57, 11), (0.63, 12),
            (0.71, 14), (0.78, 16), (0.83, 19), (0.87, 22), (0.91, 25),
            (0.95, 30), (0.975, 35), (1.0, 40)]
AGE_S = [(0.0, 0), (0.45, 0), (0.5, 33), (0.6, 65), (0.7, 97), (0.8, 145),
         (0.9, 226), (0.95, 302), (0.99, 858), (1.0, 1880)]

# Behaviour model fitted to the field step-length distribution.
NOISE_K = 0.25                       # per-axis position noise = 0.25 * h_acc
GRAZE_MPS = (0.03, 0.08)             # speed = a + b * uniform
TRAVEL_MPS = (0.2, 0.6)
P_REST_TO_GRAZE, P_GRAZE_TO_REST, P_GRAZE_TO_TRAVEL, P_TRAVEL_TO_GRAZE = \
    0.3, 0.15, 0.03, 0.4


class Rng:
    """SplitMix64; integer state, so identical on every platform."""
    M = (1 << 64) - 1

    def __init__(self, seed):
        self.s = seed & self.M

    def next64(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & self.M
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.M
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.M
        return z ^ (z >> 31)

    def uniform(self):
        return (self.next64() >> 11) / 9007199254740992.0

    def randint(self, lo, hi):
        return lo + self.next64() % (hi - lo + 1)

    def normal(self):
        a = 0.0
        for _ in range(12):             # Irwin-Hall: no libm, exact everywhere
            a += self.uniform()
        return a - 6.0

    def table(self, pts):
        u = self.uniform()
        for (p0, v0), (p1, v1) in zip(pts, pts[1:]):
            if u <= p1:
                return v0 + (v1 - v0) * (u - p0) / (p1 - p0)
        return pts[-1][1]

    def itable(self, pts):
        return int(round(self.table(pts)))


def wrap_lon(lon_e7):
    while lon_e7 > 1800000000:
        lon_e7 -= 3600000000
    while lon_e7 < -1800000000:
        lon_e7 += 3600000000
    return lon_e7


def animal_track(seed, n, spot, cadence_s, t_start, jitter_scale=1.0,
                 force_state=None):
    """n fixes of a synthetic animal, oldest first."""
    rng = Rng(seed)
    lat0, lon0, coslat = spot
    state = force_state or "rest"
    x = y = 0.0
    hx, hy = 1.0, 0.0
    t = t_start
    out = []
    for i in range(n):
        if i:
            t += cadence_s + int(round(rng.table(JITTER_S) * jitter_scale))
        u = rng.uniform()
        if force_state is None:
            if state == "rest" and u < P_REST_TO_GRAZE:
                state = "graze"
            elif state == "graze" and u < P_GRAZE_TO_REST:
                state = "rest"
            elif state == "graze" and u < P_GRAZE_TO_REST + P_GRAZE_TO_TRAVEL:
                state = "travel"
            elif state == "travel" and u < P_TRAVEL_TO_GRAZE:
                state = "graze"
        hx += 0.6 * rng.normal()
        hy += 0.6 * rng.normal()
        r = (hx * hx + hy * hy) ** 0.5 or 1.0
        hx, hy = hx / r, hy / r
        if state == "graze":
            v = GRAZE_MPS[0] + GRAZE_MPS[1] * rng.uniform()
        elif state == "travel":
            v = TRAVEL_MPS[0] + TRAVEL_MPS[1] * rng.uniform()
        else:
            v = 0.0
        step = v * cadence_s
        x += step * hx
        y += step * hy
        h_acc_dm = rng.itable(HACC_DM)
        s = NOISE_K * h_acc_dm / 10.0
        fx = x + s * rng.normal()
        fy = y + s * rng.normal()
        out.append({
            "lat_e7": lat0 + int(round(fy / M_PER_E7)),
            "lon_e7": wrap_lon(lon0 + int(round(fx / (M_PER_E7 * coslat)))),
            "t": t,
            "h_acc_dm": h_acc_dm,
            "ttff_s": rng.itable(TTFF_S),
        })
    return out


def uplink_epoch(seed, fixes):
    return max(f["t"] for f in fixes) + Rng(seed).itable(AGE_S)


def fix(lat_e7, lon_e7, t, h_acc_dm=150, ttff_s=10):
    return {"lat_e7": lat_e7, "lon_e7": lon_e7, "t": t,
            "h_acc_dm": h_acc_dm, "ttff_s": ttff_s}


def widths(fixes, header_epoch):
    return {name: value for name, _, value in g.layout(fixes, header_epoch)
            if name.endswith("_w")}


# ---------------------------------------------------------------- vectors

VECTORS = []
DECODER_ONLY = []


def vec(name, note, header_epoch, fixes, cap=CAP, check=None):
    blk = g.gps_block_encode(fixes, header_epoch, cap)
    nbits = g.gps_block_bits(fixes, header_epoch)
    v = {"name": name, "note": note, "header_epoch": header_epoch,
         "cap": cap, "fixes": fixes, "bits": nbits,
         "hex": blk.hex() if blk else None}
    if blk:
        status, decoded = g.decode(blk, header_epoch)
        assert status == "ok", (name, status, decoded)
        v["decoded"] = decoded
    else:
        v["decoded"] = []
        if nbits:                       # refused for the cap only
            v["hex_uncapped"] = g.gps_block_encode(fixes, header_epoch,
                                                   1 << 20).hex()
    if check:
        assert check(v), name
    assert not any(x["name"] == name for x in VECTORS), name
    VECTORS.append(v)
    return v


def dec(name, why, header_epoch, block, expect):
    status, out = g.decode(block, header_epoch)
    if expect in ("ignored", "empty"):
        assert status == expect, (name, status, out)
    else:
        assert status == "ok" and out == expect, (name, status, out)
    assert not any(x["name"] == name for x in DECODER_ONLY), name
    DECODER_ONLY.append({"name": name, "why": why,
                         "header_epoch": header_epoch, "hex": block.hex(),
                         "expect": expect})


def nbytes(v):
    return len(v["hex"]) // 2 if v["hex"] else 0


def layout_value(v, field):
    return [x for name, _, x in g.layout(v["fixes"], v["header_epoch"])
            if name == field][0]


def build():
    del VECTORS[:]
    del DECODER_ONLY[:]
    sav_lat, sav_lon, _ = SAVANNA

    # --- basics ------------------------------------------------------------
    one = [fix(sav_lat + 123456, sav_lon - 98765, T0, 184, 12)]
    vec("single_fix", "N = 1: ttff0 is sent instead of max/rest.",
        T0 + 47, one)

    vec("n2_identical_positions",
        "Same position, two times: lat_w = lon_w = 0, no delta bits.",
        T0 + 330,
        [fix(sav_lat, sav_lon, T0, 120, 8), fix(sav_lat, sav_lon, T0 + 309, 95, 5)],
        check=lambda v: widths(v["fixes"], v["header_epoch"])["lat_w"] == 0 and
        widths(v["fixes"], v["header_epoch"])["lon_w"] == 0)

    same = fix(sav_lat + 5000, sav_lon + 7000, T0 + 600, 150, 9)
    vec("n3_identical_fixes_129_bits",
        "Three identical fixes and age 1: 129 bits, so the block is 17 bytes "
        "with 7 pad bits (one bit past a byte boundary).",
        T0 + 601, [dict(same), dict(same), dict(same)],
        check=lambda v: v["bits"] == 129 and nbytes(v) == 17)

    rest = animal_track(101, 12, ATLANTIC, 300, T0, force_state="rest")
    vec("stationary_jitter_n12",
        "Resting animal, 5-min fixes: position noise only.",
        uplink_epoch(102, rest), rest)

    moving = animal_track(111, 12, SAVANNA, 300, T0 + 86400,
                          force_state="travel")
    vec("moving_track_n12", "Travelling animal, 5-min fixes.",
        uplink_epoch(112, moving), moving)

    sw = animal_track(121, 5, OCEAN_SW, 300, T0 + 2 * 86400)
    vec("southern_western_hemisphere",
        "Negative latitude and longitude throughout.",
        uplink_epoch(122, sw), sw,
        check=lambda v: all(f["lat_e7"] < 0 and f["lon_e7"] < 0
                            for f in v["decoded"]))

    # --- quantization ------------------------------------------------------
    vec("half_step_positive",
        "lat_e7 and lon_e7 end in 50: q rounds half up (123456750 -> "
        "123456800).",
        T0 + 10, [fix(123456750, 1234567850, T0)],
        check=lambda v: v["decoded"][0]["lat_e7"] == 123456800 and
        v["decoded"][0]["lon_e7"] == 1234567900)
    vec("half_step_negative",
        "Negative half step rounds up too: -123456750 -> -123456700.",
        T0 + 10, [fix(-123456750, -1234567850, T0)],
        check=lambda v: v["decoded"][0]["lat_e7"] == -123456700 and
        v["decoded"][0]["lon_e7"] == -1234567800)
    vec("negative_floor_not_truncation",
        "-123456751 -> -123456800 by floor division; C truncation would "
        "give -123456700.",
        T0 + 10, [fix(-123456751, -1234567851, T0), fix(-123456749, -1234567849, T0 - 300)],
        check=lambda v: v["decoded"][1]["lat_e7"] == -123456800 and
        v["decoded"][1]["lon_e7"] == -1234567900 and
        v["decoded"][0]["lat_e7"] == -123456700)

    # --- ordering ----------------------------------------------------------
    eq = [fix(sav_lat + 1000 * k, sav_lon - 700 * k, T0 + 3600, 100 + 10 * k, 5 + k)
          for k in range(4)]
    vec("equal_timestamps",
        "Four fixes with one timestamp: the decoder returns them in input "
        "order.",
        T0 + 3650, eq,
        check=lambda v: [(f["lat_e7"], f["lon_e7"]) for f in v["decoded"]] ==
        [(100 * g.q(f["lat_e7"]), 100 * g.q(f["lon_e7"])) for f in v["fixes"]])

    un = animal_track(131, 6, SAVANNA, 300, T0 + 3 * 86400)
    shuffled = [un[i] for i in (3, 0, 5, 1, 4, 2)]
    vec("unsorted_input",
        "Input out of time order; decoded comes back oldest first.",
        uplink_epoch(132, un), shuffled,
        check=lambda v: [f["t"] for f in v["decoded"]] ==
        sorted(f["t"] for f in v["fixes"]))

    mixed = [fix(sav_lat, sav_lon, T0 + 600, 100, 5),
             fix(sav_lat + 300, sav_lon, T0, 110, 6),
             fix(sav_lat + 600, sav_lon, T0 + 600, 120, 7),
             fix(sav_lat + 900, sav_lon, T0 + 300, 130, 8),
             fix(sav_lat + 1200, sav_lon, T0 + 600, 140, 9)]
    vec("unsorted_with_ties",
        "Out of order with a three-way tie: decoded is a stable ascending "
        "sort of the input.",
        T0 + 700, mixed,
        check=lambda v: [f["lat_e7"] for f in v["decoded"]] ==
        [100 * g.q(sav_lat + d) for d in (300, 900, 0, 600, 1200)])

    # --- age and header epoch ---------------------------------------------
    two = [fix(sav_lat, sav_lon, T0 + 1000, 90, 7), fix(sav_lat + 40, sav_lon + 60, T0 + 1310, 80, 4)]
    vec("age_zero", "header_epoch equals the newest fix time.", T0 + 1310, two,
        check=lambda v: widths(v["fixes"], v["header_epoch"])["age_w"] == 0)
    vec("age_minus_one", "Newest fix one second after header_epoch.",
        T0 + 1309, two,
        check=lambda v: widths(v["fixes"], v["header_epoch"])["age_w"] == 1)
    vec("age_large_negative",
        "header_epoch at the clock gate, fix at 2^32-1: age -2527741695, "
        "age_w = 33 (its maximum).",
        GATE, [fix(sav_lat, sav_lon, U32, 50, 3)],
        check=lambda v: widths(v["fixes"], v["header_epoch"])["age_w"] == 33)
    vec("age_large_positive",
        "header_epoch 2^32-1, fix at the clock gate: age_w = 33.",
        U32, [fix(sav_lat, sav_lon, GATE, 50, 3)],
        check=lambda v: widths(v["fixes"], v["header_epoch"])["age_w"] == 33)
    vec("header_epoch_zero",
        "Raw header epoch 0 (clock never set) with a real fix time: the fix "
        "time still decodes exactly.",
        0, [fix(sav_lat, sav_lon, T0, 150, 30), fix(sav_lat + 20, sav_lon - 30, T0 + 300, 160, 20)],
        check=lambda v: v["decoded"][1]["t"] == T0 + 300)

    # --- coordinate extremes -----------------------------------------------
    am = animal_track(141, 8, ANTIMERIDIAN, 300, T0 + 4 * 86400,
                      force_state="travel")
    for k, f in enumerate(am):          # walk east across 180
        f["lon_e7"] = wrap_lon(ANTIMERIDIAN[1] + 2500 * k + 7 * (k % 3))
    vec("antimeridian_crossing",
        "Track crosses +180 to -180; the format does not wrap, the jump "
        "costs a wide lon_w.",
        uplink_epoch(142, am), am,
        check=lambda v: any(f["lon_e7"] > 0 for f in v["decoded"]) and
        any(f["lon_e7"] < 0 for f in v["decoded"]) and
        widths(v["fixes"], v["header_epoch"])["lon_w"] >= 26)
    vec("poles_and_180",
        "Fixes exactly on lat +-90 and lon +-180 (inside the range): "
        "lat_w = 26 and lon_w = 27, both at their maximum.",
        T0 + 2000,
        [fix(900000000, 1800000000, T0, 30, 5),
         fix(-900000000, -1800000000, T0 + 600, 30, 5),
         fix(900000000, -1800000000, T0 + 1200, 30, 5),
         fix(-900000000, 1800000000, T0 + 1800, 30, 5)],
        check=lambda v: widths(v["fixes"], v["header_epoch"])["lat_w"] == 26 and
        widths(v["fixes"], v["header_epoch"])["lon_w"] == 27)
    vec("time_width_dtmin_32",
        "Two fixes 2527741695 s apart: dtmin_w = 32 (its maximum).",
        U32, [fix(sav_lat, sav_lon, GATE, 50, 3), fix(sav_lat, sav_lon, U32, 50, 3)],
        check=lambda v: widths(v["fixes"], v["header_epoch"])["dtmin_w"] == 32)
    vec("time_width_dt_32",
        "dt_min 0 and one gap of 2527741695 s: dt_w = 32 (its maximum).",
        U32, [fix(sav_lat, sav_lon, GATE, 50, 3), fix(sav_lat, sav_lon, GATE, 50, 3),
              fix(sav_lat, sav_lon, U32, 50, 3)],
        check=lambda v: widths(v["fixes"], v["header_epoch"])["dt_w"] == 32)

    # --- exclusion ---------------------------------------------------------
    good = fix(sav_lat, sav_lon, T0, 150, 9)
    vec("int32_min_excluded",
        "INT32_MIN latitude and INT32_MIN longitude are excluded; the valid "
        "fix goes alone.",
        T0 + 900,
        [fix(g.INT32_MIN, sav_lon, T0 + 300), good, fix(sav_lat, g.INT32_MIN, T0 + 600)],
        check=lambda v: len(v["decoded"]) == 1)
    vec("int32_min_only",
        "Every fix excluded: N = 0, nothing is emitted.",
        T0 + 900, [fix(g.INT32_MIN, g.INT32_MIN, T0)],
        check=lambda v: v["hex"] is None and v["bits"] == 0)
    vec("just_outside_range_excluded",
        "lat 900000001 and lon -1800000001 are excluded.",
        T0 + 900,
        [fix(900000001, 0 + 100, T0 + 60), good, fix(100, -1800000001, T0 + 120)],
        check=lambda v: len(v["decoded"]) == 1)
    vec("null_island_excluded",
        "An input fix at exactly (0, 0) is excluded.",
        T0 + 900, [fix(0, 0, T0 + 300), good],
        check=lambda v: len(v["decoded"]) == 1)
    vec("clock_gate_boundary",
        "t = 1767225599 is excluded, t = 1767225600 is kept.",
        GATE + 400,
        [fix(sav_lat, sav_lon, GATE - 1), fix(sav_lat + 10, sav_lon, GATE),
         fix(sav_lat + 20, sav_lon, GATE + 300)],
        check=lambda v: [f["t"] for f in v["decoded"]] == [GATE, GATE + 300])
    vec("below_clock_gate_only",
        "The only fix is below the clock gate: nothing is emitted.",
        T0, [fix(sav_lat, sav_lon, GATE - 1)],
        check=lambda v: v["hex"] is None)
    near0 = [fix(30, -40, T0 + 300, 60, 6), fix(-50, 49, T0 + 400, 60, 6),
             fix(50, -50, T0 + 500, 60, 6), fix(-51, -99, T0 + 600, 60, 6),
             good]
    vec("near_null_island_excluded",
        "The null island test is on the quantized position: (30, -40) and "
        "(-50, 49) quantize to (0, 0) and are excluded; (50, -50) quantizes "
        "to (1, 0) and (-51, -99) to (-1, -1) by floor division (C "
        "truncation would give (0, 0) and wrongly exclude it); both are "
        "kept.",
        T0 + 900, near0,
        check=lambda v: [(f["lat_e7"], f["lon_e7"]) for f in v["decoded"]] ==
        [(100 * g.q(sav_lat), 100 * g.q(sav_lon)), (100, 0), (-100, -100)] and
        [g.is_excluded(f) for f in v["fixes"]] == [True, True, False, False, False])
    vec("near_null_island_only",
        "The only fix is (49, -49), which quantizes to (0, 0): excluded, "
        "nothing is emitted.",
        T0 + 310, [fix(49, -49, T0 + 300, 60, 6)],
        check=lambda v: v["hex"] is None and v["bits"] == 0)

    r33 = animal_track(151, 33, ATLANTIC, 300, T0 + 5 * 86400, force_state="rest")
    r33[7] = dict(r33[7], t=GATE - 5)
    vec("n33_one_excluded_is_n32",
        "33 fixes, one below the clock gate: N = 32, the maximum.",
        uplink_epoch(152, r33), r33,
        check=lambda v: len(v["decoded"]) == 32 and v["hex"] is not None)
    r33b = animal_track(153, 33, ATLANTIC, 300, T0 + 6 * 86400, force_state="rest")
    vec("n33_refused",
        "33 valid fixes: N > 32, nothing is emitted.",
        uplink_epoch(154, r33b), r33b,
        check=lambda v: v["hex"] is None and v["bits"] == 0)

    # --- accuracy ----------------------------------------------------------
    hs = [0, 1, 9, 10, 11, 20, 21, 611, 619, 620, 621, 1000, U32]
    acc = [fix(sav_lat + 11 * k, sav_lon + 13 * k, T0 + 300 * k, h, 10)
           for k, h in enumerate(hs)]
    vec("accuracy_code_boundaries",
        "h_acc_dm 0, 1, 9, 10, 11, 20, 21, 611, 619, 620, 621, 1000, 2^32-1 "
        "-> h_acc_m null, 1, 1, 1, 2, 2, 3, 62, 62, 62, 63, 63, 63.",
        T0 + 300 * len(hs), acc,
        check=lambda v: [f["h_acc_m"] for f in v["decoded"]] ==
        [None, 1, 1, 1, 2, 2, 3, 62, 62, 62, 63, 63, 63])

    # --- time to fix -------------------------------------------------------
    tt = [fix(sav_lat + 17 * k, sav_lon, T0 + 300 * k, 150, s)
          for k, s in enumerate([1022, 1023, 1024, U32, 5, U32, 7])]
    vec("ttff_saturation_and_tie",
        "ttff 1022, 1023, 1024, 2^32-1, 5, 2^32-1, 7 (oldest first): max ties "
        "at 2^32-1, the newer one (lower wire index) gets ttff_max = 1023; "
        "the mean of the rest saturates at 1023.",
        T0 + 2000, tt,
        check=lambda v: [f["gps_fix_time_s"] for f in v["decoded"]] == [1023] * 7)
    tt2 = [fix(sav_lat + 17 * k, sav_lon, T0 + 300 * k, 150, s)
           for k, s in enumerate([5, 40, 12, 40])]
    vec("ttff_tie_lowest_wire_index",
        "ttff 5, 40, 12, 40 (oldest first): the newest 40 is wire index 0 "
        "and keeps 40; the older 40 gets the mean of the rest, "
        "(5 + 40 + 12) / 3 = 19.",
        T0 + 1000, tt2,
        check=lambda v: [f["gps_fix_time_s"] for f in v["decoded"]] == [19, 19, 19, 40])
    tt3 = [fix(sav_lat + 17 * k, sav_lon, T0 + 300 * k, 150, s)
           for k, s in enumerate([1, 100, 2])]
    vec("ttff_mean_rounds_half_up",
        "ttff 1, 100, 2: the rest mean 1.5 rounds up to 2.",
        T0 + 700, tt3,
        check=lambda v: [f["gps_fix_time_s"] for f in v["decoded"]] == [2, 100, 2])
    vec("ttff_single_saturated",
        "N = 1 with ttff 2^32-1: ttff0 = 1023.",
        T0 + 5, [fix(sav_lat, sav_lon, T0, 150, U32)],
        check=lambda v: v["decoded"][0]["gps_fix_time_s"] == 1023)
    tt4 = [fix(sav_lat + 17 * k, sav_lon, T0 + 300 * k, 150, s)
           for k, s in enumerate([10, 3000, 1500])]
    vec("ttff_kmax_raw_not_saturated",
        "Wire-order ttff 1500, 3000, 10: kmax compares the RAW values, so "
        "kmax = 1 and the rest mean is (1500 + 10) / 2 = 755. Comparing "
        "saturated values (1023, 1023, 10) would tie and give kmax = 0.",
        T0 + 700, tt4,
        check=lambda v: layout_value(v, "ttff_kmax") == 1 and
        [f["gps_fix_time_s"] for f in v["decoded"]] == [755, 1023, 755])
    tt5 = [fix(sav_lat + 17 * k, sav_lon, T0 + 300 * k, 150, s)
           for k, s in enumerate([5, 1023, 1025, 1024])]
    vec("ttff_saturated_tie_not_raw_tie",
        "Wire-order ttff 1024, 1025, 1023, 5: the saturated values tie at "
        "1023 on wire 0..2 (lowest index 0), the raw maximum is wire 1. "
        "kmax = 1; the rest mean (1024 + 1023 + 5) / 3 rounds to 684.",
        T0 + 1000, tt5,
        check=lambda v: layout_value(v, "ttff_kmax") == 1 and
        [f["gps_fix_time_s"] for f in v["decoded"]] == [684, 684, 1023, 684])
    tt6 = [fix(sav_lat + 17 * k, sav_lon, T0 + 300 * k, 150, s)
           for k, s in enumerate([9, 0, 30])]
    del tt6[1]["ttff_s"]
    vec("ttff_absent_is_zero",
        "The middle fix has no ttff_s: it is read as 0. Wire-order ttff 30, "
        "0, 9: kmax = 0, and the rest mean (0 + 9) / 2 rounds up to 5.",
        T0 + 700, tt6,
        check=lambda v: "ttff_s" not in v["fixes"][1] and
        [f["gps_fix_time_s"] for f in v["decoded"]] == [5, 5, 30] and
        g.gps_block_encode(v["fixes"], v["header_epoch"], CAP) ==
        g.gps_block_encode([dict(f, ttff_s=f.get("ttff_s", 0))
                            for f in v["fixes"]], v["header_epoch"], CAP))
    one_absent = {"lat_e7": sav_lat, "lon_e7": sav_lon, "t": T0, "h_acc_dm": 150}
    vec("ttff_absent_single",
        "N = 1 without ttff_s: ttff0 = 0.",
        T0 + 5, [one_absent],
        check=lambda v: v["decoded"][0]["gps_fix_time_s"] == 0)

    # --- realistic batches (synthetic, statistics from field data) ---------
    b5 = animal_track(201, 5, ATLANTIC, 300, T0 + 10 * 86400)
    vec("realistic_n5_5min", "Five 5-min fixes, the old per-packet limit.",
        uplink_epoch(202, b5), b5)
    b12 = animal_track(211, 12, SAVANNA, 300, T0 + 11 * 86400)
    vec("realistic_n12_hourly_5min",
        "Hourly uplink of 5-min fixes, grazing animal.",
        uplink_epoch(212, b12), b12)
    b24 = animal_track(221, 24, ARCTIC, 150, T0 + 12 * 86400, jitter_scale=0.5)
    vec("realistic_n24_hourly_150s",
        "Hourly uplink of 2.5-min fixes at 84 N (lon deltas are 10x wider "
        "in 1e-5 deg than at the equator).",
        uplink_epoch(222, b24), b24)
    b24b = animal_track(231, 24, OCEAN_SW, 300, T0 + 13 * 86400)
    vec("realistic_n24_2h_5min", "Two hours of 5-min fixes.",
        uplink_epoch(232, b24b), b24b)

    veh = vehicle_track()
    vec("vehicle_n24_near_cap",
        "Translocation by vehicle inside a 24-fix window of ~27-min fixes, "
        "with a 3-hour gap: lat_w 14, lon_w 16, dt_w 14, like the largest "
        "real block (160 B).",
        veh[-1]["t"], veh,
        check=lambda v: 150 <= nbytes(v) <= CAP and
        widths(v["fixes"], v["header_epoch"]) ==
        {"age_w": 0, "lat_w": 14, "lon_w": 16, "dtmin_w": 11, "dt_w": 14})

    mig = migration_track()
    over = vec("moving_n32_over_cap",
               "32 fixes of a fast mover at 84 N: the block needs more than "
               "180 B, so the encoder refuses (hex null) and the caller "
               "drops fixes. hex_uncapped is the block without a cap.",
               uplink_epoch(252, mig), mig,
               check=lambda v: v["hex"] is None and v["bits"] > 8 * CAP)

    # --- cap boundary ------------------------------------------------------
    fitb = g.gps_block_encode(b12, uplink_epoch(212, b12), CAP)
    vec("cap_exact_fit", "cap equal to the block length: emitted.",
        uplink_epoch(212, b12), b12, cap=len(fitb),
        check=lambda v: v["hex"] == fitb.hex())
    vec("cap_one_short", "cap one byte short: refused, never truncated.",
        uplink_epoch(212, b12), b12, cap=len(fitb) - 1,
        check=lambda v: v["hex"] is None)

    build_decoder_only(over)


def vehicle_track():
    """24 fixes: grazing at ~27-min fixes, a vehicle leg of several km per
    step, a 3-hour gap, then grazing at ~30-min fixes."""
    rng = Rng(241)
    lat0, lon0, coslat = SAVANNA
    lat0 += 2500000
    x = y = 0.0
    t = T0 + 20 * 86400
    legs = [(4200.0, -1500.0), (11800.0, 3100.0), (19400.0, 7600.0),
            (-6300.0, 5200.0), (8800.0, -2400.0)]        # metres per step
    out = []
    for i in range(24):
        if i:
            if i < 12:
                t += 1600 + rng.randint(-8, 14)
            elif i == 12:
                t += 1600 + 9050                       # the gap
            else:
                t += 1790 + rng.randint(-4, 70)
        if 7 <= i < 12:
            dx, dy = legs[i - 7]
            x += dx
            y += dy
        else:
            x += 20.0 * rng.normal()
            y += 20.0 * rng.normal()
        h = rng.itable(HACC_DM)
        s = NOISE_K * h / 10.0
        out.append({"lat_e7": lat0 + int(round((y + s * rng.normal()) / M_PER_E7)),
                    "lon_e7": lon0 + int(round((x + s * rng.normal()) / (M_PER_E7 * coslat))),
                    "t": t, "h_acc_dm": h, "ttff_s": rng.itable(TTFF_S)})
    return out


def migration_track():
    """32 fixes of a fast mover at 84 N, 15-min fixes with two missed ones."""
    fixes = animal_track(251, 34, ARCTIC, 900, T0 + 30 * 86400,
                         force_state="travel")
    rng = Rng(253)
    lat0, lon0, _ = ARCTIC
    for f in fixes:                      # a faster mover than the model's
        f["lat_e7"] = lat0 + 4 * (f["lat_e7"] - lat0) + rng.randint(-40, 40)
        f["lon_e7"] = lon0 + 4 * (f["lon_e7"] - lon0)
    return [f for k, f in enumerate(fixes) if k not in (10, 23)]


def build_decoder_only(over):
    ep = T0 + 1000
    base = [fix(123456700, -45678900, T0 + 600, 150, 9),
            fix(123457700, -45679900, T0, 170, 20),
            fix(123458700, -45680900, T0 + 300, 160, 12)]
    good = g.gps_block_encode(base, ep, CAP)
    fields = g.layout(base, ep)
    one = g.gps_block_encode(base[:1], ep, CAP)

    def mod(fl, **changes):
        """Replace fields by name: value, or (width, value); a changed
        width field re-widths the fields it governs."""
        out = []
        governs = {"lat_w": "dlat[", "lon_w": "dlon[", "dt_w": "ddt[",
                   "dtmin_w": "dt_min", "age_w": "age"}
        newwidth = {}
        for name, w, v in fl:
            if name in changes:
                c = changes[name]
                w, v = c if isinstance(c, tuple) else (w, c)
                if name in governs:
                    newwidth[governs[name]] = v
            for prefix, nw in newwidth.items():
                if name == prefix or (prefix.endswith("[") and name.startswith(prefix)):
                    w = nw
            out.append((name, w, v))
        return out

    dec("zero_length", "An empty gps_block carries no fixes; not an error.",
        ep, b"", "empty")
    dec("one_byte", "Version 1, N = 1, then nothing: read past end.",
        ep, bytes([0x20]), "ignored")
    dec("truncated_header", "First 5 bytes of a valid 3-fix block.",
        ep, good[:5], "ignored")
    dec("truncated_last_byte", "A valid 3-fix block without its last byte.",
        ep, good[:-1], "ignored")
    assert (sum(w for _, w, _ in fields)) % 8 != 0
    dec("nonzero_padding", "A valid block with its last pad bit set.",
        ep, good[:-1] + bytes([good[-1] | 1]), "ignored")
    dec("extra_trailing_byte", "A valid block plus one 0x00 byte.",
        ep, good + b"\x00", "ignored")
    dec("version_0", "Version 0 is reserved and invalid.",
        ep, bytes([good[0] & 0x1F]) + good[1:], "ignored")
    dec("version_2", "A v1 body under version 2: not implemented, ignored.",
        ep, bytes([(good[0] & 0x1F) | 0x40]) + good[1:], "ignored")
    dec("version_7", "Version 7: ignored.",
        ep, bytes([good[0] | 0xE0]) + good[1:], "ignored")
    dec("valid_three_fixes", "The unmodified base block of this section.",
        ep, good, g.decode(good, ep)[1])
    dec("lat0_out_of_range", "lat0 decodes to q = 9000001 (just past +90).",
        ep, g.pack(mod(fields, lat0=g.zz(9000001))), "ignored")
    dec("lon0_out_of_range", "lon0 decodes to q = -18000001 (just past -180).",
        ep, g.pack(mod(fields, lon0=g.zz(-18000001))), "ignored")
    dec("lat0_max_zigzag", "lat0 = 2^25-1, the largest the field holds.",
        ep, g.pack(mod(fields, lat0=(1 << 25) - 1)), "ignored")
    pole = g.layout([fix(899998500, 100000, T0), fix(899999500, 100000, T0 + 300)], T0 + 300)
    assert g.decode(g.pack(pole), T0 + 300)[0] == "ok"
    dec("delta_walks_past_pole",
        "Newest fix at q_lat 8999995; the delta to the older fix is +10 "
        "instead of -10, which puts it at 9000005, past +90.",
        T0 + 300, g.pack(mod(pole, **{"dlat[1]": g.zz(10)})), "ignored")
    am = g.layout([fix(100000, 1799999000, T0), fix(100000, 1799990000, T0 + 300)], T0 + 300)
    assert g.decode(g.pack(am), T0 + 300)[0] == "ok"
    dec("delta_walks_past_180",
        "Newest fix at q_lon 17999900; a delta of +101 puts the older fix "
        "at 18000001, past +180.",
        T0 + 300, g.pack(mod(am, **{"dlon[1]": g.zz(101)})), "ignored")
    dec("ttff_kmax_ge_n", "N = 3 and ttff_kmax = 3.",
        ep, g.pack(mod(fields, ttff_kmax=3)), "ignored")
    dec("age_w_34", "age_w = 34, above its maximum 33.",
        ep, g.pack(mod(fields, age_w=34, age=(34, 5))), "ignored")
    dec("lat_w_27", "lat_w = 27, above its maximum 26.",
        ep, g.pack(mod(fields, lat_w=27)), "ignored")
    dec("lon_w_28", "lon_w = 28, above its maximum 27.",
        ep, g.pack(mod(fields, lon_w=28)), "ignored")
    dec("dtmin_w_33", "dtmin_w = 33, above its maximum 32.",
        ep, g.pack(mod(fields, dtmin_w=33, dt_min=(33, 300))), "ignored")
    dec("dt_w_33", "dt_w = 33, above its maximum 32.",
        ep, g.pack(mod(fields, dt_w=33)), "ignored")
    dec("t0_below_gate",
        "header_epoch = gate + 10 and age 20: newest fix 10 s before the gate.",
        GATE + 10, g.pack(mod(g.layout(base[:1], GATE + 10),
                              age_w=6, age=(6, g.zz(20)))), "ignored")
    low = g.layout([fix(1000000, 1000000, GATE + 100), fix(1000100, 1000000, GATE + 400)], GATE + 400)
    dec("tk_below_gate",
        "dt_min raised by 200: the older fix lands 100 s before the gate.",
        GATE + 400, g.pack(mod(low, dtmin_w=9, dt_min=(9, 500))), "ignored")
    dec("t0_above_uint32",
        "header_epoch 2^32-1 and age -1: newest fix at 2^32.",
        U32, g.pack(mod(g.layout(base[:1], U32), age_w=1, age=(1, g.zz(-1)))),
        "ignored")
    null1 = g.layout(base[:1], ep)
    dec("q_zero_zero_newest",
        "N = 1 with lat0 = lon0 = zz(0): the fix reconstructs to q = (0, 0), "
        "which the encoder never emits, so the whole block is corrupt.",
        ep, g.pack(mod(null1, lat0=0, lon0=0)), "ignored")
    near = g.layout([fix(100, 100, T0), fix(200, 200, T0 + 300)], T0 + 300)
    assert g.decode(g.pack(near), T0 + 300)[0] == "ok"
    dec("q_zero_zero_after_delta",
        "Newest fix at q = (2, 2); deltas of (-2, -2) put the older fix at "
        "q = (0, 0): the whole block is corrupt, the newest fix is not "
        "returned either.",
        T0 + 300, g.pack(mod(near, lat_w=2, lon_w=2,
                             **{"dlat[1]": g.zz(-2), "dlon[1]": g.zz(-2)})),
        "ignored")
    dec("q_zero_one_decodes",
        "Control for the two above: the older fix at q = (0, 1) is a valid "
        "position and decodes.",
        T0 + 300, g.pack(mod(near, lat_w=2, lon_w=2,
                             **{"dlat[1]": g.zz(-2), "dlon[1]": g.zz(-1)})),
        [{"lat_e7": 0, "lon_e7": 100, "t": T0, "h_acc_m": 15,
          "gps_fix_time_s": 10},
         {"lat_e7": 200, "lon_e7": 200, "t": T0 + 300, "h_acc_m": 15,
          "gps_fix_time_s": 10}])
    assert one
    dec("over_cap_block_still_decodes",
        "The N = 32 block that the firmware cap refuses (moving_n32_over_cap): "
        "the decoder does not enforce the 180 B cap and decodes it.",
        over["header_epoch"], bytes.fromhex(over["hex_uncapped"]),
        g.decode(bytes.fromhex(over["hex_uncapped"]), over["header_epoch"])[1])


# ---------------------------------------------------------------- output

def _line(obj):
    return json.dumps(obj, separators=(", ", ": "))


def render():
    build()
    head = {
        "format": "CollarID GPS block v1 test vectors",
        "spec": "reference/GPS_BLOCK_V1.md",
        "generator": "reference/make_vectors.py (deterministic; do not edit "
                     "this file by hand)",
        "conventions": [
            "All numbers are integers. In decoded output h_acc_m is an "
            "integer or null (unknown accuracy); gps_fix_time_s is always an "
            "integer in v1.",
            "vectors: gps_block_encode(fixes, header_epoch, cap) must return "
            "hex (null = emit nothing), gps_block_bits(fixes, header_epoch) "
            "must return bits (0 when N after exclusion is outside 1..32), "
            "and decode(hex, header_epoch) must return ok with decoded, "
            "oldest first.",
            "cap is the cap passed to gps_block_encode: 180 (the nanopb "
            "max_size) unless the vector tests the cap itself.",
            "decoded is [] when hex is null. hex_uncapped (only when the cap "
            "alone refused) is the block the layout gives without a cap; the "
            "decoder does not enforce the cap and must decode it.",
            "A fix may omit h_acc_dm (unknown accuracy, like 0) or ttff_s "
            "(read as 0).",
            "note (vectors) and why (decoder_only) are free text for humans; "
            "tests ignore them.",
            "decoder_only: decode(hex, header_epoch) must give expect: "
            "\"ignored\", \"empty\", or ok with that list of fixes.",
            "Every track is synthetic, at fictional locations. Times are 2027 "
            "or later, except the clock-gate and range-limit cases, which sit "
            "on the constants 1767225600 (2026-01-01) and 2^32-1. No field "
            "data.",
        ],
    }
    lines = ["{"]
    for k, v in head.items():
        if isinstance(v, list):
            lines.append("  %s: [" % json.dumps(k))
            for n, e in enumerate(v):
                lines.append("    %s%s" % (json.dumps(e), "," if n < len(v) - 1 else ""))
            lines.append("  ],")
        else:
            lines.append("  %s: %s," % (json.dumps(k), json.dumps(v)))

    def block(key, items, last):
        lines.append("  %s: [" % json.dumps(key))
        for i, item in enumerate(items):
            lines.append("    {")
            keys = list(item)
            for j, k in enumerate(keys):
                val = item[k]
                comma = "," if j < len(keys) - 1 else ""
                if isinstance(val, list) and val and isinstance(val[0], dict):
                    lines.append("      %s: [" % json.dumps(k))
                    for n, e in enumerate(val):
                        lines.append("        %s%s" % (_line(e), "," if n < len(val) - 1 else ""))
                    lines.append("      ]%s" % comma)
                else:
                    lines.append("      %s: %s%s" % (json.dumps(k), _line(val), comma))
            lines.append("    }%s" % ("," if i < len(items) - 1 else ""))
        lines.append("  ]%s" % ("" if last else ","))

    block("vectors", VECTORS, False)
    block("decoder_only", DECODER_ONLY, True)
    lines.append("}")
    text = "\n".join(lines) + "\n"
    assert json.loads(text)["vectors"] == json.loads(json.dumps(VECTORS))
    return text


def main(argv):
    text = render()
    if "--check" in argv:
        with open(OUT, encoding="utf-8") as fh:
            same = fh.read() == text
        print("up to date" if same else "STALE: run make_vectors.py")
        return 0 if same else 1
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote %s: %d vectors, %d decoder-only"
          % (os.path.normpath(OUT), len(VECTORS), len(DECODER_ONLY)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
