#!/usr/bin/env python3
"""The C engine of direct-radio regions (c/direct_rules.c, its generated
table c/direct_rules_table.c, and wake_frame.c's two functions that read
it) against every direct_regions vector of test_vectors/contracts_v1.json.

    cd beacon && python3 -m unittest -v test_direct_rules_c

c/direct_rules.[ch] and the table are what the collar firmware (STM32, C)
and the Spotter (nRF52 Arduino, C++) copy, so the engine is built and run
twice: as C99 and as C++11, each with -Wall -Wextra -Werror -pedantic
(wake_frame.c and aead_ccm.c, which are C11, are compiled as C and linked
in). The harness (c/test/direct_rules_harness.c) is compiled into a
temporary directory and talks line by line. Skipped, not failed, without
a C or C++ compiler.

Standard library only.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _contracts_module(name):
    """contracts/<name>.py by path: putting contracts/ on sys.path would
    shadow this directory's make_vectors.py for the other tests of the run."""
    spec = importlib.util.spec_from_file_location("contracts_" + name, os.path.join(ROOT, "contracts", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


generate = _contracts_module("generate")
R = _contracts_module("reference")

with open(os.path.join(ROOT, "test_vectors", "contracts_v1.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)["direct_regions"]
with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as _fh:
    WAKE = json.load(_fh)["wake_timing"]

CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
CXX = os.environ.get("CXX") or shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
C_DIR = os.path.join(HERE, "c")
ENGINE = [os.path.join(C_DIR, "test", "direct_rules_harness.c"), os.path.join(C_DIR, "direct_rules.c"),
          os.path.join(C_DIR, "direct_rules_table.c")]
C11_PARTS = [os.path.join(C_DIR, "wake_frame.c"), os.path.join(C_DIR, "aead_ccm.c")]
WARN = ["-Wall", "-Wextra", "-Werror", "-pedantic", "-O1", "-I", C_DIR]
DEVICES = {"generic": "gen", "collar_wio": "wio", "collar_mk3": "mk3", "spotter": "spot"}
REASONS = list(VEC["reasons"])
HOWS = list(VEC["convert_how"])
FITS = list(VEC["fit_reasons"])
BELOW_FLOOR = list(R.DR["below_floor"])


def dev(d):
    if isinstance(d, str):
        return DEVICES[d]
    bf = BELOW_FLOOR.index(d.get("below_floor") or "unusable")
    return "%d:%d:%d:%d" % (d["gain_cdbi"], d["min_dbm"], d["max_dbm"], bf)


def build(tmp, cxx):
    """The harness executable, built as C99 (cxx False) or C++11 (True)."""
    objs = []
    for i, src in enumerate(C11_PARTS):
        obj = os.path.join(tmp, "c11_%d.o" % i)
        r = subprocess.run([CC, "-std=c11"] + WARN + ["-c", src, "-o", obj], capture_output=True, text=True)
        if r.returncode:
            raise AssertionError("%s does not compile cleanly as C11:\n%s" % (src, r.stderr))
        objs.append(obj)
    for i, src in enumerate(ENGINE):
        obj = os.path.join(tmp, "%s_%d.o" % ("cxx" if cxx else "c99", i))
        cmd = ([CXX, "-x", "c++", "-std=c++11"] if cxx else [CC, "-std=c99"]) + WARN + ["-c", src, "-o", obj]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise AssertionError("%s does not compile cleanly as %s:\n%s" % (src, "C++" if cxx else "C99", r.stderr))
        objs.append(obj)
    exe = os.path.join(tmp, "direct_rules_harness_" + ("cxx" if cxx else "c99"))
    r = subprocess.run([CXX if cxx else CC, "-o", exe] + objs, capture_output=True, text=True)
    if r.returncode:
        raise AssertionError("the harness does not link:\n" + r.stderr)
    return exe


def synth_lines(rs):
    """The harness commands that build a rule-set dict as the synthetic one (id 99)."""
    lines = ["synthclear"]
    for b in rs["bands"]:
        mask = sum({125: 1, 250: 2, 500: 4}[x] for x in b["bw_khz"])
        lines.append("synthband %d %d %d %d %d %d %d %d %d %d %d %d" % (
            b["lo_khz"], b["hi_khz"], mask, b["grid_base_khz"] or 0, b["grid_step_khz"] or 0, b["budget_ms_per_h"],
            b["eirp_cdbm"], b["lbt_dbm"] or 0, b["lbt_ms"] or 0, b["max_send_ms"], b["pause_ms"], b["conducted_dbm"]))
    d, w = rs["default"], rs["wake"]
    lines.append("synthmeta %d %d %d %d %d %d %d" % (d["freq_khz"], d["bw_khz"], d["sf"], w["freq_hz"], w["bw_khz"],
                                                     w["sf"], w["sf_long"]))
    return lines


class _DirectRules:
    """Every vector, through one build of the harness (C99 or C++)."""

    CXX_BUILD = False

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="direct_rules_c_")
        try:
            cls.exe = build(cls.tmp, cls.CXX_BUILD)
        except Exception:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def ask(self, lines):
        out = subprocess.run([self.exe], input="\n".join(lines) + "\n", capture_output=True,
                             text=True, check=True).stdout.split("\n")[:-1]
        self.assertEqual(len(out), len(lines))
        return out

    def ask_air(self, rs_id, steps, prefix=()):
        lines, want = list(prefix), ["ok"] * len(prefix)
        lines.append("ainit %d" % rs_id)
        want.append("ok")
        for s in steps:
            if s["op"] == "record":
                lines.append("arec %d %d %d" % (s["band"], s["now_s"], s["ms"]))
                want.append("ok")
            elif s["op"] == "used":
                lines.append("aused %d %d" % (s["band"], s["now_s"]))
                want.append(str(s["want"]))
            else:
                lines.append("await %d %d %d %s" % (s["band"], s["now_s"], s["ms"], s["class"]))
                want.append("never" if s["want"] is None else str(s["want"]))
        return lines, want

    # ------------------------------------------------------------ the table

    def test_the_table_is_the_spec(self):
        dr = R.SPEC["direct_regions"]
        self.assertEqual(self.ask(["sha", "counts"]),
                         ["%s %s" % (generate.sha256(R.SPEC), generate.dr_sha256(R.SPEC)),
                          "%d %d" % (len(dr["rule_sets"]), len(dr["countries"]))])
        self.assertEqual(VEC["table_sha256"], generate.dr_sha256(R.SPEC))
        lines, want = [], []
        for r in dr["rule_sets"]:
            d, w = r["default"], r["wake"]
            lines.append("ruleset %d" % r["id"])
            want.append("%d %s %d %d %d %d %d %d %d %d" % (r["id"], r["key"], len(r["bands"]), d["freq_khz"], d["bw_khz"],
                                                          d["sf"], w["freq_hz"], w["bw_khz"], w["sf"], w["sf_long"]))
            lines.append("bykey %s" % r["key"])
            want.append(str(r["id"]))
            for i, b in enumerate(r["bands"]):
                lines.append("band %d %d" % (r["id"], i))
                want.append("%s %d %d %d %d %d %d %d %d %d %d %d %d" % (
                    b["name"], b["lo_khz"], b["hi_khz"], sum({125: 1, 250: 2, 500: 4}[x] for x in b["bw_khz"]),
                    b["grid_base_khz"] or 0, b["grid_step_khz"] or 0, b["budget_ms_per_h"], b["eirp_cdbm"],
                    b["lbt_dbm"] or 0, b["lbt_ms"] or 0, b["max_send_ms"], b["pause_ms"], b["conducted_dbm"]))
            lines.append("band %d %d" % (r["id"], len(r["bands"])))
            want.append("none")
        lines += ["ruleset 0", "ruleset 16", "bykey XX999", "band 0 0", "band 1 -1"]
        want += ["none"] * 5
        conf = {c: i for i, c in enumerate(dr["confidences"])}
        for i, c in enumerate(dr["countries"]):
            lines += ["country %d" % i, "iso %s" % c["iso"]]
            want += ["%s %d %d %s" % (c["iso"], c["rule_set"], conf[c["confidence"]], c["name"]),
                     "%d %d" % (c["rule_set"], conf[c["confidence"]])]
        lines += ["country %d" % len(dr["countries"]), "iso CN", "iso XX"]
        want += ["none"] * 3
        for name, d in dr["devices"].items():
            lines.append("device %s" % DEVICES[name])
            want.append("%d %d %d %d" % (d["gain_cdbi"], d["min_dbm"], d["max_dbm"],
                                         BELOW_FLOOR.index(d.get("below_floor") or "unusable")))
        self.assertEqual(self.ask(lines), want)

    def test_the_table_file_is_current(self):
        with open(generate.TABLE_PATH, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), generate.c_table(R.SPEC), "run contracts/generate.py")

    # ------------------------------------------------------------ check and convert

    def test_the_contract_table_and_the_us_vectors(self):
        lines, want = [], []
        for v in VEC["contract_table"]:
            lines.append("convert %d %d %d %d" % tuple([v["rule_set"]] + v["in"]))
            want.append("%d %d %d %d" % tuple(v["out"] + [HOWS.index(v["how"])]))
        for v in VEC["us500"]:
            (sf, bw, mhz), (osf, obw, omhz) = v["in_mhz"], v["out_mhz"]
            lines += ["convert 1 %d %d %d" % (sf, bw, mhz * 1000), "check 1 %d %d %d gen" % (osf, obw, omhz * 1000),
                      "check 1 %d %d %d gen" % (sf, bw, mhz * 1000)]
            changed = (sf, bw, mhz) != (osf, obw, omhz)
            want += ["%d %d %d %d" % (osf, obw, omhz * 1000, HOWS.index("moved" if changed else "kept")), "0",
                     str(REASONS.index(R.dr_check(1, sf, bw, mhz * 1000)))]
            self.assertEqual(v["in_allowed"], not changed)
        self.assertEqual(self.ask(lines), want)

    def test_the_check_and_convert_sweeps(self):
        lines, want = [], []
        for rs, bw, f, codes in VEC["check_sweep"]["rows"]:
            for sf, code in zip(range(7, 13), codes):
                lines.append("check %d %d %d %d gen" % (rs, sf, bw, f))
                want.append(str(code))
        for rs, bw, f, outs in VEC["convert_sweep"]["rows"]:
            for i, sf in enumerate(range(7, 13)):
                lines.append("convert %d %d %d %d" % (rs, sf, bw, f))
                want.append("%d %d %d %d" % tuple(outs[4 * i:4 * i + 4]))
        self.assertGreater(len(lines), 20000)
        self.assertEqual(self.ask(lines), want)

    def test_odd_inputs_and_devices(self):
        lines, want = [], []
        for v in VEC["odd_inputs"]:
            lines += ["check %d %d %d %d gen" % (v["rule_set"], v["sf"], v["bw_khz"], v["freq_khz"]),
                      "convert %d %d %d %d" % (v["rule_set"], v["sf"], v["bw_khz"], v["freq_khz"])]
            want += [str(REASONS.index(v["check"])), "%d %d %d %d" % tuple(v["out"] + [HOWS.index(v["how"])])]
        for v in VEC["check_devices"]:
            lines.append("check %d %d %d %d %s" % (v["rule_set"], v["sf"], v["bw_khz"], v["freq_khz"], dev(v["device"])))
            want.append(str(REASONS.index(v["reason"])))
        for v in VEC["power_caps"]:
            lines += ["cap %d %d %s" % (v["rule_set"], v["band"], dev(v["device"])),
                      "allowed %d %d %s" % (v["rule_set"], v["band"], dev(v["device"]))]
            want += ["%d %d" % (v["cap_dbm"], 1 if v["usable"] else 0), str(v["allowed_dbm"])]
        for v in VEC["below_floor"]:
            lines += ["cap %d %d %s" % (v["rule_set"], v["band"], dev(v["device"])),
                      "allowed %d %d %s" % (v["rule_set"], v["band"], dev(v["device"])),
                      "check %d %d %d %d %s" % (v["rule_set"], v["sf"], v["bw_khz"], v["freq_khz"], dev(v["device"]))]
            want += ["%d %d" % (v["cap_dbm"], 1 if v["usable"] else 0), str(v["allowed_dbm"]),
                     str(REASONS.index(v["reason"]))]
        for v in VEC["band_of"]:
            lines.append("bandof %d %d %d" % (v["rule_set"], v["freq_khz"], v["bw_khz"]))
            want.append(str(v["band"]))
        self.assertEqual(self.ask(lines), want)

    # ------------------------------------------------------------ time on air, limits

    def test_time_on_air_and_send_limits(self):
        lines, want = [], []
        for sf, bw, n, us in VEC["toa"]["rows"]:
            lines.append("toa %d %d %d" % (sf, bw, n))
            want.append(str(us))
        for sf, bw, ms, n in VEC["max_len"]["rows"]:
            lines.append("maxlen %d %d %d" % (sf, bw, ms))
            want.append(str(n))
        for v in VEC["band_limits"]:
            lines += ["lbt %d %d" % (v["rule_set"], v["band"]), "limit %d %d" % (v["rule_set"], v["band"]),
                      "alimit %d %d normal" % (v["rule_set"], v["band"]), "alimit %d %d beacon" % (v["rule_set"], v["band"])]
            want += ["%d %d" % tuple(v["lbt"]) if v["lbt"] else "none",
                     "%d %d" % tuple(v["send_limit"]) if v["send_limit"] else "none",
                     str(v["limit_normal_ms"]), str(v["limit_beacon_ms"])]
            for sf, bw, n in v["max_len"]:
                lines.append("bandmax %d %d %d %d" % (v["rule_set"], v["band"], sf, bw))
                want.append(str(n))
        self.assertEqual(self.ask(lines), want)

    def test_time_on_air_is_wake_toa_us_bit_for_bit(self):
        lines, want = [], []
        for sf in range(5, 14):
            for bw in (0, 62, 125, 250, 500, 501):
                for n in (0, 1, 7, 13, 29, 64, 200, 255, 256):
                    for p in (0, 8, 12, 1024, 1025):
                        lines += ["toap %d %d %d %d" % (sf, bw, n, p), "wtoa %d %d %d %d" % (sf, bw, n, p)]
                        want += [str(R.dr_toa_us(sf, bw, n, p))] * 2
        self.assertEqual(self.ask(lines), want)

    # ------------------------------------------------------------ the air account, schedule fit

    def test_air_accounts(self):
        lines, want = [], []
        for case in VEC["air"]:
            l, w = self.ask_air(case["rule_set"], case["steps"])
            lines += l
            want += w
        self.assertEqual(self.ask(lines), want)

    def test_schedule_need(self):
        lines, want = [], []
        prefix = synth_lines(VEC["synthetic"]["rule_set"])
        for v in VEC["schedule_need"]:
            rs = 99 if v["rule_set"] == "synthetic" else v["rule_set"]
            lines.append("need %d %d %d %d %d %d %d %d %d %d" % (
                rs, v["sf"], v["bw_khz"], v["freq_khz"], v["reports_per_h"], v["report_bytes"], v["lost_per_h"],
                v["lost_bytes"], v["find_per_h"], v["find_bytes"]))
            g = v["want"]
            want.append("%d %d %d %d %d %d %d %d" % (g["band"], g["budget_ms"], g["normal_limit_ms"], g["need_ms"],
                                                    g["normal_ms"], g["beacon_ms"], 1 if g["fits"] else 0,
                                                    FITS.index(g["reason"])))
        self.assertEqual(self.ask(prefix + lines)[len(prefix):], want)

    # ------------------------------------------------------------ regions, wake channels, defaults, wire

    def test_regions_wake_channels_and_defaults(self):
        lines, want = [], []
        for v in VEC["region_resolve"]:
            lines.append("resolve %d %s %d" % (v["setting"], "-" if v["lorawan_region"] is None else v["lorawan_region"],
                                               v["freq_khz"]))
            want.append(str(v["region"]))
        for v in VEC["wake_channels"]:
            w = v["channel"]
            lines += ["wake %d %d" % (v["rule_set"], 1 if v["long_range"] else 0),
                      "wchan %d %d" % (v["rule_set"], 1 if v["long_range"] else 0)]
            want += ["none" if w is None else "%d %d %d %d" % (w["freq_hz"], w["bw_khz"], w["sf"], w["max_dbm"])] * 2
        for v in VEC["defaults"]:
            lines.append("default %d" % v["rule_set"])
            want.append("%d %d %d" % (v["sf"], v["bw_khz"], v["freq_khz"]))
        for v in VEC["freq_fields"]:
            lines += ["f2w %d" % v["freq_khz"], "w2f %d %d" % (v["frequency"], v["frequency_khz"])]
            want += ["%d %d" % (v["frequency"], v["frequency_khz"]), str(v["reads_back"])]
        for v in VEC["freq_read"]:
            lines.append("w2f %d %d" % (v["frequency"], v["frequency_khz"]))
            want.append(str(v["freq_khz"]))
        self.assertEqual(self.ask(lines), want)

    def test_wake_region_resolve_keeps_the_wake_vectors(self):
        """wake_frame.c's resolve (whole MHz) is the table's: every
        region_resolve vector of beacon/vectors.json, and the same answer as
        dr_region_resolve for every MHz around the bands."""
        lines, want = [], []
        for v in WAKE["region_resolve"]:
            lines.append("wresolve %d %s %d" % (v["setting"], "-" if v["lorawan_region"] is None else v["lorawan_region"],
                                                v["frequency_mhz"]))
            want.append(str(v["region"]))
        for setting in (0, 1, 3, 4, 15, 16, 4294967295):
            for lw in (None, 0, 1, 2, 3):
                for mhz in (0, 433, 862, 863, 868, 870, 871, 901, 902, 915, 928, 929, 4294967, 4294968):
                    lines.append("wresolve %d %s %d" % (setting, "-" if lw is None else lw, mhz))
                    want.append(str(R.dr_region_resolve(setting, lw, mhz * 1000 if mhz <= 4294967 else 0)))
        for r in WAKE["regions"]:
            for lr, sf in ((0, r["sf"]), (1, r["sf_long"])):
                lines.append("wchan %d %d" % (r["region"], lr))
                want.append("%d %d %d %d" % (r["frequency_hz"], r["bw_khz"], sf, r["max_dbm"]))
        self.assertEqual(self.ask(lines), want)

    # ------------------------------------------------------------ the synthetic rule set

    def test_the_synthetic_rule_set(self):
        S = VEC["synthetic"]
        prefix = synth_lines(S["rule_set"])
        lines, want = [], []
        for v in S["check"]:
            lines.append("check 99 %d %d %d %s" % (v["sf"], v["bw_khz"], v["freq_khz"], dev(v["device"])))
            want.append(str(REASONS.index(v["reason"])))
        for v in S["convert"]:
            lines.append("convert 99 %d %d %d" % (v["sf"], v["bw_khz"], v["freq_khz"]))
            want.append("%d %d %d %d" % tuple(v["out"] + [HOWS.index(v["how"])]))
        for bw, f, codes, outs in S["sweep"]:
            for i, sf in enumerate(range(7, 13)):
                lines += ["check 99 %d %d %d gen" % (sf, bw, f), "convert 99 %d %d %d" % (sf, bw, f)]
                want += [str(codes[i]), "%d %d %d %d" % tuple(outs[4 * i:4 * i + 4])]
        for v in S["power_caps"]:
            lines += ["cap 99 %d %s" % (v["band"], dev(v["device"])), "allowed 99 %d %s" % (v["band"], dev(v["device"]))]
            want += ["%d %d" % (v["cap_dbm"], 1 if v["usable"] else 0), str(v["allowed_dbm"])]
        for v in S["band_limits"]:
            lines += ["lbt 99 %d" % v["band"], "limit 99 %d" % v["band"]]
            want += ["%d %d" % tuple(v["lbt"]) if v["lbt"] else "none",
                     "%d %d" % tuple(v["send_limit"]) if v["send_limit"] else "none"]
            for sf, bw, n in v["max_len"]:
                lines.append("bandmax 99 %d %d %d" % (v["band"], sf, bw))
                want.append(str(n))
        for lr, w in enumerate(S["wake"]):
            lines.append("wake 99 %d" % lr)
            want.append("%d %d %d %d" % (w["freq_hz"], w["bw_khz"], w["sf"], w["max_dbm"]))
        lines.append("default 99")
        want.append("%d %d %d" % tuple(S["default"]))
        for case in S["air"]:
            l, w = self.ask_air(99, case["steps"])
            lines += l
            want += w
        self.assertEqual(self.ask(prefix + lines)[len(prefix):], want)


@unittest.skipIf(CC is None, "no C compiler")
class DirectRulesC99(_DirectRules, unittest.TestCase):
    CXX_BUILD = False


@unittest.skipIf(CC is None or CXX is None, "no C/C++ compiler")
class DirectRulesCxx(_DirectRules, unittest.TestCase):
    CXX_BUILD = True


@unittest.skipIf(CC is None or CXX is None, "no C/C++ compiler")
class CleanBuilds(unittest.TestCase):
    """The engine and its table, alone, as every standard and language the
    two firmwares use: no warning at -Wall -Wextra -Wconversion -Wshadow."""

    def test_each_file_compiles_cleanly(self):
        tmp = tempfile.mkdtemp(prefix="direct_rules_build_")
        try:
            strict = WARN + ["-Wconversion", "-Wshadow", "-Wcast-qual"]
            for src in (os.path.join(C_DIR, "direct_rules.c"), os.path.join(C_DIR, "direct_rules_table.c")):
                for cmd in ([CC, "-std=c99"], [CC, "-std=c11"], [CXX, "-x", "c++", "-std=c++11"],
                            [CXX, "-x", "c++", "-std=c++17"]):
                    r = subprocess.run(cmd + strict + ["-c", src, "-o", os.path.join(tmp, "x.o")],
                                       capture_output=True, text=True)
                    self.assertEqual(r.returncode, 0, "%s %s:\n%s" % (" ".join(cmd), src, r.stderr))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
