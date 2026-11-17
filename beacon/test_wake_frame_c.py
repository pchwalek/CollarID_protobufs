#!/usr/bin/env python3
"""The C reference of LoRa wake (c/wake_frame.c) against the vectors and the
Python reference.

    cd beacon && python3 -m unittest -v test_wake_frame_c

c/wake_frame.[ch] is what the collar firmware and the Handheld Receiver copy,
so it is held here to every wake vector of vectors.json and, beyond the
vectors, to beacon_v2.py over every LoRa setting and a sweep of inputs. The
test compiles c/test/wake_frame_harness.c with the C files into a temporary
directory (nothing is left in the repository) and talks to it line by line.
Skipped, not failed, on a machine without a C compiler.

Standard library only.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import beacon_v2 as b  # noqa: E402
import make_vectors as mv  # noqa: E402

with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)

CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
C_DIR = os.path.join(HERE, "c")
SOURCES = [os.path.join(C_DIR, "test", "wake_frame_harness.c"),
           os.path.join(C_DIR, "wake_frame.c"),
           os.path.join(C_DIR, "aead_ccm.c"),
           # wake_channel() and wake_region_resolve() read the region table (2026-11-17)
           os.path.join(C_DIR, "direct_rules.c"),
           os.path.join(C_DIR, "direct_rules_table.c")]

# wake_frame.h's enums, by the names the vectors use.
PARSE_CODES = {name: i + 1 for i, name in enumerate(b.WAKE_REFUSALS)}
CHECK_CODES = {name: i + 1 for i, name in enumerate(b.ROLL_CALL_REFUSALS)}
VERDICTS = {"not_called": 0, "called": 1, "more": 2, "roll": 3}


@unittest.skipIf(CC is None, "no C compiler")
class WakeFrameC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wake_frame_c_")
        exe = os.path.join(cls.tmp, "wake_frame_harness")
        build = subprocess.run([CC, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1",
                                "-I", C_DIR, "-o", exe] + SOURCES, capture_output=True, text=True)
        if build.returncode != 0:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise AssertionError("the C reference does not compile cleanly:\n" + build.stderr)
        cls.exe = exe

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def ask(self, lines):
        """Answers of the harness, one per command line."""
        out = subprocess.run([self.exe], input="\n".join(lines) + "\n", capture_output=True,
                             text=True, check=True).stdout.split("\n")[:-1]
        self.assertEqual(len(out), len(lines))
        return out

    def test_the_harness_aes_is_aes(self):
        v = VEC["aes128"][0]
        self.assertEqual(self.ask(["aes %s %s" % (v["key"], v["pt"])]), [v["ct"]])

    # ------------------------------------------------------------- vectors

    def test_tags(self):
        got = self.ask(["tag %d" % v["uid"] for v in VEC["wake_tags"]])
        self.assertEqual(got, [str(v["tag"]) for v in VEC["wake_tags"]])

    def test_frames_parse_build_and_verdicts(self):
        good = [v for v in VEC["wake_frames"] if v["ok"]]
        bad = [v for v in VEC["wake_frames"] if not v["ok"]]
        self.assertEqual((len(good), len(bad)), (12, 13))
        want = []
        for v in good:
            tags = v["tags"] + [0] * (4 - len(v["tags"]))
            want.append("ok %d %d %d %d %d %d %d" % tuple([v["flags"], v["time_left_10ms"], len(v["tags"])] + tags))
        self.assertEqual(self.ask(["parse %s" % v["frame"] for v in good]), want)
        builds = ["build %d %d %d %d %d %d %d" % tuple(
            [v["flags"], v["time_left_10ms"], len(v["tags"])] + v["tags"] + [0] * (4 - len(v["tags"])))
            for v in good]
        self.assertEqual(self.ask(builds), [v["frame"] for v in good])
        self.assertEqual(self.ask(["parse %s" % (v["frame"] or "-") for v in bad]),
                         ["err %d" % PARSE_CODES[v["refusal"]] for v in bad])
        lines, want = [], []
        for v in good:
            for p in v["verdicts"]:
                lines.append("verdict %s %d" % (v["frame"], p["uid"]))
                want.append(str(VERDICTS[p["verdict"]]))
        self.assertEqual(self.ask(lines), want)

    def test_build_refuses_what_parse_refuses(self):
        # flags, time left, k, four tags
        cases = ["build 8 0 1 1 0 0 0",      # a reserved flag
                 "build 0 0 5 1 2 3 4",      # five tags
                 "build 0 0 0 0 0 0 0",      # no tags, no ROLL
                 "build 4 0 1 1 0 0 0",      # ROLL with a tag
                 "build 5 0 0 0 0 0 0"]      # ROLL with MORE
        self.assertEqual(self.ask(cases), ["err"] * len(cases))

    def test_regions_and_channels(self):
        t = VEC["wake_timing"]
        lines = ["resolve %d %s %d" % (v["setting"], "-" if v["lorawan_region"] is None else v["lorawan_region"],
                                       v["frequency_mhz"]) for v in t["region_resolve"]]
        self.assertEqual(self.ask(lines), [str(v["region"]) for v in t["region_resolve"]])
        lines, want = [], []
        for r in t["regions"]:
            lines += ["channel %d 0" % r["region"], "channel %d 1" % r["region"]]
            want += ["%d %d %d %d" % (r["frequency_hz"], r["bw_khz"], r["sf"], r["max_dbm"]),
                     "%d %d %d %d" % (r["frequency_hz"], r["bw_khz"], r["sf_long"], r["max_dbm"])]
        # old: lines += ["channel 0 0", "channel 4 1"]; want += ["none", "none"]
        # (to 2026-11-17: 4 was no region; every region 1..15 is in
        # test_direct_rules_c.py, against contracts_v1.json direct_regions)
        lines += ["channel 0 0", "channel 16 1", "channel 255 0"]
        want += ["none", "none", "none"]
        self.assertEqual(self.ask(lines), want)

    def test_timing_table(self):
        t = VEC["wake_timing"]
        lines, want = [], []
        for s in t["settings"]:
            lines.append("timing %d %d" % (s["sf"], s["bw_khz"]))
            want.append(" ".join(str(s[k]) for k in (
                "ts_us", "frame_us", "tail_us", "w_us", "cap_us", "intent_wait_us", "cmd_window_us",
                "roll_wait_us", "roll_slot_min_us", "roll_slot_default_ms")))
            for a in s["toa"]:
                lines.append("toa %d %d %d %d" % (s["sf"], s["bw_khz"], a["bytes"], a["preamble"]))
                want.append(str(a["us"]))
            for tr in s["trains"]:
                lines.append("train %d %d %d 0" % (s["sf"], s["bw_khz"], tr["interval_s"]))
                want.append("%d %d" % (tr["train_us"], tr["frames_gap_0"]))
                lines.append("train %d %d %d 5000" % (s["sf"], s["bw_khz"], tr["interval_s"]))
                want.append("%d %d" % (tr["train_us"], tr["frames_gap_5ms"]))
        self.assertEqual(self.ask(lines), want)
        self.assertEqual(self.ask(["clamp %d" % v["interval_s"] for v in t["interval_clamp"]]),
                         [str(v["runs_s"]) for v in t["interval_clamp"]])
        self.assertEqual(self.ask(["left %d" % v["us"] for v in t["time_left"]]),
                         [str(v["time_left_10ms"]) for v in t["time_left"]])

    def test_wake_keys(self):
        keys = VEC["roll_calls"]["keys"]
        self.assertEqual(self.ask(["kdfin %d %d" % (v["group"], v["gen"]) for v in keys]),
                         [v["input"] for v in keys])
        self.assertEqual(self.ask(["kdf %s %d %d" % (v["master"], v["group"], v["gen"]) for v in keys]),
                         [v["wake_key"] for v in keys])

    def test_roll_calls_seal_and_open(self):
        frames = VEC["roll_calls"]["frames"]
        seal = ["seal %s %d %d %d %d %d %d %d" % (v["wake_key"], v["group"], v["ctr"], v["valid_from"],
                                                  v["valid_to"], v["slots"], v["slot_ms"], v["flags"])
                for v in frames]
        self.assertEqual(self.ask(seal), [v["frame"] for v in frames])
        opened = ["ok %d %d %d %d %d %d %d" % (v["group"], v["ctr"], v["valid_from"], v["valid_to"],
                                               v["slots"], v["slot_ms"], v["flags"]) for v in frames]
        self.assertEqual(self.ask(["open %s %s" % (v["wake_key"], v["frame"]) for v in frames]), opened)
        # Every single-bit change of a roll call fails to open.
        lines = []
        for v in frames:
            raw = bytes.fromhex(v["frame"])
            for i in range(len(raw)):
                for bit in range(8):
                    t = bytearray(raw)
                    t[i] ^= 1 << bit
                    lines.append("open %s %s" % (v["wake_key"], t.hex()))
        self.assertEqual(len(lines), 5 * 29 * 8)
        self.assertEqual(set(self.ask(lines)), {"fail"})

    def test_roll_call_checks(self):
        checks = VEC["roll_calls"]["checks"]
        lines, want = [], []
        for v in checks:
            lines.append("check %s %d %d %d %s %d %d %s %s" % (
                v["wake_key"] or "-", v["group"], v["gen"], v["last_ctr"],
                "-" if v["now"] is None else v["now"], v["sf"], v["bw_khz"],
                "-" if v["since_answer_s"] is None else v["since_answer_s"], v["frame"]))
            want.append("0 %d %d %d" % (v["ctr"], v["slots"], v["slot_ms"]) if v["accept"]
                        else str(CHECK_CODES[v["reason"]]))
        self.assertEqual(self.ask(lines), want)

    def test_roll_call_slots(self):
        rows = VEC["roll_calls"]["slots"]
        self.assertEqual(self.ask(["slot %d %d %d %d" % (v["uid"], v["ctr"], v["slots"], v["slot_ms"]) for v in rows]),
                         ["%d %d %d" % (v["slot"], v["reply_delay_ms"], 300 + v["slots"] * v["slot_ms"] + 200)
                          for v in rows])

    # ------------------------------------------- beyond the vectors: the Python reference

    def test_every_lora_setting_matches_the_python_reference(self):
        lines, want = [], []
        for sf in range(7, 13):
            for bw in (125, 250, 500):
                t = b.wake_timing(sf, bw)
                lines.append("timing %d %d" % (sf, bw))
                want.append(" ".join(str(x) for x in t))
                for n in (0, 1, 13, 14, 29, 30, 100, 255):
                    for p in (8, 12):
                        lines.append("toa %d %d %d %d" % (sf, bw, n, p))
                        want.append(str(b.lora_toa_us(sf, bw, n, p)))
                for i in (1, 5, 30, 120, 480):
                    for gap in (0, 1, 2500, 5000):
                        lines.append("train %d %d %d %d" % (sf, bw, i, gap))
                        want.append("%d %d" % (b.wake_train_us(sf, bw, i), b.wake_train_frames(sf, bw, i, gap)))
        self.assertEqual(self.ask(lines), want)
        # Outside SF7..12 at 125 / 250 / 500 kHz every time is 0.
        self.assertEqual(self.ask(["timing 6 500", "timing 13 125", "timing 9 400", "toa 9 500 256 8",
                                   "train 9 500 0 0", "train 9 500 4001 0", "train 9 500 30 5001"]),
                         ["0 0 0 0 0 0 0 0 0 0"] * 3 + ["0", "0 0", "0 0", "%d 0" % b.wake_train_us(9, 500, 30)])

    def test_tags_and_slots_match_the_python_reference_on_a_sweep(self):
        uids = [(0x9E3779B9 * i + 0x7E570000) & 0xFFFFFFFF for i in range(400)] + [0, 1, 0xFFFFFFFF, b.WAKE_SALT]
        self.assertEqual(self.ask(["tag %d" % u for u in uids]), [str(b.wake_tag(u)) for u in uids])
        lines, want = [], []
        for u in uids[:60]:
            for ctr in (0x01000000, 0x01000001, 0xFFFFFFFF):
                for slots in (1, 2, 31, 32, 64, 255):
                    lines.append("slot %d %d %d 82" % (u, ctr, slots))
                    want.append("%d %d %d" % (b.roll_call_slot(u, ctr, slots),
                                              b.roll_call_reply_delay_ms(u, ctr, slots, 82),
                                              b.roll_call_listen_ms(slots, 82)))
        self.assertEqual(self.ask(lines), want)

    def test_every_wake_frame_shape_matches_the_python_reference(self):
        """Every flags byte and tag count, at each length 0..14: the C parser
        gives the Python parser's answer."""
        lines, want = [], []
        for flags in range(256):
            for k in range(7):
                for n in sorted({5 + 2 * k, 5, 13}):
                    frame = bytes([0x57, flags, 0x34, 0x12, k]) + bytes(range(1, 1 + max(n - 5, 0)))
                    frame = frame[:n]
                    lines.append("parse %s" % frame.hex())
                    try:
                        f = b.parse_wake_frame(frame)
                        tags = list(f.tags) + [0] * (4 - len(f.tags))
                        want.append("ok %d %d %d %d %d %d %d" % tuple([f.flags, f.time_left_10ms, len(f.tags)] + tags))
                    except b.WakeFrameError as e:
                        want.append("err %d" % PARSE_CODES[e.reason])
        for n in range(0, 15):
            frame = (bytes([0x57, 0, 0, 0, max((n - 5) // 2, 0)]) + bytes(10))[:n]
            lines.append("parse %s" % (frame.hex() or "-"))
            try:
                b.parse_wake_frame(frame)
                want.append("ok 0 0 %d 0 0 0 0" % ((n - 5) // 2))
            except b.WakeFrameError as e:
                want.append("err %d" % PARSE_CODES[e.reason])
        self.assertEqual(self.ask(lines), want)

    def test_c_constants_are_the_python_constants(self):
        with open(os.path.join(C_DIR, "wake_frame.h"), encoding="utf-8") as fh:
            h = fh.read()

        def define(name):
            import re
            # at the start of a line: a value kept in an "old:" comment is not the define
            m = re.search(r"(?m)^#define %s\s+(0x[0-9A-Fa-f]+|\d+)u\b" % name, h)
            self.assertIsNotNone(m, name)
            return int(m.group(1), 0)

        for name, value in (
                ("WAKE_FRAME_MAGIC", b.MAGIC_WAKE), ("WAKE_FRAME_HDR_LEN", b.WAKE_HEADER_LEN),
                ("WAKE_FRAME_MAX_TAGS", b.WAKE_MAX_TAGS), ("WAKE_FLAG_MORE", b.WAKE_FLAG_MORE),
                ("WAKE_FLAG_LONG", b.WAKE_FLAG_LONG), ("WAKE_FLAG_ROLL", b.WAKE_FLAG_ROLL),
                ("WAKE_SALT", b.WAKE_SALT), ("WAKE_TIME_UNIT_MS", b.WAKE_TIME_UNIT_MS),
                ("WAKE_REGION_US915", b.DIRECT_REGION_US915), ("WAKE_REGION_EU868", b.DIRECT_REGION_EU868),
                ("WAKE_REGION_AU915", b.DIRECT_REGION_AU915), ("WAKE_LORAWAN_US915", b.LORAWAN_REGION_US915),
                ("WAKE_LORAWAN_AU915", b.LORAWAN_REGION_AU915), ("WAKE_LORAWAN_EU868", b.LORAWAN_REGION_EU868),
                ("WAKE_SYNC_WORD", b.WAKE_SYNC_WORD), ("WAKE_PREAMBLE_SYMBOLS", b.WAKE_PREAMBLE_SYMBOLS),
                ("WAKE_OTHER_PREAMBLE", b.LORA_PREAMBLE_SYMBOLS),
                ("WAKE_INTERVAL_MIN_S", b.WAKE_INTERVAL_MIN_S), ("WAKE_INTERVAL_MAX_S", b.WAKE_INTERVAL_MAX_S),
                ("WAKE_SLOW_FACTOR_MAX", b.WAKE_SLOW_FACTOR_MAX), ("WAKE_GAP_MAX_MS", b.WAKE_GAP_MAX_MS),
                ("WAKE_RX_LEAD_MS", b.WAKE_RX_LEAD_MS), ("WAKE_FIRST_SEND_MS", b.WAKE_FIRST_SEND_MS),
                ("WAKE_CALL_SNIFF_S", b.CALL_SNIFF_S), ("WAKE_CALL_SNIFF_LONG_S", b.CALL_SNIFF_LONG_S),
                ("WAKE_CALLED_WAIT_S", b.CALLED_WAIT_S), ("WAKE_CALL_IDLE_S", b.CALL_IDLE_S),
                ("WAKE_CALL_MAX_S", b.CALL_MAX_S),
                ("ROLL_CALL_MAGIC", b.MAGIC_ROLL_CALL), ("ROLL_CALL_HDR_LEN", b.AAD_LEN),
                ("ROLL_CALL_BODY_LEN", b.ROLL_CALL_BODY_LEN), ("ROLL_CALL_DIR", b.DIR_ROLL_CALL),
                ("ROLL_CALL_SLOTS_MAX", b.ROLL_CALL_SLOTS_MAX), ("ROLL_CALL_SLOTS_DEFAULT", b.ROLL_CALL_SLOTS_DEFAULT),
                ("ROLL_CALL_REPLY_LEN", b.ROLL_CALL_REPLY_LEN), ("ROLL_CALL_REPLY_BASE_MS", b.ROLL_CALL_REPLY_BASE_MS),
                ("ROLL_CALL_SLOT_MARGIN_MIN_MS", b.ROLL_CALL_SLOT_MARGIN_MIN_MS),
                ("ROLL_CALL_SLOT_MARGIN_MS", b.ROLL_CALL_SLOT_MARGIN_MS),
                ("ROLL_CALL_LISTEN_EXTRA_MS", b.ROLL_CALL_LISTEN_EXTRA_MS),
                ("ROLL_CALL_MIN_GAP_S", b.ROLL_CALL_MIN_GAP_S), ("WAKE_KDF_LABEL_LEN", len(b.LABEL_WAKE))):
            self.assertEqual(define(name), value, name)
        import re
        self.assertRegex(h, r'#define WAKE_KDF_LABEL\s+"%s"' % b.LABEL_WAKE.decode("ascii"))
        # The enum numbers are the vectors' reason names, in order.
        for prefix, names in (("WAKE_FRAME_", ["length", "bad_magic", "reserved_flags", "tag_count", "tag_bytes",
                                               "no_tags", "roll_with_tags", "roll_with_more"]),
                              ("ROLL_CALL_", list(b.ROLL_CALL_REFUSALS))):
            for i, name in enumerate(names):
                self.assertRegex(h, r"\b%s%s\s+= %d\b" % (prefix, name.upper(), i + 1))
        self.assertEqual(len(mv.WAKE_FRAME_CASES), 12)


if __name__ == "__main__":
    unittest.main()
