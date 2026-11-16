"""Tests for "What's on the card" v1 (CMD_CARD_SUMMARY, 2026-11-16).

    cd reference && python3 -m unittest -v test_card_summary

The reference codec (card_summary.py) against its frozen vectors
(test_vectors/card_summary_v1.json), the wire numbers in the .proto text,
the nanopb options and headers the collar copies, the generated Python, and
the size of the largest reply frame. Standard library only, except the
generated-Python checks (skipped without a protobuf runtime).
"""

import importlib.util
import json
import os
import re
import sys
import unittest

import card_summary as cs
import make_card_summary_vectors as mk
from test_mag_cal_contract import ROOT, U32, encode, enum_values, message_fields, read
from test_mag_rate_contract import c_struct, field_labels

D0 = mk.D0


def _load(name):
    sys.path.insert(0, ROOT)
    saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        return __import__(name)
    except Exception:  # runtime missing or older than the gencode
        return None
    finally:
        sys.dont_write_bytecode = saved
        sys.path.remove(ROOT)


MSG = _load("message_pb2")
DL = _load("downlink_pb2")


def _beacon_v2():
    path = os.path.join(ROOT, "beacon", "beacon_v2.py")
    spec = importlib.util.spec_from_file_location("beacon_v2_card_summary", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _beacon_v2()
VEC = json.load(open(mk.OUT, encoding="utf-8"))


class Vectors(unittest.TestCase):

    def test_vector_file_is_up_to_date(self):
        with open(mk.OUT, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), mk.render(), "run make_card_summary_vectors.py")

    def test_constants(self):
        self.assertEqual((VEC["day_len"], VEC["days_per_frame"], VEC["frames_max"],
                          VEC["days_default"], VEC["days_max"], VEC["mib_saturated"]),
                         (10, 16, 4, 30, 62, 65535))
        self.assertGreaterEqual(VEC["days_per_frame"] * VEC["frames_max"], VEC["days_max"])
        self.assertEqual(VEC["message_packet_field"], 12)

    def test_days(self):
        for v in VEC["days"]:
            b = bytes.fromhex(v["hex"])
            self.assertEqual(len(b), 10, v["name"])
            self.assertEqual(cs.encode_day(v["sound_hours"], v["sound_mib"], v["movement_hours"],
                                           v["movement_mib"]), b, v["name"])
            d = cs.decode_day(b)
            self.assertEqual((d["sound_hours"], d["sound_mib"], d["movement_hours"], d["movement_mib"]),
                             (v["sound_hours"], v["sound_mib"], v["movement_hours"], v["movement_mib"]),
                             v["name"])
        self.assertEqual(VEC["days"][0]["hex"], "00" * 10)   # a day with nothing

    def test_sizes_round_up_and_saturate(self):
        for v in VEC["sizes"]:
            self.assertEqual(cs.mib_from_bytes(v["bytes"]), v["mib"])
            self.assertEqual(cs.kib_from_bytes(v["bytes"]), v["kib"])
            self.assertEqual(cs.mib_from_kib(v["kib"]), v["mib_of_kib"])
        self.assertEqual(cs.mib_from_bytes(1), 1)
        self.assertEqual(cs.mib_from_bytes(1 << 40), 65535)

    def test_spans(self):
        for v in VEC["spans"]:
            self.assertEqual(cs.hours_list(cs.span_hours(v["day"], v["start"], v["end"])), v["hours"], v["name"])

    def test_windows_and_splits(self):
        for v in VEC["windows"]:
            self.assertEqual(cs.window(v["from_epoch"], v["days"], v["now"]), (v["first_day"], v["n"]), v["name"])
            self.assertEqual(v["first_day"] % 86400, 0)
        for v in VEC["splits"]:
            got = cs.split(v["days"])
            self.assertEqual([list(p) for p in got], v["frames"])
            self.assertLessEqual(len(got), 4)
            self.assertEqual(sum(c for _, c in got), v["days"])

    def test_summaries(self):
        for v in VEC["summaries"]:
            b = bytes.fromhex(v["hex"])
            days = bytes.fromhex(v["days_hex"])
            self.assertEqual(cs.encode_summary(v["first_day"], days, v["part"], v["parts"],
                                               v["log_kib"], v["as_of"]), b, v["name"])
            d = cs.decode_summary(b)
            self.assertEqual((d["first_day"], d["days"], d["part"], d["parts"], d["log_kib"], d["as_of"]),
                             (v["first_day"], days, v["part"], v["parts"], v["log_kib"], v["as_of"]))
            self.assertEqual(bytes.fromhex(v["field12_hex"]), cs.message_packet_field(b))

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            cs.decode_day(b"\0" * 9)
        with self.assertRaises(ValueError):
            cs.encode_day([24])
        with self.assertRaises(ValueError):
            cs.encode_day(sound_mib=65536)
        with self.assertRaises(ValueError):
            cs.encode_summary(0, b"\0" * 170, 1, 1)
        with self.assertRaises(ValueError):
            cs.split(63)


class Wire(unittest.TestCase):

    def test_command_and_request(self):
        self.assertEqual(enum_values("downlink.proto", "CommandType")["CMD_CARD_SUMMARY"], 30)
        self.assertEqual(message_fields("downlink.proto", "DownlinkPacket")["card_summary"],
                         ("CardSummaryRequest", 18))
        self.assertEqual(message_fields("downlink.proto", "CardSummaryRequest"),
                         {"from_epoch": ("uint32", 1), "days": ("uint32", 2)})

    def test_answer_message(self):
        self.assertEqual(message_fields("message.proto", "CardSummary"),
                         {"first_day": ("uint32", 1), "days": ("bytes", 2), "part": ("uint32", 3),
                          "parts": ("uint32", 4), "log_kib": ("uint32", 5), "as_of": ("uint32", 6)})
        self.assertEqual(message_fields("message.proto", "MessagePacket")["card_summary"], ("CardSummary", 12))
        self.assertEqual(field_labels("message.proto", "MessagePacket")["card_summary"], "optional")
        oneof = re.search(r"oneof payload \{(.*?)\}", read("message.proto"), re.S).group(1)
        self.assertNotIn("card_summary", oneof)

    def test_refusal_details(self):
        self.assertEqual(B.ACK_BLE_REFUSED, 12)
        self.assertEqual(B.BLE_REFUSED_NO_CARD, 3)
        self.assertEqual(B.BLE_REFUSED_CARD_INDEX, 7)

    def test_nanopb_options_and_headers(self):
        opts = read("message.options")
        cap = int(re.search(r"CardSummary\.days\s+max_size:(\d+)", opts).group(1))
        self.assertEqual(cap, cs.DAYS_PER_FRAME * cs.DAY_LEN)
        self.assertRegex(opts, r"MessagePacket\.card_summary\s+type:FT_IGNORE")
        # the collar's message_packet_t stays as it was; CardSummary itself is generated
        self.assertNotIn("card_summary", c_struct("message.pb.h", "message_packet"))
        self.assertIn("card_summary_days_t days;", c_struct("message.pb.h", "card_summary"))
        self.assertIn("card_summary_request_t card_summary;", c_struct("downlink.pb.h", "downlink_packet"))
        self.assertRegex(read("downlink.pb.h"), r"\bCOMMAND_TYPE_CMD_CARD_SUMMARY = 30\b")

    def test_largest_reply_frame_fits_a_sealed_report(self):
        # The header a reply frame carries (as a track frame: uid, the report
        # counter as it stands, the time, the build), every value at its
        # largest, then field 12 with a full frame of days.
        h = message_fields("common.proto", "PacketHeader")
        header = encode([(h["system_uid"][1], U32), (h["epoch"][1], U32),
                         (h["packet_index"][1], U32), (h["fw_build"][1], U32)])
        frame = encode([(1, header)]) + cs.message_packet_field(
            cs.encode_summary(0xFFFFFFFF - 0xFFFFFFFF % 86400, b"\xff" * 160, 4, 4, U32, U32))
        self.assertLessEqual(len(frame), B.COMMAND_MAX_LEN - 17)   # 238: BEACON_REPORT_MAX_BODY
        self.assertEqual(len(frame), 214)   # 26 B header + 188 B field 12


@unittest.skipIf(MSG is None or DL is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    def test_summaries_decode_with_the_runtime(self):
        for v in VEC["summaries"]:
            m = MSG.CardSummary.FromString(bytes.fromhex(v["hex"]))
            self.assertEqual((m.first_day, m.days.hex(), m.part, m.parts, m.log_kib, m.as_of),
                             (v["first_day"], v["days_hex"], v["part"], v["parts"], v["log_kib"], v["as_of"]))
            self.assertEqual(m.SerializeToString(), bytes.fromhex(v["hex"]))

    def test_a_reply_frame_is_a_message_packet(self):
        v = VEC["summaries"][0]
        hdr = MSG.MessagePacket(header={"system_uid": 0x7E570011, "epoch": D0 + 600, "packet_index": 9})
        raw = hdr.SerializeToString() + bytes.fromhex(v["field12_hex"])
        p = MSG.MessagePacket.FromString(raw)
        self.assertTrue(p.HasField("card_summary"))
        self.assertEqual(p.WhichOneof("payload"), None)
        self.assertEqual(p.card_summary.parts, v["parts"])
        self.assertEqual(cs.decode_days(p.card_summary.days)[0]["sound_hours"], [18, 19, 20])
        self.assertEqual(p.SerializeToString(), raw)

    def test_request(self):
        d = DL.DownlinkPacket(command=30)
        d.card_summary.from_epoch = D0
        d.card_summary.days = 62
        self.assertEqual(DL.DownlinkPacket.FromString(d.SerializeToString()).card_summary.days, 62)
        self.assertLessEqual(len(d.SerializeToString()), 16)


if __name__ == "__main__":
    unittest.main()
