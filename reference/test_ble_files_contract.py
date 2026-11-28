"""Tests for the requested Bluetooth file window (2026-11-16).

    cd reference && python3 -m unittest -v

collarID_thread docs/CONTRACT_files_and_spotter_gaps.md Part 1 and gap G1:
BleWindow.kinds / audio_from / audio_to (downlink.proto) limit what a window
opened by CMD_BLE_WINDOW serves, a bad audio range is refused with ACK result
12 detail 6, and CfgEchoPacket.cmd_result (ble.proto) says when a command
sent over the Bluetooth settings tunnel was not run (CMD_LOCATE_NOW). The
collar firmware, the server, the website and the app implement these
numbers. The tests pin them in the .proto text, the generated nanopb headers
and Python modules, the reference codec's constants and the specifications,
and check the wire sizes (a signed frame carries the largest window; the
status echo with cmd_result still fits one Bluetooth read).

Standard library only, except the generated-Python checks, which are skipped
when the protobuf runtime is missing or too old for the checked-in modules.
"""

import importlib.util
import os
import unittest

from test_mag_cal_contract import (BLE_READ_CEILING, PB2, U32, encode,
                                   mag_cal_worst, message_fields, read)
from test_mag_rate_contract import c_fieldlist, c_struct
from test_beacon_key_contract import echo_packet, report_worst

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_beacon_v2():
    # By path, not through sys.path: ../beacon has its own make_vectors.py,
    # which must not shadow this directory's for the other tests.
    path = os.path.join(HERE, os.pardir, "beacon", "beacon_v2.py")
    spec = importlib.util.spec_from_file_location("beacon_v2_files_contract", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = _load_beacon_v2()

# The contract.
WINDOW_FIELDS = {"minutes": ("uint32", 1),
                 "key": ("bytes", 2),
                 "kinds": ("uint32", 3),
                 "audio_from": ("uint32", 4),
                 "audio_to": ("uint32", 5),
                 # 2026-11-26: a software update through the window
                 "image_len": ("uint32", 6),
                 "image_sha256": ("bytes", 7),
                 "image_build": ("uint32", 8),
                 "image_sig": ("bytes", 9)}
KINDS = {"BLE_FILES_KIND_LOG": 1, "BLE_FILES_KIND_ACCEL": 2, "BLE_FILES_KIND_AUDIO": 4,
         "BLE_FILES_KIND_UPDATE": 8, "BLE_FILES_KIND_SOUNDLOG": 16}
# old: KINDS = {"BLE_FILES_KIND_LOG": 1, "BLE_FILES_KIND_ACCEL": 2, "BLE_FILES_KIND_AUDIO": 4,
#               "BLE_FILES_KIND_UPDATE": 8}   (before the sound log, 2026-11-27)
AUDIO_SPAN_MAX_S = 86400
# 2026-11-16 (coordinator): the takes that OVERLAP the range are served, a
# start up to the longest take (hourly rotation) before audio_from.
TAKE_MAX_S = 3600
DETAILS = {"BLE_REFUSED_NO_KEY": 1, "BLE_REFUSED_RADIO": 2, "BLE_REFUSED_NO_CARD": 3,
           "BLE_REFUSED_BATTERY": 4, "BLE_REFUSED_UPDATING": 5, "BLE_REFUSED_RANGE": 6,
           # 2026-11-26: a window with the update kind
           "BLE_REFUSED_IMAGE_LEN": 8, "BLE_REFUSED_IMAGE_HASH": 9, "BLE_REFUSED_IMAGE_BUILD": 10,
           "BLE_REFUSED_NO_RELEASE_KEY": 11, "BLE_REFUSED_UPDATE_BATTERY": 12,
           "BLE_REFUSED_WINDOW_OPEN": 13, "BLE_REFUSED_UPDATE_CARRIER": 14}
ECHO_CMD_RESULT = ("uint32", 17)
CMD_BLE_WINDOW = 27
CMD_LOCATE_NOW = 28

# A plausible audio range (2027-01-01 00:00 UTC, 24 h): epochs past 2**28
# take 5 varint bytes, as every real one does until 2038.
FROM = 1798761600
TO = FROM + AUDIO_SPAN_MAX_S


def window_cmd(kinds=0, audio_from=0, audio_to=0, minutes=30):
    """The DownlinkPacket a server signs for CMD_BLE_WINDOW (command and
    ble_window; no epoch: a signed frame never carries one)."""
    d = message_fields("downlink.proto", "DownlinkPacket")
    w = message_fields("downlink.proto", "BleWindow")
    win = encode([(w["minutes"][1], minutes), (w["key"][1], b"\xa5" * 16),
                  (w["kinds"][1], kinds), (w["audio_from"][1], audio_from),
                  (w["audio_to"][1], audio_to)])
    return encode([(d["command"][1], CMD_BLE_WINDOW), (d["ble_window"][1], win)])


def update_cmd(image_len=670612, image_build=640, kinds=8, minutes=30):
    """The same for a software update (2026-11-26): kinds bit 3 and the four
    image fields, a SHA-256 and a signature with no zero byte."""
    d = message_fields("downlink.proto", "DownlinkPacket")
    w = message_fields("downlink.proto", "BleWindow")
    win = encode([(w["minutes"][1], minutes), (w["key"][1], b"\xa5" * 16),
                  (w["kinds"][1], kinds), (w["image_len"][1], image_len),
                  (w["image_sha256"][1], b"\x5a" * 32), (w["image_build"][1], image_build),
                  (w["image_sig"][1], b"\xc3" * 64)])
    return encode([(d["command"][1], CMD_BLE_WINDOW), (d["ble_window"][1], win)])


class ProtoContract(unittest.TestCase):

    def test_window_fields(self):
        self.assertEqual(message_fields("downlink.proto", "BleWindow"), WINDOW_FIELDS)
        self.assertEqual(message_fields("downlink.proto", "DownlinkPacket")["ble_window"],
                         ("BleWindow", 15))

    def test_kind_constants_named_in_the_proto(self):
        text = read("downlink.proto")
        for name, value in KINDS.items():
            self.assertRegex(text, r"%s\s*=\s*%d\b" % (name, value))
            self.assertEqual(getattr(b, name), value)
        self.assertEqual(b.BLE_FILES_AUDIO_SPAN_MAX_S, AUDIO_SPAN_MAX_S)
        self.assertEqual(b.BLE_FILES_TAKE_MAX_S, TAKE_MAX_S)
        self.assertIn("[audio_from - %d, audio_to]" % TAKE_MAX_S, text.replace("\n//", ""))

    def test_refusal_details(self):
        self.assertEqual(b.ACK_BLE_REFUSED, 12)
        for name, value in DETAILS.items():
            self.assertEqual(getattr(b, name), value, name)
        self.assertIn("6 the window asks for audio", read("beacon/README.md").replace("\n", " "))

    def test_echo_field(self):
        echo = message_fields("ble.proto", "CfgEchoPacket")
        self.assertEqual(echo["cmd_result"], ECHO_CMD_RESULT)
        nums = [n for _, n in echo.values()]
        self.assertEqual(len(nums), len(set(nums)), "duplicate echo field")
        self.assertEqual(b.ACK_REFUSED_CARRIER, 7)

    def test_bulk_spec_says_what_a_window_serves(self):
        spec = read("bulk/README.md")
        self.assertIn("## What a window serves", spec)
        for must in ("/METADATA.CSV", "/accelerometer/", "/accelerometer_recovery/",
                     "/audio/YYYY/MM/DD/", "mic.anc.csv", "/audio_recovery/",
                     "`NOT_FOUND` (5)", "detail 6", "overlap",
                     "`[audio_from - %d, audio_to]`" % TAKE_MAX_S):
            self.assertIn(must, spec)

    def test_the_sound_log_kind_is_written_down(self):
        # 2026-11-27: bit 4 serves <take>.lvl by the audio range, and the
        # range is required with it as with bit 2 (detail 6)
        spec = read("bulk/README.md")
        self.assertIn("| sound log | 4 (16) |", spec)
        self.assertIn("`<take>.lvl`", spec)
        self.assertIn("Bits above 4 are reserved", spec)
        self.assertIn("bit 4) and `audio_from` or `audio_to` 0", spec)
        text = read("downlink.proto").replace("\n//", "")
        self.assertIn("bit 4 sound log", text)
        self.assertIn("read only with bit 2 or bit", text)
        self.assertIn("or, since 2026-11-27, for the sound log (bit 4)", read("beacon/README.md").replace("\n", " "))


class WireSizes(unittest.TestCase):

    def test_window_without_kinds_is_what_it_was(self):
        self.assertEqual(len(window_cmd()), 24)

    def test_log_and_movement_fit_the_rx2_floor(self):
        self.assertEqual(len(window_cmd(kinds=3)), 26)
        self.assertLessEqual(len(window_cmd(kinds=3)), 33)

    def test_audio_window_fits_a_signed_frame(self):
        n = len(window_cmd(kinds=7, audio_from=FROM, audio_to=TO))
        self.assertEqual(n, 38)
        self.assertLessEqual(n, b.COMMAND_MAX_BODY)
        # every uint32 at its largest still fits
        self.assertLessEqual(len(window_cmd(kinds=U32, audio_from=U32, audio_to=U32)),
                             b.COMMAND_MAX_BODY)

    def test_sound_log_window_is_the_audio_window_size(self):
        # 2026-11-27: kinds 16 (or 23 with log, movement and sound) is one
        # varint byte, as 7 was: 38 B with a range, a signed frame's body
        self.assertEqual(len(window_cmd(kinds=16, audio_from=FROM, audio_to=TO)), 38)
        self.assertEqual(len(window_cmd(kinds=0x17, audio_from=FROM, audio_to=TO)), 38)

    def test_update_window_fits_a_signed_frame(self):
        # 2026-11-26: 134 B for an image of 0.67 MB; every uint32 at its
        # largest still fits a 0x44 frame's body (226). Far over LoRaWAN's
        # 33 B RX2 floor: an update is ordered over the direct radio.
        self.assertEqual(len(update_cmd()), 134)
        worst = len(update_cmd(image_len=U32, image_build=U32, kinds=U32))
        self.assertEqual(worst, 143)
        self.assertLessEqual(worst, b.COMMAND_MAX_BODY)
        self.assertEqual((b.BLE_UPDATE_IMAGE_MIN, b.BLE_UPDATE_IMAGE_MAX, b.BLE_UPDATE_MIN_BATTERY_PCT),
                         (1024, 2048000, 50))

    def test_status_echo_with_cmd_result_fits_one_read(self):
        e = message_fields("ble.proto", "CfgEchoPacket")
        worst = echo_packet(beacon_key=report_worst(wake=True), mag_cal=mag_cal_worst())
        self.assertEqual(len(worst), 122)   # test_beacon_key_contract
        # cmd_result (field 17: a 2-byte tag) adds 3 B: 125 B
        field = encode([(e["cmd_result"][1], 7)])
        self.assertEqual(len(field), 3)
        self.assertLessEqual(len(worst) + len(field), BLE_READ_CEILING)


class GeneratedC(unittest.TestCase):
    """The nanopb headers the firmware copies (README: --c-style)."""

    def test_downlink_header(self):
        s = c_struct("downlink.pb.h", "ble_window")
        for f in ("uint32_t minutes;", "uint32_t kinds;", "uint32_t audio_from;",
                  "uint32_t audio_to;"):
            self.assertIn(f, s)
        fl = c_fieldlist("downlink.pb.h", "BLE_WINDOW_FIELDLIST")
        for name, (_, num) in WINDOW_FIELDS.items():
            self.assertRegex(fl, r"\b%s,\s+%d\)" % (name, num))
        # old: BLE_WINDOW_SIZE 42 (before the image fields, 2026-11-26)
        self.assertRegex(read("downlink.pb.h"), r"#define BLE_WINDOW_SIZE\s+154\b")
        self.assertRegex(read("downlink.pb.h"), r"#define DOWNLINK_PACKET_SIZE\s+1030\b")
        for f in ("uint32_t image_len;", "pb_byte_t image_sha256[32];", "uint32_t image_build;",
                  "pb_byte_t image_sig[64];"):
            self.assertIn(f, s)

    def test_ble_header(self):
        self.assertIn("uint32_t cmd_result;", c_struct("ble.pb.h", "cfg_echo_packet"))
        self.assertRegex(c_fieldlist("ble.pb.h", "CFG_ECHO_PACKET_FIELDLIST"),
                         r"UINT32,\s+cmd_result,\s+17\)")


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    def test_descriptors(self):
        ble, dl = PB2
        w = dl.DESCRIPTOR.message_types_by_name["BleWindow"]
        self.assertEqual({f.name: f.number for f in w.fields},
                         {k: v[1] for k, v in WINDOW_FIELDS.items()})
        echo = ble.DESCRIPTOR.message_types_by_name["CfgEchoPacket"]
        self.assertEqual(echo.fields_by_name["cmd_result"].number, ECHO_CMD_RESULT[1])

    def test_round_trip_matches_the_minimal_encoder(self):
        ble, dl = PB2
        p = dl.DownlinkPacket(command=CMD_BLE_WINDOW)
        p.ble_window.minutes = 30
        p.ble_window.key = b"\xa5" * 16
        p.ble_window.kinds = 7
        p.ble_window.audio_from = FROM
        p.ble_window.audio_to = TO
        raw = p.SerializeToString()
        self.assertEqual(raw, window_cmd(kinds=7, audio_from=FROM, audio_to=TO))
        back = dl.DownlinkPacket.FromString(raw)
        self.assertEqual((back.ble_window.kinds, back.ble_window.audio_from, back.ble_window.audio_to),
                         (7, FROM, TO))
        e = ble.CfgEchoPacket(echo_seq=1, cmd_result=7)
        self.assertEqual(ble.CfgEchoPacket.FromString(e.SerializeToString()).cmd_result, 7)


if __name__ == "__main__":
    unittest.main()
