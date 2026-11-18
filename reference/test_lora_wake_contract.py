"""Tests for the LoRa wake wire contract in the .proto files (2026-11-13).

    cd reference && python3 -m unittest -v

A Handheld Receiver wakes listening collars over LoRa with a train of wake
frames and then commands them (collarID_thread docs/CONTRACT_lora_wake.md;
the frames themselves are beacon/README.md, beacon/beacon_v2.py and
beacon/vectors.json). This file pins what the .proto files add for it:

  ble.proto       ScheduleConfig.lora_wake_interval_s = 13
                  enum DirectRegion, LoRaConfig.region = 8, .wake_long_range = 9
                  BeaconKeyReport.wake_group = 6, .wake_gen = 7, .wake_kcv = 8
  downlink.proto  ConfigRadioTiming.lora_wake_interval_s = 6
                  RadioSettings.direct_region = 12, .wake_long_range = 13
                  CMD_LOCATE_NOW = 28, LocateNow, DownlinkPacket.locate = 16
                  BEACON_KEY_SLOT_WAKE = 2, BeaconKeySet.group = 4
  common.proto    PacketHeader.wake_slow_hours = 17

The tests pin the numbers in the .proto text, check that the generated
nanopb headers, Python modules and Swift at the repository root were
regenerated from that text, check the rules the firmware relies on (a
schedule that does not listen keeps its bytes, and with them its
SchedSync_Crc; PacketHeader.radio_crc covers the two new radio settings
and stays what it was for a collar that sets neither; writer_version 2
knows the listening interval)
and check every size budget the additions touch: the 33 B RX2 floor of a
config fragment, the 96 B tunnel frame, the 182 B echo read, the 140 B
status characteristic and the 200 B radio characteristic.

Standard library only, except the generated-Python classes, which are
skipped when the protobuf runtime is missing or too old for the checked-in
modules. The .proto parser and the minimal encoder come from
test_mag_cal_contract.py. Every key below is synthetic.
"""

import os
import re
import sys
import unittest
import zlib

from test_mag_cal_contract import (BLE_READ_CEILING, PB2, ROOT, U32,
                                   enum_values, message_fields, read)
from test_mag_rate_contract import (c_fieldlist, c_struct, field_labels,
                                    raw_block)

# The contract, as the firmware, receiver, server and client agents implement it.
SCHEDULE_FIELD = ("uint32", 13)
TIMING_FIELD = ("uint32", 6)
DIRECT_REGION = {"DIRECT_REGION_AUTO": 0, "DIRECT_REGION_US915": 1,
                 "DIRECT_REGION_EU868": 2, "DIRECT_REGION_AU915": 3,
                 # 4..15: direct-radio regions, 2026-11-17 (test_direct_regions_contract.py)
                 "DIRECT_REGION_BR915": 4, "DIRECT_REGION_LA915": 5, "DIRECT_REGION_IN865": 6,
                 "DIRECT_REGION_JP920": 7, "DIRECT_REGION_KR920": 8, "DIRECT_REGION_SG920": 9,
                 "DIRECT_REGION_MY919": 10, "DIRECT_REGION_TH920": 11, "DIRECT_REGION_VN920": 12,
                 "DIRECT_REGION_ID920": 13, "DIRECT_REGION_TW920": 14, "DIRECT_REGION_RU868": 15}
RADIO_REGION = {"REGION_US915": 0, "REGION_AU915": 1, "REGION_EU868": 2}   # LoRaWAN's, for contrast
LORA_CONFIG_FIELDS = {"radioSpreadingFactor": ("RadioSpreadingFactor", 1),
                      "radioBandwidth": ("RadioBandwidth", 2),
                      "radioCodingRate": ("RadioCodingRate", 3),
                      "tx_power_dbm": ("int32", 4),
                      "sync_word": ("uint32", 5),
                      "frequency": ("uint32", 6),
                      "rx_listen": ("bool", 7),
                      "region": ("DirectRegion", 8),
                      "wake_long_range": ("bool", 9),
                      "frequency_khz": ("uint32", 10)}           # direct-radio regions, 2026-11-17
RADIO_SETTINGS_FIELDS = {"spreading_factor": ("uint32", 1), "bandwidth": ("uint32", 2),
                         "coding_rate": ("uint32", 3), "tx_power_dbm": ("int32", 4),
                         "sync_word": ("uint32", 5), "frequency_mhz": ("uint32", 6),
                         "rx_listen": ("bool", 7), "lost_mode_enabled": ("bool", 8),
                         "lost_activation_epoch": ("uint32", 9), "lost_interval_min": ("uint32", 10),
                         "lost_tx_power_dbm": ("int32", 11),
                         "direct_region": ("uint32", 12), "wake_long_range": ("bool", 13),
                         "frequency_khz": ("uint32", 14)}        # direct-radio regions, 2026-11-17
CMD_LOCATE_NOW = 28
LOCATE_FIELD = ("LocateNow", 16)
HEADER_FIELD = ("uint32", 17)
SLOT_WAKE = 2
GROUP_FIELD = ("uint32", 4)
WAKE_REPORT_FIELDS = {"wake_group": ("uint32", 6), "wake_gen": ("uint32", 7), "wake_kcv": ("bytes", 8)}

INTERVAL_CHOICES = (10, 30, 60)      # what configurators offer; the firmware holds 5..120
RX2_FLOOR = 33                       # the smallest LoRaWAN downlink payload a fragment must fit (US915 RX2)
SERVER_FRAG_BUDGET = 30              # collarid-prod SCHED_FRAG_BUDGET_B
TUNNEL_FRAME_CAP = 96                # ble.options cfg_downlink
STATUS_CHAR_CAP = 140                # SizeStatuschar on both radios
RADIO_CHAR_CAP = 200                 # SizeRadiochar on both radios
SIGNED_FRAME_OVERHEAD = 29           # beacon/README.md, the 0x44 command frame
U64 = (1 << 64) - 1
SYNTHETIC_KEY = bytes(range(16))
KCV = b"\xff" * 3


def _pb2(name):
    """A generated module from the repository root, without writing bytecode
    (the root tracks a __pycache__ directory)."""
    sys.path.insert(0, ROOT)
    saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        return __import__(name)
    except Exception:
        return None
    finally:
        sys.dont_write_bytecode = saved
        sys.path.pop(0)


# ------------------------------------------------------------------- tests

class ProtoContract(unittest.TestCase):

    def test_schedule_field(self):
        f = message_fields("ble.proto", "ScheduleConfig")
        self.assertEqual(f.get("lora_wake_interval_s"), SCHEDULE_FIELD)
        nums = [n for _, n in f.values()]
        self.assertEqual(sorted(nums), list(range(1, 14)))          # 1..13, no gap, no reuse
        # Implicit presence is the point: an explicit `optional` would encode
        # a 0 and move SchedSync_Crc on every schedule that does not listen.
        self.assertEqual(field_labels("ble.proto", "ScheduleConfig")["lora_wake_interval_s"], "")

    def test_downlink_timing_field(self):
        f = message_fields("downlink.proto", "ConfigRadioTiming")
        self.assertEqual(f.get("lora_wake_interval_s"), TIMING_FIELD)
        self.assertEqual(sorted(n for _, n in f.values()), list(range(1, 7)))
        self.assertEqual(set(field_labels("downlink.proto", "ConfigRadioTiming").values()), {"optional"})

    def test_direct_region(self):
        self.assertEqual(enum_values("ble.proto", "DirectRegion"), DIRECT_REGION)
        # Not the LoRaWAN region's numbers: AUTO takes 0, US915 and AU915 move
        # (0 -> 1, 1 -> 3) and only EU868 keeps its 2, so one is never cast
        # to the other.
        self.assertEqual(enum_values("ble.proto", "RadioRegion"), RADIO_REGION)
        self.assertEqual({name: (RADIO_REGION["REGION_" + name], DIRECT_REGION["DIRECT_REGION_" + name])
                          for name in ("US915", "EU868", "AU915")},
                         {"US915": (0, 1), "EU868": (2, 2), "AU915": (1, 3)})
        self.assertEqual(message_fields("ble.proto", "LoRaConfig"), LORA_CONFIG_FIELDS)
        labels = field_labels("ble.proto", "LoRaConfig")
        self.assertEqual((labels["region"], labels["wake_long_range"]), ("", ""))

    def test_radio_settings(self):
        self.assertEqual(message_fields("downlink.proto", "RadioSettings"), RADIO_SETTINGS_FIELDS)
        self.assertEqual(set(field_labels("downlink.proto", "RadioSettings").values()), {"optional"})

    def test_locate_now(self):
        cmds = enum_values("downlink.proto", "CommandType")
        self.assertEqual(cmds.get("CMD_LOCATE_NOW"), CMD_LOCATE_NOW)
        self.assertEqual(len(cmds.values()), len(set(cmds.values())), "duplicate command number")
        # old: self.assertEqual(max(cmds.values()), CMD_LOCATE_NOW)       # the newest command
        # GPS history (2026-11-15) added CMD_SEND_TRACK = 29 after it, and
        # What's on the card (2026-11-16) CMD_CARD_SUMMARY = 30 after that.
        # old: self.assertEqual(max(cmds.values()), cmds.get("CMD_SEND_TRACK"))
        self.assertEqual(max(cmds.values()), cmds.get("CMD_CARD_SUMMARY"))
        self.assertEqual(cmds.get("CMD_CARD_SUMMARY"), cmds.get("CMD_SEND_TRACK") + 1)
        self.assertEqual(cmds.get("CMD_SEND_TRACK"), CMD_LOCATE_NOW + 1)
        self.assertEqual(message_fields("downlink.proto", "LocateNow"), {"timeout_s": ("uint32", 1)})
        dl = message_fields("downlink.proto", "DownlinkPacket")
        self.assertEqual(dl.get("locate"), LOCATE_FIELD)
        self.assertEqual(field_labels("downlink.proto", "DownlinkPacket")["locate"], "optional")
        # old: self.assertEqual(sorted(n for _, n in dl.values()), list(range(1, 17)))
        # (DownlinkPacket.track = 17 since 2026-11-15, GPS history;
        # DownlinkPacket.card_summary = 18 since 2026-11-16, What's on the card)
        # old: self.assertEqual(sorted(n for _, n in dl.values()), list(range(1, 18)))
        self.assertEqual(sorted(n for _, n in dl.values()), list(range(1, 19)))

    def test_send_track(self):
        """GPS history (collarID_thread docs/DESIGN_gps_history.md): the track
        request and its parameters."""
        self.assertEqual(enum_values("downlink.proto", "CommandType").get("CMD_SEND_TRACK"), 29)
        self.assertEqual(message_fields("downlink.proto", "TrackRequest"),
                         {"from_epoch": ("uint32", 1), "to_epoch": ("uint32", 2),
                          "skip": ("uint32", 3), "count": ("uint32", 4)})
        dl = message_fields("downlink.proto", "DownlinkPacket")
        self.assertEqual(dl.get("track"), ("TrackRequest", 17))
        self.assertEqual(field_labels("downlink.proto", "DownlinkPacket")["track"], "optional")

    def test_packet_header(self):
        h = message_fields("common.proto", "PacketHeader")
        self.assertEqual(h.get("wake_slow_hours"), HEADER_FIELD)
        self.assertEqual(field_labels("common.proto", "PacketHeader")["wake_slow_hours"], "optional")
        self.assertEqual(sorted(n for _, n in h.values()), list(range(1, 18)))

    def test_wake_key_slot(self):
        self.assertEqual(enum_values("downlink.proto", "BeaconKeySlot").get("BEACON_KEY_SLOT_WAKE"), SLOT_WAKE)
        self.assertEqual(message_fields("downlink.proto", "BeaconKeySet").get("group"), GROUP_FIELD)
        self.assertEqual(field_labels("downlink.proto", "BeaconKeySet")["group"], "")
        rep = message_fields("ble.proto", "BeaconKeyReport")
        for name, field in WAKE_REPORT_FIELDS.items():
            self.assertEqual(rep.get(name), field, name)
        self.assertRegex(read("ble.options"), r"(?m)^BeaconKeyReport\.wake_kcv\s+max_size:3\s*$")
        self.assertNotRegex(read("ble.options"), r"BeaconKeyReport\.wake_kcv.*fixed_length")

    def test_rules_are_written_down(self):
        ble, dl, common = read("ble.proto"), read("downlink.proto"), read("common.proto")
        sched = raw_block("ble.proto", "message", "ScheduleConfig")
        for phrase in ("0 = not listening", "10, 30 and 60", "5..120", "SCHED_RAIL_WAKE_NO_REGION",
                       "SchedSync_Crc", "firmware main build TBD"):
            self.assertIn(phrase, re.sub(r"\s*//\s*", " ", sched), phrase)
        timing = re.sub(r"\s*//\s*", " ", raw_block("downlink.proto", "message", "ConfigRadioTiming"))
        for phrase in ("0 = not listening", "an explicit 0 IS encoded", "5..120", "SCHED_RAIL_WAKE_NO_REGION"):
            self.assertIn(phrase, timing, phrase)
        # The wake table sits beside the enum, with the numbers of CONTRACT section 1.
        table = ble.split("enum DirectRegion {")[0].split("enum RadioCodingRate {")[1]
        for row in (r"US915\s+919\.000 MHz\s+500 kHz\s+9\s+\(12\)\s+22 dBm",
                    r"EU868\s+869\.525 MHz\s+125 kHz\s+7\s+\(10\)\s+22 dBm",
                    r"AU915\s+919\.000 MHz\s+500 kHz\s+9\s+\(12\)\s+22 dBm"):
            self.assertRegex(table, row)
        self.assertIn("sync word 0x57", table)
        auto = re.sub(r"\s*//\s*", " ", raw_block("ble.proto", "enum", "DirectRegion"))
        for phrase in ("863 to 870 MHz is EU868", "902 to 928 MHz is US915", "never AU915", "does not listen"):
            self.assertIn(phrase, auto, phrase)
        cmd = re.sub(r"\s*//\s*", " ", dl.split("CMD_LOCATE_NOW          = 28")[0].split("CMD_BLE_WINDOW          = 27")[1])
        for phrase in ("0 or absent = 60 s", "10..120", "One at a time",
                       "signed direct radio, LoRaWAN and the BLE tunnel", "answers 5"):
            self.assertIn(phrase, cmd, phrase)
        slot = re.sub(r"\s*//\s*", " ", dl.split("BEACON_KEY_SLOT_WAKE    = 2")[0].split("BEACON_KEY_SLOT_COMMAND = 1")[1])
        for phrase in ('"CID-LORA-WAK" || group_le32 || gen', "BLE tunnel only", "REJECTED_ARG", "REJECTED_GEN",
                       "never rolled back", "ignores roll calls"):
            self.assertIn(phrase, slot, phrase)
        header = re.sub(r"\s*//\s*", " ", common.split("optional uint32 wake_slow_hours = 17")[0]
                        .split("optional uint32 radio_crc = 16")[1])
        for phrase in ("Sent only when not zero, then cleared", "counts once", "3 B on air"):
            self.assertIn(phrase, header, phrase)
        # old: "13 from the firmware that has direct_region and wake_long_range"
        # (the first cut encoded both always; decided 2026-11-13: only when set,
        # so radio_crc does not move at the firmware update)
        crc_rule = re.sub(r"\s*//\s*", " ", common.split("optional uint32 radio_crc = 16")[0])
        for phrase in ("fields 1 to 11, always encoded", "direct_region when it is not 0",
                       "wake_long_range when true", "one rule computes it for every firmware build"):
            self.assertIn(phrase, crc_rule, phrase)
        settings = re.sub(r"\s*//\s*", " ", raw_block("downlink.proto", "message", "RadioSettings"))
        for phrase in ("an explicit 0 or false IS encoded", "direct_region is encoded only when it is not 0",
                       "wake_long_range only when true"):
            self.assertIn(phrase, settings, phrase)
        # The writer revision that knows the listening interval (ScheduleConfigPacket.writer_version).
        writer = re.sub(r"\s*//\s*", " ", ble.split("uint32 writer_version = 7;")[0].split("CfgEchoPacket cfg_echo = 6;")[1])
        for phrase in ("1 = knows TimeWindow.day_mask / start_day / end_day",
                       "2 = knows ScheduleConfig.lora_wake_interval_s",
                       "refuses a schedule write from a version below 2"):
            self.assertIn(phrase, writer, phrase)


class GeneratedC(unittest.TestCase):
    """The nanopb headers are what the firmware copies; they must come from
    the .proto text above (README: nanopb_generator.py --c-style)."""

    def test_ble_header(self):
        h = read("ble.pb.h")
        self.assertRegex(h, r"#define SCHEDULE_CONFIG_LORA_WAKE_INTERVAL_S_TAG\s+13\b")
        body = c_struct("ble.pb.h", "schedule_config")
        self.assertIn("uint32_t lora_wake_interval_s;", body)
        self.assertNotIn("has_lora_wake_interval_s", body)            # implicit presence
        # SINGULAR: a zero is not written, which keeps SchedSync_Crc where it was.
        self.assertRegex(c_fieldlist("ble.pb.h", "SCHEDULE_CONFIG_FIELDLIST"),
                         r"SINGULAR, UINT32,\s+lora_wake_interval_s,\s+13\)")
        for name, num in DIRECT_REGION.items():
            self.assertRegex(h, r"\bDIRECT_REGION_%s = %d\b" % (name, num))
        self.assertRegex(h, r"#define LO_RA_CONFIG_REGION_TAG\s+8\b")
        self.assertRegex(h, r"#define LO_RA_CONFIG_WAKE_LONG_RANGE_TAG\s+9\b")
        body = c_struct("ble.pb.h", "lo_ra_config")
        self.assertIn("direct_region_t region;", body)
        self.assertIn("bool wake_long_range;", body)
        fl = c_fieldlist("ble.pb.h", "LO_RA_CONFIG_FIELDLIST")
        self.assertRegex(fl, r"SINGULAR, UENUM,\s+region,\s+8\)")
        self.assertRegex(fl, r"SINGULAR, BOOL,\s+wake_long_range,\s+9\)")
        for field, (_, num) in WAKE_REPORT_FIELDS.items():
            self.assertRegex(h, r"#define BEACON_KEY_REPORT_%s_TAG\s+%d\b" % (field.upper(), num))
        body = c_struct("ble.pb.h", "beacon_key_report")
        for line in ("uint32_t wake_group;", "uint32_t wake_gen;", "beacon_key_report_wake_kcv_t wake_kcv;"):
            self.assertIn(line, body)
        # nanopb's bounds, each with the fields above at their largest.
        # old: LO_RA_CONFIG_SIZE 35, RADIO_CONFIG_PACKET_SIZE 185 (to 2026-11-17;
        # LoRaConfig.frequency_khz = 10 adds 6 B, test_direct_regions_contract.py)
        for macro, size in (("SCHEDULE_CONFIG_SIZE", 186), ("LO_RA_CONFIG_SIZE", 41),
                            ("RADIO_CONFIG_PACKET_SIZE", 191), ("BEACON_KEY_REPORT_SIZE", 38)):
            self.assertRegex(h, r"#define %s\s+%d\b" % (macro, size))

    def test_downlink_header(self):
        h = read("downlink.pb.h")
        self.assertRegex(h, r"\bCOMMAND_TYPE_CMD_LOCATE_NOW = %d\b" % CMD_LOCATE_NOW)
        self.assertRegex(h, r"#define DOWNLINK_PACKET_LOCATE_TAG\s+16\b")
        body = c_struct("downlink.pb.h", "downlink_packet")
        self.assertIn("bool has_locate;", body)
        self.assertIn("locate_now_t locate;", body)
        self.assertRegex(c_fieldlist("downlink.pb.h", "DOWNLINK_PACKET_FIELDLIST"),
                         r"OPTIONAL, MESSAGE,\s+locate,\s+16\)")
        self.assertIn("uint32_t timeout_s;", c_struct("downlink.pb.h", "locate_now"))
        self.assertRegex(h, r"#define LOCATE_NOW_TIMEOUT_S_TAG\s+1\b")
        self.assertIn("PB_BIND(LOCATE_NOW, locate_now_t, AUTO)", read("downlink.pb.c"))
        self.assertRegex(h, r"#define CONFIG_RADIO_TIMING_LORA_WAKE_INTERVAL_S_TAG\s+6\b")
        body = c_struct("downlink.pb.h", "config_radio_timing")
        self.assertIn("bool has_lora_wake_interval_s;", body)
        self.assertIn("uint32_t lora_wake_interval_s;", body)
        self.assertRegex(c_fieldlist("downlink.pb.h", "CONFIG_RADIO_TIMING_FIELDLIST"),
                         r"OPTIONAL, UINT32,\s+lora_wake_interval_s,\s+6\)")
        self.assertRegex(h, r"#define RADIO_SETTINGS_DIRECT_REGION_TAG\s+12\b")
        self.assertRegex(h, r"#define RADIO_SETTINGS_WAKE_LONG_RANGE_TAG\s+13\b")
        body = c_struct("downlink.pb.h", "radio_settings")
        for line in ("bool has_direct_region;", "uint32_t direct_region;",
                     "bool has_wake_long_range;", "bool wake_long_range;"):
            self.assertIn(line, body)
        self.assertRegex(h, r"\bBEACON_KEY_SLOT_BEACON_KEY_SLOT_WAKE = %d\b" % SLOT_WAKE)
        self.assertRegex(h, r"#define BEACON_KEY_SET_GROUP_TAG\s+4\b")
        self.assertIn("uint32_t group;", c_struct("downlink.pb.h", "beacon_key_set"))
        # old: RADIO_SETTINGS_SIZE 76 (to 2026-11-17; RadioSettings.frequency_khz = 14 adds 6 B)
        for macro, size in (("LOCATE_NOW_SIZE", 6), ("CONFIG_RADIO_TIMING_SIZE", 33),
                            ("RADIO_SETTINGS_SIZE", 82), ("BEACON_KEY_SET_SIZE", 32)):
            self.assertRegex(h, r"#define %s\s+%d\b" % (macro, size))

    def test_common_header(self):
        h = read("common.pb.h")
        self.assertRegex(h, r"#define PACKET_HEADER_WAKE_SLOW_HOURS_TAG\s+17\b")
        body = c_struct("common.pb.h", "packet_header")
        self.assertIn("bool has_wake_slow_hours;", body)
        self.assertIn("uint32_t wake_slow_hours;", body)
        self.assertRegex(c_fieldlist("common.pb.h", "PACKET_HEADER_FIELDLIST"),
                         r"OPTIONAL, UINT32,\s+wake_slow_hours,\s+17\)")
        self.assertRegex(h, r"#define PACKET_HEADER_SIZE\s+100\b")

    def test_every_header_is_one_generator_run(self):
        for name in ("ble.pb.h", "common.pb.h", "downlink.pb.h", "message.pb.h"):
            self.assertIn("/* Generated by nanopb-0.4.8-dev */", read(name), name)

    def test_c_names_do_not_collide_with_the_wake_codec(self):
        """The firmware includes the nanopb headers, beacon_frame.h and
        beacon/c/wake_frame.h in one unit: no macro, type or enumerator of
        the wake codec may be one of theirs."""
        def names(text):
            return (set(re.findall(r"#define\s+(\w+)", text)) | set(re.findall(r"\b(\w+_t);", text))
                    | set(re.findall(r"^\s*([A-Z][A-Z0-9_]+)\s*=\s*\d", text, re.M)))

        wake = names(read(os.path.join("beacon", "c", "wake_frame.h"))) - {"WAKE_FRAME_H"}
        self.assertGreater(len(wake), 60)
        others = set()
        for name in ("ble.pb.h", "common.pb.h", "downlink.pb.h", "message.pb.h", "addon.pb.h",
                     os.path.join("beacon", "c", "beacon_frame.h"), os.path.join("beacon", "c", "aead_ccm.h")):
            others |= names(read(name))
        self.assertEqual(wake & others, set())
        # ... and the codec's region numbers are the enum's.
        h = read(os.path.join("beacon", "c", "wake_frame.h"))
        for name in ("US915", "EU868", "AU915"):
            self.assertRegex(h, r"#define WAKE_REGION_%s\s+%du" % (name, DIRECT_REGION["DIRECT_REGION_" + name]))
            self.assertRegex(h, r"#define WAKE_LORAWAN_%s\s+%du" % (name, RADIO_REGION["REGION_" + name]))


class GeneratedSwift(unittest.TestCase):

    def test_ble_swift(self):
        s = read("ble.pb.swift")
        self.assertIn("enum DirectRegion: SwiftProtobuf.Enum", s)
        for case in ("case auto // = 0", "case us915 // = 1", "case eu868 // = 2", "case au915 // = 3"):
            self.assertIn(case, s.split("enum DirectRegion: SwiftProtobuf.Enum")[1].split("\n}\n")[0], case)
        self.assertIn('13: .standard(proto: "lora_wake_interval_s")', s)
        self.assertIn('9: .standard(proto: "wake_long_range")', s)
        self.assertIn('8: .same(proto: "region")', s)
        self.assertIn('6: .standard(proto: "wake_group")', s)
        self.assertIn('7: .standard(proto: "wake_gen")', s)
        self.assertIn('8: .standard(proto: "wake_kcv")', s)
        self.assertIn("var wakeKcv: Data = Data()", s)

    def test_common_swift(self):
        s = read("common.pb.swift")
        self.assertIn('17: .standard(proto: "wake_slow_hours")', s)
        self.assertIn("var hasWakeSlowHours: Bool", s)


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    def test_descriptors_match_proto(self):
        ble, dl = PB2
        f = ble.DESCRIPTOR.message_types_by_name["ScheduleConfig"].fields_by_name["lora_wake_interval_s"]
        self.assertEqual((f.number, f.type, f.has_presence), (13, f.TYPE_UINT32, False))
        e = ble.DESCRIPTOR.enum_types_by_name["DirectRegion"]
        self.assertEqual({v.name: v.number for v in e.values}, DIRECT_REGION)
        lc = ble.DESCRIPTOR.message_types_by_name["LoRaConfig"]
        self.assertEqual((lc.fields_by_name["region"].number, lc.fields_by_name["region"].enum_type.name), (8, "DirectRegion"))
        self.assertEqual((lc.fields_by_name["wake_long_range"].number, lc.fields_by_name["wake_long_range"].type),
                         (9, lc.fields_by_name["wake_long_range"].TYPE_BOOL))
        rep = ble.DESCRIPTOR.message_types_by_name["BeaconKeyReport"]
        self.assertEqual({n: rep.fields_by_name[n].number for n in WAKE_REPORT_FIELDS}, {"wake_group": 6, "wake_gen": 7, "wake_kcv": 8})
        t = dl.DESCRIPTOR.message_types_by_name["ConfigRadioTiming"].fields_by_name["lora_wake_interval_s"]
        self.assertEqual((t.number, t.has_presence), (6, True))
        rs = dl.DESCRIPTOR.message_types_by_name["RadioSettings"]
        self.assertEqual([fd.name for fd in rs.fields], list(RADIO_SETTINGS_FIELDS))
        self.assertTrue(all(fd.has_presence for fd in rs.fields))
        cmd = dl.DESCRIPTOR.enum_types_by_name["CommandType"]
        self.assertEqual(cmd.values_by_name["CMD_LOCATE_NOW"].number, CMD_LOCATE_NOW)
        loc = dl.DESCRIPTOR.message_types_by_name["DownlinkPacket"].fields_by_name["locate"]
        self.assertEqual((loc.message_type.name, loc.number, loc.has_presence), ("LocateNow", 16, True))
        slot = dl.DESCRIPTOR.enum_types_by_name["BeaconKeySlot"]
        self.assertEqual(slot.values_by_name["BEACON_KEY_SLOT_WAKE"].number, SLOT_WAKE)
        self.assertEqual(dl.DESCRIPTOR.message_types_by_name["BeaconKeySet"].fields_by_name["group"].number, 4)
        common = _pb2("common_pb2")
        w = common.DESCRIPTOR.message_types_by_name["PacketHeader"].fields_by_name["wake_slow_hours"]
        self.assertEqual((w.number, w.has_presence), (17, True))


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class ScheduleWireRule(unittest.TestCase):
    """0 = not listening, and it costs nothing on the wire."""

    def test_a_schedule_that_does_not_listen_keeps_its_bytes(self):
        """SchedSync_Crc hashes the encoded schedule. Five slots that do not
        listen encode exactly as they did before the field, so the CRC of
        every deployed schedule stays what it was."""
        ble, _ = PB2

        def packet(intervals):
            p = ble.ScheduleConfigPacket(engaged=True)
            for i in range(5):
                s = p.schedules.add()
                s.window.start_hour = i
                s.lora_enabled = True
                s.lora_send_interval_min = 60
                s.magnetometer.enabled = True
                if intervals[i] is not None:
                    s.lora_wake_interval_s = intervals[i]
            return p.SerializeToString()

        never_set, zeroed = packet([None] * 5), packet([0] * 5)
        self.assertEqual(never_set, zeroed)
        self.assertNotIn(b"\x68\x00", never_set)
        # Listening is exactly one tag (13 << 3 = 0x68) and one byte more per slot, up to 120 s.
        for s in INTERVAL_CHOICES + (5, 120):
            listening = packet([s, 0, 0, 0, 0])
            self.assertEqual(len(listening), len(never_set) + 2)
            self.assertIn(b"\x68" + bytes([s]), listening)
            back = ble.ScheduleConfigPacket.FromString(listening)
            self.assertEqual([x.lora_wake_interval_s for x in back.schedules], [s, 0, 0, 0, 0])
        # A decoder that predates the field reads the rest unchanged.
        old = ble.ScheduleConfigPacket.FromString(packet([30] * 5))
        self.assertEqual([x.lora_send_interval_min for x in old.schedules], [60] * 5)

    def test_a_radio_config_without_the_wake_settings_keeps_its_bytes(self):
        ble, _ = PB2
        legacy = ble.LoRaConfig(radioSpreadingFactor=4, tx_power_dbm=22, sync_word=0x12, frequency=915, rx_listen=True)
        same = ble.LoRaConfig(radioSpreadingFactor=4, tx_power_dbm=22, sync_word=0x12, frequency=915, rx_listen=True,
                              region=0, wake_long_range=False)
        self.assertEqual(legacy.SerializeToString(), same.SerializeToString())
        both = ble.LoRaConfig(radioSpreadingFactor=4, tx_power_dbm=22, sync_word=0x12, frequency=915, rx_listen=True,
                              region=3, wake_long_range=True)
        self.assertEqual(both.SerializeToString(), legacy.SerializeToString() + b"\x40\x03\x48\x01")
        self.assertEqual(ble.LoRaConfig.FromString(legacy.SerializeToString()).region, 0)   # AUTO

    def test_downlink_absent_leaves_explicit_zero_turns_off(self):
        _, dl = PB2
        absent = dl.ConfigRadioTiming()
        self.assertFalse(absent.HasField("lora_wake_interval_s"))
        self.assertEqual(absent.SerializeToString(), b"")
        off = dl.ConfigRadioTiming(lora_wake_interval_s=0)
        self.assertTrue(off.HasField("lora_wake_interval_s"))
        self.assertEqual(off.SerializeToString(), b"\x30\x00")
        for s in INTERVAL_CHOICES:
            self.assertEqual(dl.ConfigRadioTiming(lora_wake_interval_s=s).SerializeToString(), b"\x30" + bytes([s]))


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class SizeBudget(unittest.TestCase):

    @staticmethod
    def _fragment(dl, txn=16383, **timing):
        """A config fragment as the server sends it since fw 360: no epoch,
        the last slot, the last fragment index of a full transaction, a
        2-byte transaction id."""
        p = dl.DownlinkPacket(cfg_txn_id=txn)
        p.config.schedule_index = 4
        p.config.fragment_index = 31
        p.config.fragment_total = 32
        for k, v in timing.items():
            setattr(p.config.cfg_radio_timing, k, v)
        return p.SerializeToString()

    def test_radio_timing_fragment_fits_the_rx2_floor(self):
        _, dl = PB2
        before = dict(lorawan_enabled=True, lorawan_send_interval_min=1440, lora_enabled=True,
                      lora_send_interval_min=1440, tx_power_dbm=22)
        self.assertEqual(len(self._fragment(dl, **before)), 25)
        whole = self._fragment(dl, lora_wake_interval_s=120, **before)
        self.assertEqual(len(whole), 27)                              # every field of the kind: 2 B more
        self.assertLessEqual(len(whole), SERVER_FRAG_BUDGET)
        self.assertLessEqual(len(whole), RX2_FLOOR)
        self.assertEqual(len(self._fragment(dl, lora_wake_interval_s=30)), 15)   # the setting alone
        # A negative tx_power_dbm is a 10-byte varint and was over the floor before
        # the field (the server splits the kind); the field does not change that.
        before["tx_power_dbm"] = -9
        self.assertEqual(len(self._fragment(dl, **before)), 34)

    def test_radio_settings_grow_by_four_bytes(self):
        _, dl = PB2
        eleven = dict(spreading_factor=5, bandwidth=2, coding_rate=3, tx_power_dbm=22, sync_word=0x57,
                      frequency_mhz=919, rx_listen=True, lost_mode_enabled=True,
                      lost_activation_epoch=U32, lost_interval_min=1440, lost_tx_power_dbm=22)
        a = dl.RadioSettings(**eleven).SerializeToString()
        b = dl.RadioSettings(direct_region=3, wake_long_range=True, **eleven).SerializeToString()
        self.assertEqual(b, a + b"\x60\x03\x68\x01")
        # The two alone in a fragment (field 16 has a two-byte tag): 16 B, inside the floor.
        p = dl.DownlinkPacket(cfg_txn_id=16383)
        p.config.fragment_index, p.config.fragment_total = 31, 32
        p.config.cfg_radio.direct_region = 3
        p.config.cfg_radio.wake_long_range = True
        self.assertEqual(len(p.SerializeToString()), 16)
        self.assertLessEqual(len(p.SerializeToString()), RX2_FLOOR)

    def test_radio_crc_covers_the_wake_settings_and_does_not_move(self):
        """PacketHeader.radio_crc is CRC-32 over RadioSettings with fields 1
        to 11 always present, direct_region present only when it is not 0 and
        wake_long_range only when true (decided 2026-11-13). So the numbers
        the firmware's host test pinned before LoRa wake (test_sched_sync.cpp:
        0x7F62DCFD, 0xCA0B9622) stay for a collar that sets neither, and the
        collar, the server, the website and the app compute it by one rule
        for every build. The other numbers here are for them to pin too.
        old (the first cut, both always encoded): 0xD0A8AE16 and 0xDCA69822
        at region 0, long range off."""
        _, dl = PB2
        bench = dict(spreading_factor=4, bandwidth=0, coding_rate=0, tx_power_dbm=22, sync_word=0x12,
                     frequency_mhz=915, rx_listen=True, lost_mode_enabled=True,
                     lost_activation_epoch=1794408720, lost_interval_min=1, lost_tx_power_dbm=22)
        bare = dict(spreading_factor=0, bandwidth=0, coding_rate=0, tx_power_dbm=-9, sync_word=0,
                    frequency_mhz=868, rx_listen=False, lost_mode_enabled=False,
                    lost_activation_epoch=0, lost_interval_min=0, lost_tx_power_dbm=0)

        def radio_crc(eleven, region=0, long_range=False):
            rs = dl.RadioSettings(**eleven)            # fields 1..11: always, zeros included
            if region != 0:
                rs.direct_region = region              # only when not AUTO
            if long_range:
                rs.wake_long_range = True              # only when on
            return zlib.crc32(rs.SerializeToString()) & 0xFFFFFFFF

        # (region, long range) -> radio_crc, for the firmware's two cases
        want = {
            "bench": (bench, {(0, False): 0x7F62DCFD,       # unchanged by the firmware update
                              (1, False): 0x7D5437A3, (2, False): 0xE45D6619, (3, False): 0x935A568F,
                              (0, True): 0xB58DBDAB,
                              (1, True): 0xA66DF4B7, (2, True): 0xA42B4AEE, (3, True): 0xA5E920D9}),
            "bare": (bare, {(0, False): 0xCA0B9622,         # unchanged by the firmware update
                            (1, False): 0xEDFDF394, (2, False): 0x74F4A22E, (3, False): 0x03F392B8,
                            (0, True): 0x2524799C,
                            (1, True): 0xAA63C283, (2, True): 0xA8257CDA, (3, True): 0xA9E716ED}),
        }
        for name, (eleven, table) in want.items():
            for (region, long_range), crc in table.items():
                self.assertEqual(radio_crc(eleven, region, long_range), crc, (name, region, long_range))
            self.assertEqual(len(set(table.values())), 8, name)      # either setting moves it
        # What goes into the hash: the 11 fields, then tag 12 (0x60) and tag 13
        # (0x68) only for a set value. An explicit 0 or false is NOT in it,
        # though a fragment may carry one (it sets AUTO or the standard setting).
        base = dl.RadioSettings(**bench).SerializeToString()
        self.assertEqual(len(base), 27)
        both = dl.RadioSettings(direct_region=2, wake_long_range=True, **bench).SerializeToString()
        self.assertEqual(both, base + b"\x60\x02\x68\x01")
        explicit = dl.RadioSettings(direct_region=0, wake_long_range=False, **bench).SerializeToString()
        self.assertEqual(explicit, base + b"\x60\x00\x68\x00")
        self.assertNotEqual(zlib.crc32(explicit) & 0xFFFFFFFF, 0x7F62DCFD)   # which is why they are left out

    def test_locate_now(self):
        _, dl = PB2
        bare = dl.DownlinkPacket(command=CMD_LOCATE_NOW)
        self.assertEqual(bare.SerializeToString(), b"\x10\x1c")                    # 2 B: a 60 s attempt
        p = dl.DownlinkPacket(command=CMD_LOCATE_NOW)
        p.locate.timeout_s = 60
        self.assertEqual(p.SerializeToString(), b"\x10\x1c\x82\x01\x02\x08\x3c")   # 7 B
        self.assertEqual(len(p.SerializeToString()) + SIGNED_FRAME_OVERHEAD, 36)   # the signed 0x44 frame
        p.locate.timeout_s = 120                                                   # the collar's ceiling
        self.assertEqual(len(p.SerializeToString()), 7)
        p.epoch = 1794600000                                                       # a LoRaWAN downlink carries the time
        self.assertEqual(len(p.SerializeToString()), 13)
        self.assertLessEqual(len(p.SerializeToString()), RX2_FLOOR)
        self.assertLessEqual(len(p.SerializeToString()), TUNNEL_FRAME_CAP)

    def test_wake_slow_hours(self):
        common = _pb2("common_pb2")
        self.assertEqual(common.PacketHeader(wake_slow_hours=3).SerializeToString(), b"\x88\x01\x03")   # 3 B
        self.assertEqual(len(common.PacketHeader(wake_slow_hours=127).SerializeToString()), 3)
        h = common.PacketHeader(system_uid=0x7E57C0DE, packet_index=9)
        self.assertFalse(h.HasField("wake_slow_hours"))
        before = h.SerializeToString()
        h.wake_slow_hours = 1
        self.assertEqual(h.SerializeToString(), before + b"\x88\x01\x01")

    def test_wake_key_set_fits_the_tunnel_frame(self):
        _, dl = PB2
        frame = dl.DownlinkPacket(epoch=U32, command=19, cfg_txn_id=U32)
        without = len(frame.SerializeToString())
        frame.beacon_key.slot = SLOT_WAKE
        frame.beacon_key.gen = 255
        frame.beacon_key.key = SYNTHETIC_KEY
        frame.beacon_key.group = U32
        self.assertEqual(len(frame.SerializeToString()) - without, 31)     # downlink.proto: "31 B for the wake slot"
        self.assertEqual(len(frame.SerializeToString()), 45)
        self.assertLessEqual(len(frame.SerializeToString()), TUNNEL_FRAME_CAP)
        back = dl.DownlinkPacket.FromString(frame.SerializeToString())
        self.assertEqual((back.beacon_key.slot, back.beacon_key.group, back.beacon_key.gen), (2, U32, 255))
        # A set that leaves group out decodes to group 0, which the collar refuses.
        frame.beacon_key.ClearField("group")
        self.assertEqual(dl.DownlinkPacket.FromString(frame.SerializeToString()).beacon_key.group, 0)
        clear = dl.DownlinkPacket(command=22)
        clear.beacon_key.slot = SLOT_WAKE
        self.assertEqual(clear.SerializeToString(), b"\x10\x16\x5a\x02\x08\x02")

    def _status_packet(self, ble, wake, group=False):
        """The collar's status packet with every field it fills at its
        largest (ble.proto SystemStatePacket: never gps_data or sensors)."""
        p = ble.BlePacket()
        p.header.epoch = U32
        p.header.system_uid = U32
        st = p.system_state_packet
        st.engage_state = True
        st.battery.charging, st.battery.voltage, st.battery.percentage = True, 1.0, 1.0
        st.sdcard.detected, st.sdcard.space_remaining, st.sdcard.total_space = True, U64, U64
        st.sdcard.family, st.sdcard.product_name, st.sdcard.off_between_writes = 7, "SN01T", True
        st.firmware_version = "b" + "9" * 14
        st.hw_diag = U32
        st.beacon_key.state, st.beacon_key.gen, st.beacon_key.kcv, st.beacon_key.result = 2, 255, KCV, 5
        if wake:
            st.beacon_key.wake_gen, st.beacon_key.wake_kcv = 255, KCV
        if group:
            st.beacon_key.wake_group = U32
        st.board.cpu, st.board.top = 1, 1
        bp = st.battery_protection
        bp.on, bp.min_temp_c, bp.held_off, bp.die_temp_x10 = True, -30, True, -400
        st.battery_hibernate_pct, st.battery_resume_pct = 40, 60
        st.battery_saving_band_pct, st.saving_power = 15, True     # 2026-11-18: 4 B more
        return p.SerializeToString()

    def test_status_packet_fits_the_characteristic(self):
        ble, _ = PB2
        # old: 127 without the wake key, 135 with it (before the saving band and state, 2026-11-18)
        self.assertEqual(len(self._status_packet(ble, wake=False)), 131)
        with_wake = self._status_packet(ble, wake=True)
        self.assertEqual(len(with_wake), 139)                                # what ble.proto states now
        self.assertLessEqual(len(with_wake), STATUS_CHAR_CAP)
        # Why wake_group stays on the echo: with it the packet would not fit.
        # old: self.assertEqual(len(self._status_packet(ble, wake=True, group=True)), 141)
        self.assertEqual(len(self._status_packet(ble, wake=True, group=True)), 146)
        self.assertGreater(len(self._status_packet(ble, wake=True, group=True)), STATUS_CHAR_CAP)
        r = ble.BlePacket.FromString(with_wake).system_state_packet.beacon_key
        self.assertEqual((r.wake_gen, r.wake_kcv, r.wake_group, r.tx_counter), (255, KCV, 0, 0))

    def test_wake_report_sizes(self):
        ble, _ = PB2
        none = ble.BeaconKeyReport(state=1, gen=3, kcv=KCV, result=1)
        held = ble.BeaconKeyReport(state=1, gen=3, kcv=KCV, result=1, wake_group=42, wake_gen=1, wake_kcv=KCV)
        self.assertEqual(held.SerializeToString(), none.SerializeToString() + b"\x30\x2a\x38\x01\x42\x03" + KCV)
        worst = ble.BeaconKeyReport(wake_group=U32, wake_gen=255, wake_kcv=KCV)
        self.assertEqual(len(worst.SerializeToString()), 14)                 # "At most 14 B on the echo"
        self.assertEqual(len(ble.BeaconKeyReport(wake_gen=255, wake_kcv=KCV).SerializeToString()), 8)   # "8 B on the status packet"
        # No wake key: nothing on the wire, so a report of firmware that
        # predates the slot and one that holds no wake key read the same.
        self.assertEqual(ble.BeaconKeyReport(wake_group=0, wake_gen=0, wake_kcv=b"").SerializeToString(), b"")
        old = ble.BeaconKeyReport.FromString(none.SerializeToString())
        self.assertEqual((old.wake_group, old.wake_gen, old.wake_kcv), (0, 0, b""))

    def test_radio_config_fits_its_characteristic(self):
        """The radio characteristic holds 200 B on both radios. The largest
        radio configuration a client or the collar writes there: ABP
        credentials, every setting set, and (worst of all) three negative
        transmit powers, each a 10-byte varint."""
        ble, _ = PB2

        def packet(wake, negative):
            p = ble.BlePacket()
            p.header.epoch = U32
            p.header.system_uid = U32
            r = p.radio_config_packet
            w = r.loRaWAN_config
            w.region, w.auth = 2, 1
            w.abp.dev_addr = b"\xff" * 4
            for k in ("nwk_s_key", "app_s_key", "f_nwk_s_int_key", "s_nwk_s_int_key"):
                setattr(w.abp, k, b"\xff" * 16)
            power = -9 if negative else 22
            w.transmit_interval_min, w.tx_only_on_new_gps_fix, w.tx_power_dbm = 1440, True, power
            c = r.loRa_config
            c.radioSpreadingFactor, c.radioBandwidth, c.radioCodingRate = 5, 2, 3
            c.tx_power_dbm, c.sync_word, c.frequency, c.rx_listen = power, 0xFF, 928, True
            if wake:
                c.region, c.wake_long_range = 3, True
            r.lostMode_enabled = True
            lm = r.lostMode_config
            lm.activation_epoch, lm.transmit_interval_min, lm.tx_power_dbm = U32, 1440, power
            r.mortality_enabled = True
            r.mortality_config.trigger_duration_hours, r.mortality_config.transmit_interval_min = 720, 1440
            return len(p.SerializeToString())

        self.assertEqual((packet(False, False), packet(True, False)), (153, 157))
        self.assertEqual((packet(False, True), packet(True, True)), (180, 184))
        self.assertLessEqual(packet(True, True), RADIO_CHAR_CAP)

    def test_status_echo_still_fits_one_read(self):
        # The echo's worst case with a wake key is in test_beacon_key_contract
        # (122 B); here, that the two tests agree on the ceiling.
        self.assertEqual(BLE_READ_CEILING, 182)


if __name__ == "__main__":
    unittest.main()
