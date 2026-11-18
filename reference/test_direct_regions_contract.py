"""Tests for the direct-radio regions wire contract in the .proto files (2026-11-17).

    cd reference && python3 -m unittest -v test_direct_regions_contract

collarID_thread docs/CONTRACT_direct_regions.md section 11. This file pins
what the .proto files add for it:

  ble.proto       enum DirectRegion 4..15 (BR915 ... RU868), the rule sets
                  of contracts/collarid_contracts.json direct_regions
                  LoRaConfig.frequency_khz = 10 (uint32, implicit presence)
  downlink.proto  RadioSettings.frequency_khz = 14 (optional uint32)

and the rules the repos rely on: a whole-MHz frequency writes no kHz field
(so every existing configuration keeps its bytes and every collar on a whole
MHz keeps its PacketHeader.radio_crc), the kHz frequency is written with the
MHz rounded to the nearest (a half up) for older readers, and the size
budgets still hold (the 200 B radio characteristic, the 33 B RX2 floor of a
fragment). The generated nanopb headers, Python modules and Swift are
checked against the .proto text. The region table itself (rule sets,
countries, check, convert, budgets) is contracts/; its tests are
contracts/test_contracts.py and beacon/test_direct_rules_c.py.

Standard library only, except the generated-Python classes, which are
skipped when the protobuf runtime is missing or too old.
"""

import importlib.util
import json
import os
import re
import unittest
import zlib

from test_lora_wake_contract import RADIO_CHAR_CAP, RX2_FLOOR, U32
from test_mag_cal_contract import PB2, ROOT, enum_values, message_fields, read
from test_mag_rate_contract import c_fieldlist, c_struct, field_labels

# contracts/reference.py by path: putting contracts/ on sys.path would shadow
# this directory's make_vectors.py for the other tests of the run.
_spec = importlib.util.spec_from_file_location("contracts_reference", os.path.join(ROOT, "contracts", "reference.py"))
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)

with open(os.path.join(ROOT, "contracts", "collarid_contracts.json"), encoding="utf-8") as _fh:
    SPEC = json.load(_fh)
RULE_SETS = {"DIRECT_REGION_" + r["key"]: r["id"] for r in SPEC["direct_regions"]["rule_sets"]}
LORA_FIELD = ("uint32", 10)
RADIO_FIELD = ("uint32", 14)

# PacketHeader.radio_crc for the firmware's bench case (test_sched_sync.cpp:
# SF11, 915 MHz, listen on, lost mode on) moved to kHz channels. The first is
# the whole-MHz value every collar reports today (unchanged).
BENCH = dict(spreading_factor=4, bandwidth=0, coding_rate=0, tx_power_dbm=22, sync_word=0x12,
             frequency_mhz=915, rx_listen=True, lost_mode_enabled=True,
             lost_activation_epoch=1794408720, lost_interval_min=1, lost_tx_power_dbm=22)
RADIO_CRC = {
    # (direct_region, long range, frequency in kHz) -> radio_crc
    (0, False, 915000): 0x7F62DCFD,          # unchanged: a whole MHz writes no field 14
    (2, False, 869525): 0xFB1DC75E,          # EU band O: 870 MHz + 869525 kHz + region 2
    (0, False, 869525): 0x59158E63,
    (8, False, 922100): 0x787C03A6,          # Korea's grid
    (2, True, 868100): 0xE6A0F68E,
    (2, False, 869000): 0xA4EF8597,          # a whole MHz again: no field 14
}


def radio_settings_for_crc(dl, eleven, region, long_range, freq_khz):
    """RadioSettings as PacketHeader.radio_crc takes it: fields 1..11 always,
    12 when not 0, 13 when true, 14 only when the frequency is not a whole
    MHz (frequency_mhz then the nearest MHz)."""
    mhz, khz = R.dr_freq_to_fields(freq_khz)
    rs = dl.RadioSettings(**dict(eleven, frequency_mhz=mhz))
    if region:
        rs.direct_region = region
    if long_range:
        rs.wake_long_range = True
    if khz:
        rs.frequency_khz = khz
    return rs


class ProtoContract(unittest.TestCase):

    def test_direct_region_is_the_rule_set_table(self):
        values = enum_values("ble.proto", "DirectRegion")
        self.assertEqual(values, dict(DIRECT_REGION_AUTO=0, **RULE_SETS))
        self.assertEqual(sorted(RULE_SETS.values()), list(range(1, 16)))
        self.assertEqual(R.DR_CONST["region_max"], max(values.values()))

    def test_lora_config_frequency_khz(self):
        f = message_fields("ble.proto", "LoRaConfig")
        self.assertEqual(f["frequency_khz"], LORA_FIELD)
        self.assertEqual(sorted(n for _, n in f.values()), list(range(1, 11)))
        # implicit presence: 0 is not encoded, so existing configs keep their bytes
        self.assertEqual(field_labels("ble.proto", "LoRaConfig")["frequency_khz"], "")

    def test_radio_settings_frequency_khz(self):
        f = message_fields("downlink.proto", "RadioSettings")
        self.assertEqual(f["frequency_khz"], RADIO_FIELD)
        self.assertEqual(sorted(n for _, n in f.values()), list(range(1, 15)))
        self.assertEqual(field_labels("downlink.proto", "RadioSettings")["frequency_khz"], "optional")

    def test_the_comments_say_the_rules(self):
        ble = re.sub(r"\s*//\s*", " ", read("ble.proto"))
        dl = re.sub(r"\s*//\s*", " ", read("downlink.proto"))
        for phrase in ("CONFIG.CSV key lora_region (0..15)", "above 15 is no region",
                       "Written only when the frequency is not a whole MHz",
                       "rounded to the nearest MHz (a half up)", "CONFIG.CSV key lora_frequency_khz"):
            self.assertIn(phrase, ble, phrase)
        for phrase in ("refuse a direct_region above 15", "ONLY WHEN THE FREQUENCY IS NOT A WHOLE MHz",
                       "keeps its radio_crc"):
            self.assertIn(phrase, dl, phrase)
        self.assertNotIn("lora_region (0..3)", ble)


class GeneratedC(unittest.TestCase):

    def test_ble_header(self):
        h = read("ble.pb.h")
        for name, num in RULE_SETS.items():
            self.assertRegex(h, r"\bDIRECT_REGION_%s = %d\b" % (name, num))
        self.assertRegex(h, r"#define _DIRECT_REGION_MAX DIRECT_REGION_DIRECT_REGION_RU868\b")
        self.assertRegex(h, r"#define LO_RA_CONFIG_FREQUENCY_KHZ_TAG\s+10\b")
        self.assertIn("uint32_t frequency_khz;", c_struct("ble.pb.h", "lo_ra_config"))
        self.assertRegex(c_fieldlist("ble.pb.h", "LO_RA_CONFIG_FIELDLIST"), r"SINGULAR, UINT32,\s+frequency_khz,\s+10\)")
        for macro, size in (("LO_RA_CONFIG_SIZE", 41), ("RADIO_CONFIG_PACKET_SIZE", 191)):
            self.assertRegex(h, r"#define %s\s+%d\b" % (macro, size))

    def test_downlink_header(self):
        h = read("downlink.pb.h")
        self.assertRegex(h, r"#define RADIO_SETTINGS_FREQUENCY_KHZ_TAG\s+14\b")
        body = c_struct("downlink.pb.h", "radio_settings")
        self.assertIn("bool has_frequency_khz;", body)
        self.assertIn("uint32_t frequency_khz;", body)
        self.assertRegex(c_fieldlist("downlink.pb.h", "RADIO_SETTINGS_FIELDLIST"),
                         r"OPTIONAL, UINT32,\s+frequency_khz,\s+14\)")
        # old: ("CONFIG_FRAGMENT_SIZE", 460), ("DOWNLINK_PACKET_SIZE", 887)   (before
        # ConfigSystem.battery_saving_band_pct, 6 more in nanopb's bound, 2026-11-18)
        for macro, size in (("RADIO_SETTINGS_SIZE", 82), ("CONFIG_FRAGMENT_SIZE", 466),
                            ("DOWNLINK_PACKET_SIZE", 893)):
            self.assertRegex(h, r"#define %s\s+%d\b" % (macro, size))
        m = read("message.pb.h")
        # old: (("CONFIG_REPORT_SIZE", 487), ("MESSAGE_PACKET_SIZE", 2565))   (before the saving band, 2026-11-18)
        for macro, size in (("CONFIG_REPORT_SIZE", 493), ("MESSAGE_PACKET_SIZE", 2571)):
            self.assertRegex(m, r"#define %s\s+%d\b" % (macro, size))

    def test_swift(self):
        s = read("ble.pb.swift")
        enum = s.split("enum DirectRegion: SwiftProtobuf.Enum")[1].split("\n}\n")[0]
        for key, num in RULE_SETS.items():
            swift = key[len("DIRECT_REGION_"):].lower()            # swift-protobuf drops the enum prefix
            self.assertRegex(enum, r"case %s // = %d\b" % (swift, num))
        self.assertIn("var frequencyKhz: UInt32 = 0", s)
        self.assertIn('10: .standard(proto: "frequency_khz")', s)


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    def test_descriptors(self):
        ble, dl = PB2
        e = ble.DESCRIPTOR.enum_types_by_name["DirectRegion"]
        self.assertEqual({v.name: v.number for v in e.values}, dict(DIRECT_REGION_AUTO=0, **RULE_SETS))
        f = ble.DESCRIPTOR.message_types_by_name["LoRaConfig"].fields_by_name["frequency_khz"]
        self.assertEqual((f.number, f.type, f.has_presence), (10, f.TYPE_UINT32, False))
        f = dl.DESCRIPTOR.message_types_by_name["RadioSettings"].fields_by_name["frequency_khz"]
        self.assertEqual((f.number, f.type, f.has_presence), (14, f.TYPE_UINT32, True))

    def test_a_whole_mhz_config_keeps_its_bytes(self):
        ble, _ = PB2
        legacy = ble.LoRaConfig(radioSpreadingFactor=4, tx_power_dbm=22, sync_word=0x12, frequency=915)
        mhz, khz = R.dr_freq_to_fields(915000)
        same = ble.LoRaConfig(radioSpreadingFactor=4, tx_power_dbm=22, sync_word=0x12, frequency=mhz, frequency_khz=khz)
        self.assertEqual(same.SerializeToString(), legacy.SerializeToString())
        self.assertEqual(ble.LoRaConfig.FromString(legacy.SerializeToString()).frequency_khz, 0)
        mhz, khz = R.dr_freq_to_fields(869525)
        eu = ble.LoRaConfig(radioSpreadingFactor=4, tx_power_dbm=22, sync_word=0x12, frequency=mhz, frequency_khz=khz)
        self.assertEqual((mhz, khz), (870, 869525))
        self.assertEqual(eu.SerializeToString().hex(), "08042016281230e60650958935")    # + 50 95 89 35: 4 B
        back = ble.LoRaConfig.FromString(eu.SerializeToString())
        self.assertEqual(R.dr_freq_from_fields(back.frequency, back.frequency_khz), 869525)

    def test_radio_crc_moves_only_for_a_khz_frequency(self):
        _, dl = PB2
        for (region, long_range, khz), want in RADIO_CRC.items():
            rs = radio_settings_for_crc(dl, BENCH, region, long_range, khz)
            self.assertEqual(zlib.crc32(rs.SerializeToString()) & 0xFFFFFFFF, want, (region, long_range, khz))
            self.assertEqual(rs.HasField("frequency_khz"), khz % 1000 != 0)
        # Field 14 comes last, after 12 and 13, only when set.
        base = radio_settings_for_crc(dl, BENCH, 2, True, 869525).SerializeToString()
        self.assertTrue(base.endswith(b"\x60\x02\x68\x01\x70\x95\x89\x35"))

    def test_the_radio_characteristic_still_holds_the_largest_configuration(self):
        """test_lora_wake_contract's worst case (184 B: ABP, every setting,
        three negative powers, region and long range), now with a kHz
        frequency: 4 B more for any frequency below 2097.152 MHz."""
        ble, _ = PB2
        p = ble.BlePacket()
        p.header.epoch = U32
        p.header.system_uid = U32
        r = p.radio_config_packet
        w = r.loRaWAN_config
        w.region, w.auth = 2, 1
        w.abp.dev_addr = b"\xff" * 4
        for k in ("nwk_s_key", "app_s_key", "f_nwk_s_int_key", "s_nwk_s_int_key"):
            setattr(w.abp, k, b"\xff" * 16)
        w.transmit_interval_min, w.tx_only_on_new_gps_fix, w.tx_power_dbm = 1440, True, -9
        c = r.loRa_config
        c.radioSpreadingFactor, c.radioBandwidth, c.radioCodingRate = 5, 2, 3
        c.tx_power_dbm, c.sync_word, c.frequency, c.rx_listen = -9, 0xFF, 928, True
        c.region, c.wake_long_range = 15, True
        r.lostMode_enabled = True
        lm = r.lostMode_config
        lm.activation_epoch, lm.transmit_interval_min, lm.tx_power_dbm = U32, 1440, -9
        r.mortality_enabled = True
        r.mortality_config.trigger_duration_hours, r.mortality_config.transmit_interval_min = 720, 1440
        self.assertEqual(len(p.SerializeToString()), 184)
        c.frequency_khz = 999999
        self.assertEqual(len(p.SerializeToString()), 188)
        self.assertLessEqual(len(p.SerializeToString()), RADIO_CHAR_CAP)

    def test_a_radio_fragment_with_a_khz_frequency_fits_the_floor(self):
        _, dl = PB2
        p = dl.DownlinkPacket(cfg_txn_id=16383)
        p.config.fragment_index, p.config.fragment_total = 31, 32
        mhz, khz = R.dr_freq_to_fields(923400)
        p.config.cfg_radio.frequency_mhz = mhz
        p.config.cfg_radio.frequency_khz = khz
        p.config.cfg_radio.direct_region = 15
        p.config.cfg_radio.bandwidth = 0
        p.config.cfg_radio.spreading_factor = 5
        self.assertEqual(len(p.SerializeToString()), 25)
        self.assertLessEqual(len(p.SerializeToString()), RX2_FLOOR)


if __name__ == "__main__":
    unittest.main()
