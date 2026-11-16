"""Tests for the contracts themselves (the repos' own tests check their code against them).

    cd contracts && python3 -m unittest -v test_contracts

Standard library only.
"""

import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "reference"))
import generate  # noqa: E402
import make_vectors  # noqa: E402
import reference as R  # noqa: E402


class Fresh(unittest.TestCase):
    def test_generated_files_are_current(self):
        for name, text in generate.render().items():
            with open(os.path.join(generate.OUT, name)) as fh:
                self.assertEqual(fh.read(), text, f"{name} is stale: run contracts/generate.py")

    def test_vectors_are_current(self):
        with open(make_vectors.OUT) as fh:
            self.assertEqual(fh.read(), make_vectors.render(), "run contracts/make_vectors.py")

    def test_every_generated_file_names_the_spec_hash(self):
        h = generate.sha256(generate.load())
        for name, text in generate.render().items():
            self.assertIn(h, text, name)


class Ledger(unittest.TestCase):
    """The ErrorFlags bits here are the ledger in message.proto (reference/test_error_flags_contract.py)."""

    def test_allocated_bits_match_the_proto_ledger(self):
        from test_error_flags_contract import ALLOCATED, FIRST_FREE
        bits = {b["bit"]: b["key"] for b in R.SPEC["error_flags"]["bits"]}
        for bit, name in ALLOCATED.items():
            self.assertEqual(bits.get(bit, "").upper(), name, f"bit {bit}")
        self.assertEqual(R.SPEC["error_flags"]["first_free"], FIRST_FREE)

    def test_bits_0_to_7_are_the_boot_diagnostics(self):
        bits = {b["bit"]: b["key"] for b in R.SPEC["error_flags"]["bits"]}
        self.assertEqual([bits[i] for i in range(8)],
                         ["accelerometer", "magnetometer", "light", "environment", "gps", "particulate",
                          "lora", "diagnostics_ran"])

    def test_one_key_per_bit(self):
        keys = [b["key"] for b in R.SPEC["error_flags"]["bits"]]
        bits = [b["bit"] for b in R.SPEC["error_flags"]["bits"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(bits, list(range(len(bits))))


class Reference(unittest.TestCase):
    def test_special_mode_round_trip(self):
        for c in (1, 2, 5, 127, 128, 300, 0x4D5400B9):
            self.assertEqual(R.decode_special_mode(R.encode_special_mode(c)), c)

    def test_crc_check_value(self):
        self.assertEqual(R.crc32(b"123456789"), 0xCBF43926)

    def test_padding_lands_on_a_batch(self):
        for n in (1, 300, 928, 960, 4096):
            for p in (20, 96, 182):
                self.assertEqual((32 + len(R.pad_to_batches(bytes(n), p))) % (10 * p), 0)

    def test_caps_round_trip(self):
        c = R.parse_caps(R.caps_bytes(4, 7, 1, 157))
        self.assertEqual((c["fmt"], c["family"], c["build"], c["kind"]), (4, 1, 157, "wb5m"))
        self.assertEqual(R.SPEC["caps"]["length"], len(R.caps_bytes(4, 7, 1, 1)))

    def test_the_spec_matches_the_radio_contract_header(self):
        """CollarID_BLE common/collar_bus.h, when it is checked out beside this repo."""
        path = os.path.join(os.path.dirname(ROOT), "CollarID_BLE", "common", "collar_bus.h")
        if not os.path.exists(path):
            self.skipTest("CollarID_BLE not beside this repo")
        text = open(path).read()
        g = R.SPEC["gatt"]
        for define, key in (("CB_UUID_SERVICE", "service"), ("CB_UUID_UPDATE_CHAR", "update_char"),
                            ("CB_UUID_STATUS_CHAR", "status_char"), ("CB_UUID_CAPS_CHAR", "caps_char"),
                            ("CB_UUID_LOCALDEV_CHAR", "localdev_char"), ("CB_UUID_RADIO_CHAR", "radio_char"),
                            ("CB_UUID_OTAREBOOT_CHAR", "ota_reboot_char"),
                            # the file characteristic (CIDB, ../bulk/README.md), 2026-11-16
                            ("CB_UUID_BULK_CHAR", "bulk_char")):
            m = re.search(r"#define %s\s+\"([^\"]+)\"" % define, text)
            self.assertTrue(m and m.group(1) == g[key], define)
        num = lambda name: int(re.search(r"#define %s\s+(0x[0-9A-Fa-f]+|\d+)u" % name, text).group(1), 0)
        self.assertEqual(num("CB_GATT_CAPS_LEN"), R.SPEC["caps"]["length"])
        self.assertEqual(num("CB_GATT_CAPS_FORMAT"), R.SPEC["caps"]["format_build"])
        self.assertEqual(num("CB_GATT_CAPS_BUILD_OFFSET"), R.SPEC["caps"]["build_offset"])
        self.assertEqual(num("CB_GATT_CAPS_FAMILY_WB5M"), R.SPEC["caps"]["families"]["wb5m"])
        self.assertEqual(num("CB_GATT_CAPS_FAMILY_NRF54L15"), R.SPEC["caps"]["families"]["nrf54l15"])


class BatteryThresholds(unittest.TestCase):
    """Low-battery hibernation (2026-11-12): the defaults are what every collar
    ran before the setting, the CSV reading always lands on a valid pair, and
    the bounds leave room for the gap."""

    def test_the_defaults_are_the_old_constants_and_valid(self):
        B = R.SPEC["battery_thresholds"]
        self.assertEqual((B["hibernate_default"], B["resume_default"]), (10, 20))
        self.assertTrue(R.battery_thresholds_valid(B["hibernate_default"], B["resume_default"]))
        self.assertEqual(R.battery_thresholds_from_csv(None, None), [10, 20])

    def test_every_hibernate_level_has_a_valid_resume(self):
        B = R.SPEC["battery_thresholds"]
        self.assertGreaterEqual(B["resume_max"], B["hibernate_max"] + B["min_gap"])
        self.assertLessEqual(B["resume_min"], B["hibernate_min"] + B["min_gap"])

    def test_the_csv_reading_is_always_valid(self):
        texts = [None, "", "x", "-100", "0", "1", "4", "5", "9", "10", "39", "40", "41", "59", "60", "61", "99999"]
        for h in texts:
            for r in texts:
                pair = R.battery_thresholds_from_csv(h, r)
                self.assertTrue(R.battery_thresholds_valid(*pair), (h, r, pair))

    def test_a_valid_pair_reads_back_unchanged(self):
        B = R.SPEC["battery_thresholds"]
        for h in range(B["hibernate_min"], B["hibernate_max"] + 1):
            for r in range(B["resume_min"], B["resume_max"] + 1):
                if R.battery_thresholds_valid(h, r):
                    self.assertEqual(R.battery_thresholds_from_csv(str(h), str(r)), [h, r])

    def test_the_csv_keys_follow_battery_protection(self):
        g = R.SPEC["config_csv"]["keys"]["global"]
        i = g.index("battery_protection_min_temp_c")
        self.assertEqual(g[i + 1:i + 3], ["battery_hibernate_pct", "battery_resume_pct"])


class LoRaWake(unittest.TestCase):
    """LoRa wake (2026-11-13): three CONFIG.CSV keys. The region and the
    long-range setting follow the direct radio's other global keys; the
    listening interval closes each schedule's rows, after its direct-radio
    send interval. Unconditional: every writer emits all three."""

    def test_the_global_keys_follow_the_direct_radio(self):
        g = R.SPEC["config_csv"]["keys"]["global"]
        i = g.index("lora_rx_listen")
        self.assertEqual(g[i + 1:i + 3], ["lora_region", "lora_wake_long_range"])
        self.assertEqual(g[i + 3], "lost_mode_enabled")
        self.assertEqual(len(g), len(set(g)))

    def test_the_schedule_key_is_the_last_row(self):
        sched = R.SPEC["config_csv"]["keys"]["schedule"]
        self.assertEqual(sched[-2:], ["lora_send_interval_min", "lora_wake_interval_s"])
        self.assertEqual(len(sched), len(set(sched)))

    def test_they_are_unconditional_and_every_writer_s(self):
        cfg = R.SPEC["config_csv"]
        for key in ("lora_region", "lora_wake_long_range", "lora_wake_interval_s"):
            self.assertNotIn(key, cfg["conditional"])
            self.assertNotIn(key, cfg["firmware_only"])

    def test_the_names_are_the_proto_s(self):
        """The schedule key is the proto field's name; the global keys take
        the direct radio's `lora_` prefix as its other keys do."""
        root = os.path.dirname(HERE)
        with open(os.path.join(root, "ble.proto")) as fh:
            ble = fh.read()
        self.assertRegex(ble, r"uint32 lora_wake_interval_s\s+= 13;")
        self.assertRegex(ble, r"DirectRegion region\s+= 8;")
        self.assertRegex(ble, r"bool wake_long_range\s+= 9;")
        for key in ("lora_region (0..3)", "lora_wake_long_range (0/1)"):
            self.assertIn("CONFIG.CSV key " + key, re.sub(r"\s*//\s*", " ", ble))

    def test_the_generated_header_lists_them(self):
        with open(os.path.join(generate.OUT, "collarid_contracts.h")) as fh:
            h = fh.read()
        for key in ("lora_region", "lora_wake_long_range", "lora_wake_interval_s"):
            self.assertIn('X("%s")' % key, h)
        g, sched = (R.SPEC["config_csv"]["keys"][k] for k in ("global", "schedule"))
        self.assertIn("#define CID_CONFIG_CSV_GLOBAL_COUNT %du" % len(g), h)
        self.assertIn("#define CID_CONFIG_CSV_SCHEDULE_COUNT %du" % len(sched), h)
        self.assertEqual((len(g), len(sched)), (44, 41))


if __name__ == "__main__":
    unittest.main()
