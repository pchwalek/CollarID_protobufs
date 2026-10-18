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
                            ("CB_UUID_OTAREBOOT_CHAR", "ota_reboot_char")):
            m = re.search(r"#define %s\s+\"([^\"]+)\"" % define, text)
            self.assertTrue(m and m.group(1) == g[key], define)
        num = lambda name: int(re.search(r"#define %s\s+(0x[0-9A-Fa-f]+|\d+)u" % name, text).group(1), 0)
        self.assertEqual(num("CB_GATT_CAPS_LEN"), R.SPEC["caps"]["length"])
        self.assertEqual(num("CB_GATT_CAPS_FORMAT"), R.SPEC["caps"]["format_build"])
        self.assertEqual(num("CB_GATT_CAPS_BUILD_OFFSET"), R.SPEC["caps"]["build_offset"])
        self.assertEqual(num("CB_GATT_CAPS_FAMILY_WB5M"), R.SPEC["caps"]["families"]["wb5m"])
        self.assertEqual(num("CB_GATT_CAPS_FAMILY_NRF54L15"), R.SPEC["caps"]["families"]["nrf54l15"])


if __name__ == "__main__":
    unittest.main()
