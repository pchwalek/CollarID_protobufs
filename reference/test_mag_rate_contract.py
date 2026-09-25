"""Tests for the magnetometer rate-mode wire contract (MAG-1).

    cd reference && python3 -m unittest -v

MagnetometerConfig.sample_rate_hz (ble.proto) and
ConfigMagnetometer.sample_rate_hz (downlink.proto) carry the rate mode:
0 = interval mode (sample_interval_s), else 1, 2, 4, 8 or 16 Hz. The tests
pin the numbers and types in the .proto text, check that the generated
nanopb headers, Python modules and Swift at the repository root were
regenerated from that text, and check the rule the firmware's SchedSync_Crc
relies on: a schedule that leaves the rate at 0 encodes byte for byte as one
written before the field existed, while the downlink field, being optional,
encodes an explicit 0.

Standard library only, except the generated-Python classes, which are
skipped when the protobuf runtime is missing or too old for the checked-in
modules. The .proto parser and the minimal encoder come from
test_mag_cal_contract.py.
"""

import re
import unittest

from test_mag_cal_contract import (PB2, _block, _strip_comments, encode,
                                   message_fields, read)

# The contract, as the firmware, server and client agents implement it.
RATES = (1, 2, 4, 8, 16)
LSE_HZ = 32768  # LPTIM1 kernel clock; every rate must divide it exactly
FIELD = ("uint32", 3)
BLE_FIELDS = {"enabled": ("bool", 1),
              "sample_interval_s": ("uint32", 2),
              "sample_rate_hz": FIELD}
DOWNLINK_FIELDS = dict(BLE_FIELDS)

# A MagnetometerConfig every deployed collar could have written before the
# field existed: enabled, one row a minute. What the field adds is a
# tag 3 varint (0x18) which proto3 omits at 0.
LEGACY = b"\x08\x01\x10\x3c"
RATE_TAG = b"\x18"


def raw_block(proto, kind, name):
    """The message body with its comments (the contract text)."""
    return _block(read(proto), kind, name)


def field_labels(proto, name):
    """field -> 'optional' / 'repeated' / '' as written in the .proto."""
    body = _block(_strip_comments(read(proto)), "message", name)
    rx = r"(optional\s+|repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+\s*;"
    return {f: lbl.strip() for lbl, f in re.findall(rx, body)}


def c_struct(header, name):
    m = re.search(r"typedef struct %s \{(.*?)\} %s_t;" % (name, name),
                  read(header), re.S)
    if not m:
        raise AssertionError("struct %s not in %s" % (name, header))
    return m.group(1)


def c_fieldlist(header, macro):
    m = re.search(r"#define %s\(X, a\) \\\n((?:.*\\\n)*.*)" % macro,
                  read(header))
    if not m:
        raise AssertionError("%s not in %s" % (macro, header))
    return m.group(1)


# ------------------------------------------------------------------- tests

class ProtoContract(unittest.TestCase):

    def test_ble_fields(self):
        self.assertEqual(message_fields("ble.proto", "MagnetometerConfig"),
                         BLE_FIELDS)
        # Implicit presence is the whole point: an explicit `optional` would
        # encode a 0 and move SchedSync_Crc on every legacy schedule.
        labels = field_labels("ble.proto", "MagnetometerConfig")
        self.assertEqual(labels["sample_rate_hz"], "")

    def test_downlink_fields(self):
        self.assertEqual(message_fields("downlink.proto", "ConfigMagnetometer"),
                         DOWNLINK_FIELDS)
        labels = field_labels("downlink.proto", "ConfigMagnetometer")
        self.assertEqual(set(labels.values()), {"optional"})

    def test_rates_named_in_both_contracts(self):
        for proto, name in (("ble.proto", "MagnetometerConfig"),
                            ("downlink.proto", "ConfigMagnetometer")):
            body = raw_block(proto, "message", name)
            self.assertRegex(body, r"1, 2, 4, 8 (?:and|or) 16 Hz", name)
            self.assertRegex(body, r"0 = interval mode", name)

    def test_rates_divide_the_crystal(self):
        # Why the set is closed: LPTIM1 reloads every 32768/f LSE cycles
        # (DESIGN_magnetometer_rate.md 3.1); anything else would need
        # compare stepping. Powers of two, no gaps, 16 Hz the top.
        for f in RATES:
            self.assertEqual(LSE_HZ % f, 0, f)
        self.assertEqual(RATES, tuple(1 << i for i in range(5)))


class GeneratedC(unittest.TestCase):
    """The nanopb headers are what the firmware copies; they must come from
    the .proto text above (README: nanopb_generator.py --c-style)."""

    def test_ble_header(self):
        h = read("ble.pb.h")
        self.assertRegex(h, r"#define MAGNETOMETER_CONFIG_SAMPLE_RATE_HZ_TAG\s+3\b")
        body = c_struct("ble.pb.h", "magnetometer_config")
        self.assertIn("uint32_t sample_rate_hz;", body)
        self.assertNotIn("has_sample_rate_hz", body)  # implicit presence
        fl = c_fieldlist("ble.pb.h", "MAGNETOMETER_CONFIG_FIELDLIST")
        # SINGULAR is nanopb's proto3 rule: a zero is not written, which is
        # what keeps SchedSync_Crc (pb_encode of the schedule) unchanged.
        self.assertRegex(fl, r"SINGULAR, UINT32,\s+sample_rate_hz,\s+3\)")
        # enabled + sample_interval_s + a 5-byte varint with its tag.
        self.assertRegex(h, r"#define MAGNETOMETER_CONFIG_SIZE\s+14\b")

    def test_downlink_header(self):
        h = read("downlink.pb.h")
        self.assertRegex(h, r"#define CONFIG_MAGNETOMETER_SAMPLE_RATE_HZ_TAG\s+3\b")
        body = c_struct("downlink.pb.h", "config_magnetometer")
        self.assertIn("bool has_sample_rate_hz;", body)
        self.assertIn("uint32_t sample_rate_hz;", body)
        fl = c_fieldlist("downlink.pb.h", "CONFIG_MAGNETOMETER_FIELDLIST")
        self.assertRegex(fl, r"OPTIONAL, UINT32,\s+sample_rate_hz,\s+3\)")
        self.assertRegex(h, r"#define CONFIG_MAGNETOMETER_SIZE\s+14\b")


class GeneratedSwift(unittest.TestCase):

    def test_ble_swift(self):
        s = read("ble.pb.swift")
        m = re.search(r"struct MagnetometerConfig: Sendable \{(.*?)\n\}", s, re.S)
        self.assertIsNotNone(m)
        self.assertIn("var sampleRateHz: UInt32 = 0", m.group(1))
        self.assertIn('3: .standard(proto: "sample_rate_hz")', s)
        # The same zero-omission rule as nanopb and the Python runtime.
        self.assertIn("if self.sampleRateHz != 0 {", s)


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    def _fields(self, desc):
        got = {}
        for fd in desc.fields:
            t = {fd.TYPE_BOOL: "bool", fd.TYPE_UINT32: "uint32"}[fd.type]
            got[fd.name] = (t, fd.number)
        return got

    def test_descriptors_match_proto(self):
        ble, dl = PB2
        cfg = ble.DESCRIPTOR.message_types_by_name["MagnetometerConfig"]
        self.assertEqual(self._fields(cfg), BLE_FIELDS)
        self.assertFalse(cfg.fields_by_name["sample_rate_hz"].has_presence)
        cfg = dl.DESCRIPTOR.message_types_by_name["ConfigMagnetometer"]
        self.assertEqual(self._fields(cfg), DOWNLINK_FIELDS)
        for fd in cfg.fields:
            self.assertTrue(fd.has_presence, fd.name)


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class WireRule(unittest.TestCase):
    """0 = interval mode, and it costs nothing on the wire."""

    def test_legacy_config_is_byte_identical(self):
        ble, _ = PB2
        self.assertEqual(encode([(1, 1), (2, 60)]), LEGACY)
        untouched = ble.MagnetometerConfig(enabled=True, sample_interval_s=60)
        explicit = ble.MagnetometerConfig(enabled=True, sample_interval_s=60,
                                          sample_rate_hz=0)
        self.assertEqual(untouched.SerializeToString(), LEGACY)
        self.assertEqual(explicit.SerializeToString(), LEGACY)
        # Bytes written before the field existed decode as interval mode.
        self.assertEqual(ble.MagnetometerConfig.FromString(LEGACY).sample_rate_hz, 0)

    def test_schedule_packet_hash_input_is_unchanged(self):
        """SchedSync_Crc hashes the encoded ScheduleConfigPacket. Five slots
        in interval mode encode exactly as they did before the field."""
        ble, _ = PB2

        def packet(rates):
            p = ble.ScheduleConfigPacket(engaged=True)
            for i in range(5):
                s = p.schedules.add()
                s.window.start_hour = i
                s.magnetometer.enabled = True
                s.magnetometer.sample_interval_s = 60
                if rates[i] is not None:
                    s.magnetometer.sample_rate_hz = rates[i]
            return p.SerializeToString()

        never_set = packet([None] * 5)
        zeroed = packet([0] * 5)
        self.assertEqual(never_set, zeroed)
        self.assertIn(LEGACY, never_set)
        self.assertNotIn(RATE_TAG + b"\x00", never_set)
        # A real rate is exactly one tag and one varint byte more per slot.
        for f in RATES:
            with_rate = packet([f, 0, 0, 0, 0])
            self.assertEqual(len(with_rate), len(never_set) + 2)
            self.assertIn(LEGACY + RATE_TAG + bytes([f]), with_rate)
            back = ble.ScheduleConfigPacket.FromString(with_rate)
            self.assertEqual(back.schedules[0].magnetometer.sample_rate_hz, f)
            self.assertEqual(back.schedules[1].magnetometer.sample_rate_hz, 0)

    def test_downlink_absent_leaves_explicit_zero_encodes(self):
        _, dl = PB2
        absent = dl.ConfigMagnetometer()
        self.assertFalse(absent.HasField("sample_rate_hz"))
        self.assertEqual(absent.SerializeToString(), b"")
        back_to_interval = dl.ConfigMagnetometer(sample_rate_hz=0)
        self.assertTrue(back_to_interval.HasField("sample_rate_hz"))
        self.assertEqual(back_to_interval.SerializeToString(), RATE_TAG + b"\x00")
        for f in RATES:
            self.assertEqual(dl.ConfigMagnetometer(sample_rate_hz=f).SerializeToString(),
                             RATE_TAG + bytes([f]))
        # The whole fragment as the server sends it: the "+2" of the
        # downlink.proto size note.
        full = dl.ConfigMagnetometer(enabled=True, sample_interval_s=60,
                                     sample_rate_hz=4)
        self.assertEqual(full.SerializeToString(), LEGACY + RATE_TAG + b"\x04")
        self.assertEqual(len(full.SerializeToString()), len(LEGACY) + 2)


if __name__ == "__main__":
    unittest.main()
