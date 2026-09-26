"""Tests for the ErrorFlags bit ledger (message.proto Deployment.errorFlags).

    cd reference && python3 -m unittest -v

ErrorFlags.flag is one shared word: the collar firmware sets the bits, the
server names them and the website explains them, each from its own table.
Two conditions on one bit is the failure this ledger exists to prevent
(firmware builds 306-365 sent the microphone fault on bit 8, which is
mortality). The tests pin the allocation in the message.proto comment, which
is the ledger, check that the generated nanopb header carries the same
comment, check the cross-reference from the Bluetooth beacon key state to
its bit, and check that every allocated bit still fits the uplink budget
that reference/GPS_BLOCK_V1.md reserves for the word.

Standard library only.
"""

import re
import unittest

from test_mag_cal_contract import enum_values, read, varint

# The ledger, as the firmware, server and website implement it.
# Bits 0-6: boot hardware diagnostics (bit set = fault); bit 7: diagnostics ran.
ALLOCATED = {
    8: "MORTALITY",
    9: "STORAGE",
    10: "MIC",
    11: "LORAWAN_FCNT",
    12: "BEACON_KEY_FALLBACK",
}
FIRST_FREE = 13

# ble.proto BeaconKeyState: the Bluetooth echo's view of the same condition.
BEACON_KEY_STATE_FALLBACK = 2

# reference/GPS_BLOCK_V1.md: the uplink budget never strips "errorFlags 5",
# the Deployment field 8 wrapper around ErrorFlags { flag = 1 }.
ERROR_FLAGS_BUDGET = 5


def ledger_comment(text, prefix):
    """The comment block directly above the ErrorFlags message, prefix stripped."""
    m = re.search(r"((?:%s[^\n]*\n)+)(?:message ErrorFlags\s*\{|typedef struct error_flags)"
                  % re.escape(prefix), text)
    if not m:
        raise AssertionError("no comment block above ErrorFlags")
    return [ln[len(prefix):].rstrip() for ln in m.group(1).splitlines()]


def proto_ledger():
    return ledger_comment(read("message.proto"), "//")


def named_bits(lines):
    return {int(n): name for n, name in
            re.findall(r"^ {3}bit\s+(\d+)\s+([A-Z][A-Z0-9_]*):", "\n".join(lines), re.M)}


def deployment_error_flags(flag):
    inner = varint(1 << 3 | 0) + varint(flag)                 # ErrorFlags.flag = 1
    return varint(8 << 3 | 2) + varint(len(inner)) + inner    # Deployment.errorFlags = 8


class Ledger(unittest.TestCase):

    def test_named_bits(self):
        self.assertEqual(named_bits(proto_ledger()), ALLOCATED)

    def test_hardware_bits_and_validity(self):
        text = "\n".join(proto_ledger())
        self.assertRegex(text, r"bits 0-6\s+boot hardware diagnostics")
        self.assertRegex(text, r"bit  7\s+diagnostics ran")

    def test_free_range(self):
        text = "\n".join(proto_ledger())
        self.assertIn("bits %d-31 free" % FIRST_FREE, text)
        self.assertEqual(len(re.findall(r"bits \d+-31 free", text)), 1)
        self.assertEqual(FIRST_FREE, max(ALLOCATED) + 1)

    def test_every_bit_is_named_once(self):
        # Ledger lines start in column 3; prose that mentions a bit is indented further.
        text = "\n".join(proto_ledger())
        numbers = [int(n) for n in re.findall(r"^ {3}bit\s+(\d+)\s", text, re.M)]
        self.assertEqual(sorted(numbers), [7] + sorted(ALLOCATED))
        self.assertEqual(len(numbers), len(set(numbers)))

    def test_beacon_key_fallback_is_the_echo_state(self):
        """Bit 12 and BeaconKeyState FALLBACK describe one condition, and each
        side says so, so neither table can drift on its own."""
        text = "\n".join(proto_ledger())
        self.assertIn("BEACON_KEY_STATE_FALLBACK", text)
        self.assertIn("Never set", text)
        self.assertEqual(enum_values("ble.proto", "BeaconKeyState")["BEACON_KEY_STATE_FALLBACK"],
                         BEACON_KEY_STATE_FALLBACK)
        m = re.search(r"((?:[ \t]*//[^\n]*\n)+)[ \t]*BEACON_KEY_STATE_FALLBACK\s*=", read("ble.proto"))
        self.assertIsNotNone(m)
        self.assertRegex(m.group(1), r"ErrorFlags bit 12\s*\n\s*//\s*\(BEACON_KEY_FALLBACK")


class GeneratedC(unittest.TestCase):

    def test_message_header_carries_the_ledger(self):
        # nanopb writes the proto comment as one /* ... */ block, lines
        # unprefixed; compare from the first bit line on.
        header = [ln[:-2] if ln.endswith("*/") else ln
                  for ln in ledger_comment(read("message.pb.h"), "")]
        proto = proto_ledger()
        start = next(i for i, ln in enumerate(proto) if ln.lstrip().startswith("bits 0-6"))
        hstart = next(i for i, ln in enumerate(header) if "bits 0-6" in ln)
        self.assertEqual([ln.strip() for ln in header[hstart:]],
                         [ln.strip() for ln in proto[start:]])

    def test_ble_header_cross_reference(self):
        self.assertRegex(read("ble.pb.h"),
                         r"ErrorFlags bit 12\s*\n\s*\(BEACON_KEY_FALLBACK, message\.proto\)[^\n]*\*/\s*\n"
                         r"\s*BEACON_KEY_STATE_BEACON_KEY_STATE_FALLBACK = 2")


class SizeBudget(unittest.TestCase):

    def test_every_allocated_bit_fits_the_budget(self):
        worst = (1 << FIRST_FREE) - 1                  # bits 0 .. 12 all set
        self.assertLessEqual(len(deployment_error_flags(worst)), ERROR_FLAGS_BUDGET)

    def test_budget_is_stated_where_the_uplink_budget_is(self):
        self.assertIn("errorFlags %d" % ERROR_FLAGS_BUDGET, read("reference/GPS_BLOCK_V1.md"))

    def test_bit_13_is_the_last_that_fits(self):
        """Bits up to 13 keep the word at 2 varint bytes; bit 14 needs a
        third and would grow every flagged uplink past the budget."""
        self.assertLessEqual(len(deployment_error_flags((1 << 14) - 1)), ERROR_FLAGS_BUDGET)
        self.assertGreater(len(deployment_error_flags(1 << 14)), ERROR_FLAGS_BUDGET)


if __name__ == "__main__":
    unittest.main()
