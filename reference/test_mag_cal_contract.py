"""Tests for the magnetometer calibration wire contract.

    cd reference && python3 -m unittest -v

CMD_MAG_CALIBRATE / CMD_MAG_CALIBRATE_ABORT (downlink.proto CommandType) and
CfgEchoPacket.mag_cal (ble.proto) are implemented by the collar firmware, the
configurator and the app from these numbers. The tests pin them in the .proto
text, check that the generated nanopb headers and Python modules at the
repository root were regenerated from that text, and check the size budget
of the Bluetooth echo that carries the report.

Standard library only, except the generated-Python class, which is skipped
when the protobuf runtime is missing or too old for the checked-in modules.
"""

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, os.pardir))
U32 = (1 << 32) - 1

# One Bluetooth read of the settings characteristic carries 182 B
# (ble.proto ScheduleConfigPacket.ble_query, ble.options slot_report).
BLE_READ_CEILING = 182

# The contract, as the firmware and client agents implement it.
COMMANDS = {"CMD_FACTORY_RESET": 18,
            "CMD_MAG_CALIBRATE": 20,
            "CMD_MAG_CALIBRATE_ABORT": 21}
ECHO_MAG_CAL = ("MagCalReport", 16)
REPORT_FIELDS = {
    "state": ("MagCalState", 1),
    "run": ("uint32", 2),
    "progress_pct": ("uint32", 3),
    "sectors_hit": ("uint32", 4),
    "verdict": ("MagCalVerdict", 5),
    "reason": ("MagCalReason", 6),
    "field_ut_x10": ("uint32", 7),
    "residual_permille": ("uint32", 8),
}
ENUMS = {
    "MagCalState": {
        "MAG_CAL_STATE_IDLE": 0, "MAG_CAL_STATE_COLLECTING": 1,
        "MAG_CAL_STATE_FITTING": 2, "MAG_CAL_STATE_DONE": 3,
        "MAG_CAL_STATE_FAILED": 4, "MAG_CAL_STATE_ABORTED": 5},
    "MagCalVerdict": {
        "MAG_CAL_VERDICT_NONE": 0, "MAG_CAL_VERDICT_GOOD": 1,
        "MAG_CAL_VERDICT_FAIR": 2, "MAG_CAL_VERDICT_RETRY": 3},
    "MagCalReason": {
        "MAG_CAL_REASON_NONE": 0, "MAG_CAL_REASON_TIMEOUT": 1,
        "MAG_CAL_REASON_NOT_ENOUGH_ROTATION": 2,
        "MAG_CAL_REASON_SENSOR_FAULT": 3,
        "MAG_CAL_REASON_FIELD_OUT_OF_RANGE": 4,
        "MAG_CAL_REASON_RESIDUAL_HIGH": 5, "MAG_CAL_REASON_STORAGE": 6},
}


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------ .proto parsing

def _strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def _block(text, kind, name):
    m = re.search(r"\b%s\s+%s\s*\{" % (kind, re.escape(name)), text)
    if not m:
        raise AssertionError("%s %s not found" % (kind, name))
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i - 1]


def enum_values(proto, name):
    body = _block(_strip_comments(read(proto)), "enum", name)
    return {k: int(v) for k, v in re.findall(r"(\w+)\s*=\s*(\d+)\s*;", body)}


def message_fields(proto, name):
    body = _block(_strip_comments(read(proto)), "message", name)
    rx = r"(?:optional\s+|repeated\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)\s*;"
    return {f: (t, int(n)) for t, f, n in re.findall(rx, body)}


# ----------------------------------------------------- minimal proto3 encoder
# Enough of the wire format to size the echo without the protobuf runtime.
# Fields are (number, value): int = varint (0 omitted, as proto3 does),
# bytes = length-delimited, None = omitted. Written in field-number order,
# as the protobuf runtime and nanopb both write these messages.

def varint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def encode(fields):
    out = bytearray()
    for num, val in sorted(fields, key=lambda f: f[0]):
        if val is None or (isinstance(val, int) and val == 0):
            continue
        if isinstance(val, (bytes, bytearray)):
            out += varint(num << 3 | 2) + varint(len(val)) + val
        else:
            out += varint(num << 3 | 0) + varint(int(val))
    return bytes(out)


def mag_cal_worst():
    """Largest MagCalReport the documented ranges allow. field_ut_x10 is
    bounded by the LIS2MDL's +-49.152 G full scale: |B| <= 4915.2 uT x
    sqrt(3) = 8514 uT, so field_ut_x10 < 2**21 (a 3-byte varint)."""
    f = message_fields("ble.proto", "MagCalReport")
    return encode([
        (f["state"][1], max(ENUMS["MagCalState"].values())),
        (f["run"][1], U32),
        (f["progress_pct"][1], 100),
        (f["sectors_hit"][1], 26),
        (f["verdict"][1], max(ENUMS["MagCalVerdict"].values())),
        (f["reason"][1], max(ENUMS["MagCalReason"].values())),
        (f["field_ut_x10"][1], (1 << 21) - 1),
        (f["residual_permille"][1], 1000),
    ])


def echo_packet(mag_cal=None, slot_report=None, bounded=True):
    """The BlePacket BLE_Send_CfgEcho builds: header epoch + system_uid,
    schedule arm holding cfg_echo only. bounded=True keeps the fields the
    firmware fills from small sets at their real maxima (ack_status and
    wipe_status are small codes, the fence masks have 4 bits, at most 5
    schedules); bounded=False puts every uint32 at 2**32-1."""
    e = message_fields("ble.proto", "CfgEchoPacket")
    small = lambda v: v if bounded else U32
    echo = encode([
        (e["txn_id"][1], U32), (e["ack_status"][1], small(7)),
        (e["missing_mask"][1], U32), (e["fence_used_mask"][1], small(0xF)),
        (e["fence_active_mask"][1], small(0xF)),
        (e["fence_fired_mask"][1], small(0xF)), (e["sched_crc"][1], U32),
        (e["slot_report"][1], slot_report), (e["echo_seq"][1], U32),
        (e["wipe_status"][1], small(5)), (e["wipe_removed"][1], U32),
        (e["schedule_count"][1], small(5)), (e["engaged"][1], 1),
        (e["mag_cal"][1], mag_cal),
    ])
    s = message_fields("ble.proto", "ScheduleConfigPacket")
    h = message_fields("common.proto", "PacketHeader")
    b = message_fields("ble.proto", "BlePacket")
    header = encode([(h["epoch"][1], U32), (h["system_uid"][1], U32)])
    sched = encode([(s["cfg_echo"][1], echo)])
    return encode([(b["header"][1], header),
                   (b["schedule_config_packet"][1], sched)])


# ------------------------------------------------------------------- tests

class ProtoContract(unittest.TestCase):

    def test_command_numbers(self):
        cmds = enum_values("downlink.proto", "CommandType")
        for name, num in COMMANDS.items():
            self.assertEqual(cmds.get(name), num, name)
        used = list(cmds.values())
        self.assertEqual(len(used), len(set(used)), "duplicate command number")

    def test_echo_field(self):
        echo = message_fields("ble.proto", "CfgEchoPacket")
        self.assertEqual(echo.get("mag_cal"), ECHO_MAG_CAL)
        nums = [n for _, n in echo.values()]
        self.assertEqual(len(nums), len(set(nums)), "duplicate echo field")

    def test_report_fields(self):
        self.assertEqual(message_fields("ble.proto", "MagCalReport"),
                         REPORT_FIELDS)

    def test_report_enums(self):
        for name, values in ENUMS.items():
            self.assertEqual(enum_values("ble.proto", name), values, name)


class GeneratedC(unittest.TestCase):
    """The nanopb headers are what the firmware copies; they must come from
    the .proto text above (README: nanopb_generator.py --c-style)."""

    def test_downlink_header(self):
        h = read("downlink.pb.h")
        for name, num in enum_values("downlink.proto", "CommandType").items():
            self.assertRegex(h, r"\bCOMMAND_TYPE_%s = %d\b" % (name, num))

    def test_ble_header(self):
        h = read("ble.pb.h")
        self.assertRegex(h, r"#define CFG_ECHO_PACKET_MAG_CAL_TAG\s+16\b")
        self.assertIn("bool has_mag_cal;", h)
        for field, (_, num) in REPORT_FIELDS.items():
            self.assertRegex(h, r"#define MAG_CAL_REPORT_%s_TAG\s+%d\b"
                             % (field.upper(), num))
        for enum, values in ENUMS.items():
            prefix = re.sub(r"(?<!^)(?=[A-Z])", "_", enum).upper()
            for value, num in values.items():
                self.assertRegex(h, r"\b%s_%s = %d\b" % (prefix, value, num))


def _load_pb2():
    # No bytecode: the repository root tracks a __pycache__ directory, and
    # running the tests must not rewrite it.
    sys.path.insert(0, ROOT)
    saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        import ble_pb2
        import downlink_pb2
        return ble_pb2, downlink_pb2
    except Exception:  # runtime missing or older than the gencode
        return None
    finally:
        sys.dont_write_bytecode = saved
        sys.path.remove(ROOT)


PB2 = _load_pb2()


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    def test_descriptors_match_proto(self):
        ble, dl = PB2
        cmd = dl.DESCRIPTOR.enum_types_by_name["CommandType"]
        for name, num in COMMANDS.items():
            self.assertEqual(cmd.values_by_name[name].number, num)
        echo = ble.DESCRIPTOR.message_types_by_name["CfgEchoPacket"]
        f = echo.fields_by_name["mag_cal"]
        self.assertEqual((f.message_type.name, f.number), ECHO_MAG_CAL)
        rep = ble.DESCRIPTOR.message_types_by_name["MagCalReport"]
        got = {}
        for fd in rep.fields:
            t = fd.enum_type.name if fd.enum_type else "uint32"
            self.assertTrue(fd.enum_type or fd.type == fd.TYPE_UINT32)
            got[fd.name] = (t, fd.number)
        self.assertEqual(got, REPORT_FIELDS)
        for name, values in ENUMS.items():
            e = ble.DESCRIPTOR.enum_types_by_name[name]
            self.assertEqual({v.name: v.number for v in e.values}, values)

    def test_encoder_agrees_with_runtime(self):
        """The stdlib encoder the budget tests use must size exactly what
        the protobuf runtime serializes."""
        ble, _ = PB2
        m = ble.MagCalReport(state=5, run=U32, progress_pct=100,
                             sectors_hit=26, verdict=3, reason=6,
                             field_ut_x10=(1 << 21) - 1,
                             residual_permille=1000)
        self.assertEqual(m.SerializeToString(), mag_cal_worst())
        p = ble.BlePacket()
        p.header.epoch = U32
        p.header.system_uid = U32
        e = p.schedule_config_packet.cfg_echo
        e.txn_id = U32; e.ack_status = 7; e.missing_mask = U32
        e.fence_used_mask = e.fence_active_mask = e.fence_fired_mask = 0xF
        e.sched_crc = U32; e.echo_seq = U32; e.wipe_status = 5
        e.wipe_removed = U32; e.schedule_count = 5; e.engaged = True
        e.mag_cal.CopyFrom(m)
        self.assertEqual(p.SerializeToString(),
                         echo_packet(mag_cal=mag_cal_worst()))


class EchoBudget(unittest.TestCase):

    def test_mag_cal_at_most_26_bytes(self):
        # ble.proto: "At most 26 B on the wire" (tag, length and body).
        field = encode([(ECHO_MAG_CAL[1], mag_cal_worst())])
        self.assertEqual(len(field), 26)

    def test_status_echo_fits_one_read(self):
        worst = echo_packet(mag_cal=mag_cal_worst())
        self.assertEqual(len(worst), 88)  # ble.options
        every_u32_max = echo_packet(mag_cal=mag_cal_worst(), bounded=False)
        self.assertLessEqual(len(every_u32_max), BLE_READ_CEILING)

    def test_report_echoes_have_no_room(self):
        # Why mag_cal stays off echoes that carry slot_report: at its
        # ble.options cap the report alone already fills the read. If this
        # ever fails, the presence rule can be relaxed.
        cap = int(re.search(r"CfgEchoPacket\.slot_report\s+max_size:(\d+)",
                            read("ble.options")).group(1))
        slot = echo_packet(slot_report=b"\0" * cap, mag_cal=mag_cal_worst())
        self.assertGreater(len(slot), BLE_READ_CEILING)


if __name__ == "__main__":
    unittest.main()
