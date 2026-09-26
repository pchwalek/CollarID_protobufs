"""Tests for the lost-mode beacon key wire contract (radio security phase E4).

    cd reference && python3 -m unittest -v

CMD_BEACON_KEY_SET / CMD_BEACON_KEY_CLEAR with DownlinkPacket.beacon_key
(downlink.proto) and CfgEchoPacket.beacon_key (ble.proto) are implemented by
the collar firmware, the server's key registry, the configurator and the app
from these numbers. The tests pin them in the .proto text and the nanopb
options, check that the generated nanopb headers, Python modules and Swift at
the repository root were regenerated from that text, check that no message
carries the key back and that the generated C cannot collide with the
firmware's beacon_frame.h, and check the size budgets of the tunnel frame
that delivers a key and of the Bluetooth echo that reports its state.

Standard library only, except the generated-Python classes, which are skipped
when the protobuf runtime is missing or too old for the checked-in modules.
The .proto parser and the minimal encoder come from test_mag_cal_contract.py.
Every key and key check value below is synthetic.
"""

import re
import unittest

from test_mag_cal_contract import (BLE_READ_CEILING, PB2, U32, encode,
                                   enum_values, mag_cal_worst, message_fields,
                                   read)
from test_mag_rate_contract import c_fieldlist, c_struct, field_labels

# ble.options: one tunnel frame (ScheduleConfigPacket.cfg_downlink).
TUNNEL_FRAME_CAP = 96

# The contract, as the firmware, server and client agents implement it.
COMMANDS = {"CMD_FACTORY_RESET": 18,
            "CMD_BEACON_KEY_SET": 19,
            "CMD_MAG_CALIBRATE": 20,
            "CMD_MAG_CALIBRATE_ABORT": 21,
            "CMD_BEACON_KEY_CLEAR": 22}
DOWNLINK_FIELD = ("BeaconKeySet", 11)
SET_FIELDS = {"slot": ("BeaconKeySlot", 1),
              "gen": ("uint32", 2),
              "key": ("bytes", 3)}
ECHO_FIELD = ("BeaconKeyReport", 15)
REPORT_FIELDS = {"state": ("BeaconKeyState", 1),
                 "gen": ("uint32", 2),
                 "kcv": ("bytes", 3),
                 "result": ("BeaconKeyResult", 4),
                 "tx_counter": ("uint32", 5)}
ENUMS = {
    "downlink.proto": {
        "BeaconKeySlot": {"BEACON_KEY_SLOT_BEACON": 0,
                          "BEACON_KEY_SLOT_COMMAND": 1}},
    "ble.proto": {
        "BeaconKeyState": {"BEACON_KEY_STATE_NONE": 0,
                           "BEACON_KEY_STATE_KEYED": 1,
                           "BEACON_KEY_STATE_FALLBACK": 2},
        "BeaconKeyResult": {"BEACON_KEY_RESULT_NONE": 0,
                            "BEACON_KEY_RESULT_APPLIED": 1,
                            "BEACON_KEY_RESULT_CLEARED": 2,
                            "BEACON_KEY_RESULT_REJECTED_GEN": 3,
                            "BEACON_KEY_RESULT_REJECTED_ARG": 4,
                            "BEACON_KEY_RESULT_STORE_ERROR": 5}},
}
KEY_LEN = 16   # AES-128, beacon/README.md
KCV_LEN = 3    # AES(key, 0^16)[0..2]
GEN_MAX = 255  # the counter's top byte

SYNTHETIC_KEY = bytes(range(KEY_LEN))
SYNTHETIC_KCV = b"\x2b\x1a\x1e"   # beacon/vectors.json kdf[0], a test master


def report_worst(bounded=True):
    """Largest BeaconKeyReport the contract allows: gen is one byte, kcv is
    three, tx_counter is any 32-bit value. bounded=False lets gen run to
    2**32-1 as well, the nanopb BEACON_KEY_REPORT_SIZE view."""
    f = message_fields("ble.proto", "BeaconKeyReport")
    return encode([
        (f["state"][1], max(ENUMS["ble.proto"]["BeaconKeyState"].values())),
        (f["gen"][1], GEN_MAX if bounded else U32),
        (f["kcv"][1], b"\xff" * KCV_LEN),
        (f["result"][1], max(ENUMS["ble.proto"]["BeaconKeyResult"].values())),
        (f["tx_counter"][1], U32),
    ])


def echo_packet(beacon_key=None, mag_cal=None, slot_report=None, bounded=True):
    """test_mag_cal_contract.echo_packet with the beacon_key report added:
    the BlePacket BLE_Send_CfgEcho builds, header epoch + system_uid,
    schedule arm holding cfg_echo only."""
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
        (e["beacon_key"][1], beacon_key),
        (e["mag_cal"][1], mag_cal),
    ])
    s = message_fields("ble.proto", "ScheduleConfigPacket")
    h = message_fields("common.proto", "PacketHeader")
    b = message_fields("ble.proto", "BlePacket")
    header = encode([(h["epoch"][1], U32), (h["system_uid"][1], U32)])
    sched = encode([(s["cfg_echo"][1], echo)])
    return encode([(b["header"][1], header),
                   (b["schedule_config_packet"][1], sched)])


def key_set_frame(slot=1, gen=GEN_MAX, key=SYNTHETIC_KEY, txn=True):
    """The largest CMD_BEACON_KEY_SET DownlinkPacket a client writes into
    the tunnel: epoch, command, a transaction id, and the key set."""
    d = message_fields("downlink.proto", "DownlinkPacket")
    k = message_fields("downlink.proto", "BeaconKeySet")
    key_set = encode([(k["slot"][1], slot), (k["gen"][1], gen),
                      (k["key"][1], key)])
    return encode([(d["epoch"][1], U32), (d["command"][1], COMMANDS["CMD_BEACON_KEY_SET"]),
                   (d["cfg_txn_id"][1], U32 if txn else 0),
                   (d["beacon_key"][1], key_set)])


# ------------------------------------------------------------------- tests

class ProtoContract(unittest.TestCase):

    def test_command_numbers(self):
        cmds = enum_values("downlink.proto", "CommandType")
        for name, num in COMMANDS.items():
            self.assertEqual(cmds.get(name), num, name)
        used = list(cmds.values())
        self.assertEqual(len(used), len(set(used)), "duplicate command number")
        # 19 and 15 were "held for the planned lost-mode beacon key"; the
        # hold notes must be gone with the numbers taken.
        for proto in ("downlink.proto", "ble.proto"):
            self.assertNotIn("held for the planned", read(proto), proto)

    def test_downlink_field(self):
        dl = message_fields("downlink.proto", "DownlinkPacket")
        self.assertEqual(dl.get("beacon_key"), DOWNLINK_FIELD)
        self.assertEqual(field_labels("downlink.proto", "DownlinkPacket")["beacon_key"],
                         "optional")
        nums = [n for _, n in dl.values()]
        self.assertEqual(len(nums), len(set(nums)), "duplicate downlink field")

    def test_key_set_fields(self):
        self.assertEqual(message_fields("downlink.proto", "BeaconKeySet"),
                         SET_FIELDS)

    def test_echo_field(self):
        echo = message_fields("ble.proto", "CfgEchoPacket")
        self.assertEqual(echo.get("beacon_key"), ECHO_FIELD)
        nums = [n for _, n in echo.values()]
        self.assertEqual(len(nums), len(set(nums)), "duplicate echo field")

    def test_report_fields(self):
        self.assertEqual(message_fields("ble.proto", "BeaconKeyReport"),
                         REPORT_FIELDS)

    def test_enums(self):
        for proto, enums in ENUMS.items():
            for name, values in enums.items():
                self.assertEqual(enum_values(proto, name), values, name)

    def test_report_never_carries_the_key(self):
        # The only bytes field of the report is the 3-byte check value, and
        # the key set is referenced from the downlink envelope alone: no
        # uplink or Bluetooth message can echo key material.
        rep = message_fields("ble.proto", "BeaconKeyReport")
        self.assertEqual([f for f, (t, _) in rep.items() if t == "bytes"], ["kcv"])
        for proto in ("ble.proto", "common.proto", "message.proto"):
            self.assertNotIn("BeaconKeySet", read(proto), proto)
        refs = re.findall(r"BeaconKeySet\s+\w+\s*=", read("downlink.proto"))
        self.assertEqual(len(refs), 1)

    def test_options(self):
        # The key is exactly 16 bytes and fixed (a wrong length fails the
        # decode); the check value is at most 3 and NOT fixed, so an unkeyed
        # report encodes nothing for it.
        self.assertRegex(read("downlink.options"),
                         r"(?m)^BeaconKeySet\.key\s+max_size:16 fixed_length:true\s*$")
        self.assertRegex(read("ble.options"),
                         r"(?m)^BeaconKeyReport\.kcv\s+max_size:3\s*$")
        self.assertNotRegex(read("ble.options"), r"BeaconKeyReport\.kcv.*fixed_length")
        self.assertRegex(read("ble.options"),
                         r"cfg_downlink\s+max_size:%d\b" % TUNNEL_FRAME_CAP)

    def test_gate_and_carrier_rules_are_written_down(self):
        dl, ble = read("downlink.proto"), read("ble.proto")
        self.assertRegex(dl, r"CMD_BEACON_KEY_SET\s+= 19")
        self.assertRegex(dl, r"CMD_BEACON_KEY_CLEAR\s+= 22")
        # BLE tunnel only, like CMD_FACTORY_RESET: said next to the command.
        self.assertIn("Accepted ONLY over the BLE config tunnel, like CMD_FACTORY_RESET",
                      dl.split("CMD_BEACON_KEY_SET      = 19")[0])
        for text in (dl, ble):
            self.assertIn("firmware main build TBD", text)


class GeneratedC(unittest.TestCase):
    """The nanopb headers are what the firmware copies; they must come from
    the .proto text above (README: nanopb_generator.py --c-style)."""

    def test_downlink_header(self):
        h = read("downlink.pb.h")
        for name, num in enum_values("downlink.proto", "CommandType").items():
            self.assertRegex(h, r"\bCOMMAND_TYPE_%s = %d\b" % (name, num))
        self.assertRegex(h, r"#define DOWNLINK_PACKET_BEACON_KEY_TAG\s+11\b")
        self.assertIn("bool has_beacon_key;", c_struct("downlink.pb.h", "downlink_packet"))
        body = c_struct("downlink.pb.h", "beacon_key_set")
        self.assertIn("beacon_key_slot_t slot;", body)
        self.assertIn("uint32_t gen;", body)
        self.assertIn("pb_byte_t key[%d];" % KEY_LEN, body)
        for field, (_, num) in SET_FIELDS.items():
            self.assertRegex(h, r"#define BEACON_KEY_SET_%s_TAG\s+%d\b"
                             % (field.upper(), num))
        fl = c_fieldlist("downlink.pb.h", "BEACON_KEY_SET_FIELDLIST")
        self.assertRegex(fl, r"SINGULAR, FIXED_LENGTH_BYTES, key,\s+3\)")
        fl = c_fieldlist("downlink.pb.h", "DOWNLINK_PACKET_FIELDLIST")
        self.assertRegex(fl, r"OPTIONAL, MESSAGE,\s+beacon_key,\s+11\)")
        for value, num in ENUMS["downlink.proto"]["BeaconKeySlot"].items():
            self.assertRegex(h, r"\bBEACON_KEY_SLOT_%s = %d\b" % (value, num))
        # slot + gen + 16 fixed bytes with their tags.
        self.assertRegex(h, r"#define BEACON_KEY_SET_SIZE\s+26\b")

    def test_downlink_header_does_not_collide_with_beacon_frame_h(self):
        # The firmware's Core/Inc/beacon_frame.h (E1) already defines
        # beacon_key_purpose_t and BEACON_KEY_{LEN,BEACON,COMMAND}; the E4
        # handler includes both headers. The enum is BeaconKeySlot for that
        # reason: its C names must stay disjoint.
        h = read("downlink.pb.h")
        self.assertNotIn("beacon_key_purpose_t;", h)
        for macro in ("BEACON_KEY_LEN", "BEACON_KEY_BEACON", "BEACON_KEY_COMMAND",
                      "BEACON_KCV_LEN"):
            self.assertNotRegex(h, r"#define %s\b" % macro)
            self.assertNotRegex(h, r"\b%s = \d" % macro)

    def test_ble_header(self):
        h = read("ble.pb.h")
        self.assertRegex(h, r"#define CFG_ECHO_PACKET_BEACON_KEY_TAG\s+15\b")
        self.assertIn("bool has_beacon_key;", c_struct("ble.pb.h", "cfg_echo_packet"))
        self.assertIn("typedef PB_BYTES_ARRAY_T(%d) beacon_key_report_kcv_t;" % KCV_LEN, h)
        body = c_struct("ble.pb.h", "beacon_key_report")
        self.assertIn("beacon_key_report_kcv_t kcv;", body)
        self.assertIn("uint32_t tx_counter;", body)
        for field, (_, num) in REPORT_FIELDS.items():
            self.assertRegex(h, r"#define BEACON_KEY_REPORT_%s_TAG\s+%d\b"
                             % (field.upper(), num))
        for enum, values in ENUMS["ble.proto"].items():
            prefix = re.sub(r"(?<!^)(?=[A-Z])", "_", enum).upper()
            for value, num in values.items():
                self.assertRegex(h, r"\b%s_%s = %d\b" % (prefix, value, num))
        # Every varint at its 5-byte maximum plus the 3-byte check value.
        self.assertRegex(h, r"#define BEACON_KEY_REPORT_SIZE\s+21\b")
        self.assertEqual(len(report_worst(bounded=False)), 21)


class GeneratedSwift(unittest.TestCase):

    def test_ble_swift(self):
        s = read("ble.pb.swift")
        self.assertIn("struct BeaconKeyReport: @unchecked Sendable {", s)
        self.assertIn("var hasBeaconKey: Bool", s)
        self.assertIn('15: .standard(proto: "beacon_key")', s)
        self.assertIn("var kcv: Data = Data()", s)
        self.assertIn("var txCounter: UInt32 = 0", s)
        self.assertIn("enum BeaconKeyState: SwiftProtobuf.Enum", s)
        self.assertIn("enum BeaconKeyResult: SwiftProtobuf.Enum", s)


@unittest.skipIf(PB2 is None, "protobuf runtime unavailable")
class GeneratedPython(unittest.TestCase):

    @staticmethod
    def _fields(desc):
        got = {}
        for fd in desc.fields:
            if fd.enum_type:
                t = fd.enum_type.name
            elif fd.message_type:
                t = fd.message_type.name
            else:
                t = {fd.TYPE_UINT32: "uint32", fd.TYPE_BYTES: "bytes"}[fd.type]
            got[fd.name] = (t, fd.number)
        return got

    def test_descriptors_match_proto(self):
        ble, dl = PB2
        cmd = dl.DESCRIPTOR.enum_types_by_name["CommandType"]
        for name, num in COMMANDS.items():
            self.assertEqual(cmd.values_by_name[name].number, num)
        pkt = dl.DESCRIPTOR.message_types_by_name["DownlinkPacket"]
        f = pkt.fields_by_name["beacon_key"]
        self.assertEqual((f.message_type.name, f.number), DOWNLINK_FIELD)
        self.assertTrue(f.has_presence)
        self.assertEqual(self._fields(dl.DESCRIPTOR.message_types_by_name["BeaconKeySet"]),
                         SET_FIELDS)
        echo = ble.DESCRIPTOR.message_types_by_name["CfgEchoPacket"]
        f = echo.fields_by_name["beacon_key"]
        self.assertEqual((f.message_type.name, f.number), ECHO_FIELD)
        self.assertEqual(self._fields(ble.DESCRIPTOR.message_types_by_name["BeaconKeyReport"]),
                         REPORT_FIELDS)
        for proto, enums in ENUMS.items():
            mod = dl if proto == "downlink.proto" else ble
            for name, values in enums.items():
                e = mod.DESCRIPTOR.enum_types_by_name[name]
                self.assertEqual({v.name: v.number for v in e.values}, values)

    def test_key_set_reachable_only_from_the_downlink_envelope(self):
        """Walk every message reachable from the two wrappers clients and
        collars exchange: BlePacket and MessagePacket never embed the key
        set, so nothing an unbonded central or a gateway reads can hold a
        key. DownlinkPacket does, once."""
        ble, dl = PB2
        # No bytecode: the repository root tracks a __pycache__ directory
        # (test_mag_cal_contract._load_pb2 has the same rule).
        import sys
        sys.path.insert(0, __import__("test_mag_cal_contract").ROOT)
        saved, sys.dont_write_bytecode = sys.dont_write_bytecode, True
        try:
            import message_pb2
        finally:
            sys.dont_write_bytecode = saved
            sys.path.pop(0)

        def reachable(desc):
            seen, todo = set(), [desc]
            while todo:
                d = todo.pop()
                if d.full_name in seen:
                    continue
                seen.add(d.full_name)
                todo += [fd.message_type for fd in d.fields if fd.message_type]
            return seen

        for wrapper in (ble.DESCRIPTOR.message_types_by_name["BlePacket"],
                        message_pb2.DESCRIPTOR.message_types_by_name["MessagePacket"]):
            self.assertNotIn("BeaconKeySet", reachable(wrapper), wrapper.name)
        self.assertIn("BeaconKeySet",
                      reachable(dl.DESCRIPTOR.message_types_by_name["DownlinkPacket"]))

    def test_encoder_agrees_with_runtime(self):
        """The stdlib encoder the budget tests use must size exactly what
        the protobuf runtime serializes."""
        ble, dl = PB2
        r = ble.BeaconKeyReport(state=2, gen=GEN_MAX, kcv=b"\xff" * KCV_LEN,
                                result=5, tx_counter=U32)
        self.assertEqual(r.SerializeToString(), report_worst())
        p = ble.BlePacket()
        p.header.epoch = U32
        p.header.system_uid = U32
        e = p.schedule_config_packet.cfg_echo
        e.txn_id = U32; e.ack_status = 7; e.missing_mask = U32
        e.fence_used_mask = e.fence_active_mask = e.fence_fired_mask = 0xF
        e.sched_crc = U32; e.echo_seq = U32; e.wipe_status = 5
        e.wipe_removed = U32; e.schedule_count = 5; e.engaged = True
        e.beacon_key.CopyFrom(r)
        e.mag_cal.CopyFrom(ble.MagCalReport(
            state=5, run=U32, progress_pct=100, sectors_hit=26, verdict=3,
            reason=6, field_ut_x10=(1 << 21) - 1, residual_permille=1000))
        self.assertEqual(p.SerializeToString(),
                         echo_packet(beacon_key=report_worst(), mag_cal=mag_cal_worst()))
        frame = dl.DownlinkPacket(epoch=U32, command=19, cfg_txn_id=U32)
        frame.beacon_key.slot = 1
        frame.beacon_key.gen = GEN_MAX
        frame.beacon_key.key = SYNTHETIC_KEY
        self.assertEqual(frame.SerializeToString(), key_set_frame())

    def test_unkeyed_report_is_present_and_empty(self):
        """"No key" (present, state NONE) and "not supported" (absent) must
        differ on the wire: an empty report is tag 15 with length 0."""
        ble, _ = PB2
        p = ble.BlePacket()
        e = p.schedule_config_packet.cfg_echo
        self.assertFalse(e.HasField("beacon_key"))
        e.beacon_key.SetInParent()
        self.assertTrue(e.HasField("beacon_key"))
        self.assertEqual(e.SerializeToString(), encode([(ECHO_FIELD[1], b"")]))
        self.assertEqual(encode([(ECHO_FIELD[1], b"")]), b"\x7a\x00")
        back = ble.BlePacket.FromString(p.SerializeToString())
        r = back.schedule_config_packet.cfg_echo.beacon_key
        self.assertTrue(back.schedule_config_packet.cfg_echo.HasField("beacon_key"))
        self.assertEqual((r.state, r.gen, r.kcv, r.result, r.tx_counter),
                         (0, 0, b"", 0, 0))

    def test_report_round_trip(self):
        ble, _ = PB2
        r = ble.BeaconKeyReport(state=1, gen=3, kcv=SYNTHETIC_KCV, result=1,
                                tx_counter=(3 << 24) | 0x000041)
        back = ble.BeaconKeyReport.FromString(r.SerializeToString())
        self.assertEqual(back, r)
        self.assertEqual(back.tx_counter >> 24, back.gen)
        self.assertEqual(len(back.kcv), KCV_LEN)

    def test_clear_frame_is_two_bytes(self):
        _, dl = PB2
        clear = dl.DownlinkPacket(command=COMMANDS["CMD_BEACON_KEY_CLEAR"])
        self.assertEqual(clear.SerializeToString(), b"\x10\x16")


class SizeBudget(unittest.TestCase):

    def test_key_set_fits_the_tunnel_frame(self):
        # downlink.proto: "at most 25 B inside the tunnel frame" for the key
        # set with its tag and length; the whole frame, with epoch and a
        # transaction id, is well inside one cfg_downlink write.
        k = message_fields("downlink.proto", "BeaconKeySet")
        key_set = encode([(k["slot"][1], 1), (k["gen"][1], GEN_MAX),
                          (k["key"][1], SYNTHETIC_KEY)])
        self.assertEqual(len(encode([(DOWNLINK_FIELD[1], key_set)])), 25)
        self.assertEqual(len(key_set_frame()), 39)
        self.assertLessEqual(len(key_set_frame()), TUNNEL_FRAME_CAP)

    def test_report_at_most_20_bytes(self):
        # ble.proto: "At most 20 B on the wire" (tag, length and body).
        field = encode([(ECHO_FIELD[1], report_worst())])
        self.assertEqual(len(field), 20)

    def test_status_echo_fits_one_read(self):
        worst = echo_packet(beacon_key=report_worst(), mag_cal=mag_cal_worst())
        self.assertEqual(len(worst), 108)  # ble.options
        every_u32_max = echo_packet(beacon_key=report_worst(bounded=False),
                                    mag_cal=mag_cal_worst(), bounded=False)
        self.assertLessEqual(len(every_u32_max), BLE_READ_CEILING)

    def test_report_echoes_have_no_room(self):
        # Why beacon_key stays off echoes that carry slot_report, like
        # mag_cal: at its ble.options cap the slot report alone already fills
        # the read. If this ever fails, the presence rule can be relaxed.
        cap = int(re.search(r"CfgEchoPacket\.slot_report\s+max_size:(\d+)",
                            read("ble.options")).group(1))
        slot = echo_packet(slot_report=b"\0" * cap, beacon_key=report_worst(),
                           mag_cal=mag_cal_worst())
        self.assertGreater(len(slot), BLE_READ_CEILING)


if __name__ == "__main__":
    unittest.main()
