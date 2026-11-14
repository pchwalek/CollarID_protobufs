#!/usr/bin/env python3
"""Tests for the lost-mode beacon reference codec (beacon_v2.py) and the
frozen vectors (vectors.json).

    cd beacon && python3 -m unittest -v

Standard library only. When the `cryptography` package is importable the
codec is also checked against its AESCCM and CMAC (an independent
implementation); otherwise those cases are skipped, not failed.
"""

import contextlib
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import beacon_v2 as b  # noqa: E402
import make_vectors as mv  # noqa: E402

with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from cryptography.hazmat.primitives import cmac as _cmac
    from cryptography.hazmat.primitives.ciphers import algorithms as _alg
    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


def hx(s):
    return bytes.fromhex(s)


# ------------------------------------------------------------- primitives

class TestPrimitives(unittest.TestCase):
    def test_fips197_c1(self):
        for v in VEC["aes128"]:
            self.assertEqual(b.AES128(hx(v["key"])).encrypt_block(hx(v["pt"])).hex(), v["ct"], v["name"])

    def test_sbox_is_the_aes_sbox(self):
        self.assertEqual(b.SBOX[0x00], 0x63)
        self.assertEqual(b.SBOX[0x01], 0x7C)
        self.assertEqual(b.SBOX[0x53], 0xED)
        self.assertEqual(b.SBOX[0xFF], 0x16)
        self.assertEqual(sorted(b.SBOX), list(range(256)))   # a permutation

    def test_rfc4493_examples(self):
        self.assertEqual(len(VEC["cmac"]), 4)
        for v in VEC["cmac"]:
            self.assertEqual(b.cmac(hx(v["key"]), hx(v["msg"])).hex(), v["mac"], v["name"])

    def test_rfc3610_packet_vectors_seal_and_open(self):
        self.assertEqual(len(VEC["ccm"]), 24)
        m8 = 0
        for v in VEC["ccm"]:
            ct, tag = b.ccm_seal(hx(v["key"]), hx(v["nonce"]), hx(v["aad"]), hx(v["pt"]), v["tag_len"])
            self.assertEqual((ct.hex(), tag.hex()), (v["ct"], v["tag"]), v["name"])
            pt = b.ccm_open(hx(v["key"]), hx(v["nonce"]), hx(v["aad"]), ct, tag, v["tag_len"])
            self.assertEqual(pt.hex(), v["pt"], v["name"])
            m8 += v["tag_len"] == 8
        self.assertEqual(m8, 12)   # vectors 1-6 and 13-18 are the M=8 sets

    def test_rfc3610_open_rejects(self):
        for v in VEC["ccm"]:
            key, nonce, aad, ct, tag = hx(v["key"]), hx(v["nonce"]), hx(v["aad"]), hx(v["ct"]), hx(v["tag"])
            bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
            with self.assertRaises(b.AuthError):
                b.ccm_open(key, nonce, aad, ct, bad_tag, v["tag_len"])
            bad_aad = bytes([aad[0] ^ 0x80]) + aad[1:]
            with self.assertRaises(b.AuthError):
                b.ccm_open(key, nonce, bad_aad, ct, tag, v["tag_len"])
            bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
            with self.assertRaises(b.AuthError):
                b.ccm_open(key, nonce, aad, bad_ct, tag, v["tag_len"])
            with self.assertRaises(b.AuthError):
                b.ccm_open(key, nonce, aad, ct, tag[:-1], v["tag_len"])

    def test_ccm_parameter_checks(self):
        key, nonce = bytes(16), bytes(13)
        for bad in (0, 1, 2, 3, 5, 7, 9, 17):
            with self.assertRaises(ValueError):
                b.ccm_seal(key, nonce, b"", b"x", bad)
        with self.assertRaises(ValueError):
            b.ccm_seal(key, bytes(12), b"", b"x", 8)
        with self.assertRaises(ValueError):
            b.AES128(bytes(15))
        # AAD-only and no-AAD forms round-trip
        ct, tag = b.ccm_seal(key, nonce, b"aad", b"", 8)
        self.assertEqual(ct, b"")
        self.assertEqual(b.ccm_open(key, nonce, b"aad", b"", tag, 8), b"")
        ct, tag = b.ccm_seal(key, nonce, b"", b"payload", 8)
        self.assertEqual(b.ccm_open(key, nonce, b"", ct, tag, 8), b"payload")

    def test_ccm_block_flags_for_the_beacon_shape(self):
        # 9 B AAD, 13 B body, M=8, L=2: B_0 flags 0x59, one AAD block, and
        # the keystream A_i flags 0x01 (docs: 5 AES block operations).
        blocks = b._ccm_blocks(bytes(13), bytes(9), 13, 8)
        self.assertEqual(len(blocks), 32)
        self.assertEqual(blocks[0], 0x59)
        self.assertEqual(blocks[14:16], (13).to_bytes(2, "big"))
        self.assertEqual(blocks[16:18], (9).to_bytes(2, "big"))


# -------------------------------------------------------------------- keys

class TestKdf(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(len(VEC["kdf"]), 8)
        for v in VEC["kdf"]:
            inp = b.kdf_input(v["purpose"], v["uid"], v["gen"])
            self.assertEqual(inp.hex(), v["input"], v["name"])
            self.assertEqual(len(inp), 17)
            self.assertEqual(inp[:12], v["label"].encode("ascii"))
            key = b.kdf(hx(v["master"]), v["purpose"], v["uid"], v["gen"])
            self.assertEqual(key.hex(), v["dev_key"], v["name"])
            self.assertEqual(b.kcv(key).hex(), v["kcv"], v["name"])

    def test_domain_separation(self):
        m = hx(mv.MASTER_BEACON_A)
        base = b.kdf(m, "beacon", mv.UID_TEST, 1)
        self.assertNotEqual(base, b.kdf(m, "command", mv.UID_TEST, 1))          # label
        self.assertNotEqual(base, b.kdf(m, "beacon", mv.UID_TEST, 2))           # generation
        self.assertNotEqual(base, b.kdf(m, "beacon", mv.UID_TEST ^ 1, 1))       # uid
        self.assertNotEqual(base, b.kdf(hx(mv.MASTER_BEACON_B), "beacon", mv.UID_TEST, 1))   # master
        # the two-master rule: the command family under the command master is
        # not the command label under the beacon master
        self.assertNotEqual(b.kdf(hx(mv.MASTER_COMMAND), "command", mv.UID_TEST, 1),
                            b.kdf(m, "command", mv.UID_TEST, 1))
        self.assertEqual(b.LABEL_BEACON, b"CID-LORA-BCN")
        self.assertEqual(b.LABEL_COMMAND, b"CID-LORA-CMD")
        self.assertNotEqual(b.LABEL_BEACON, b.LABEL_COMMAND)

    def test_input_checks(self):
        with self.assertRaises(KeyError):
            b.kdf_input("other", 1, 1)
        for uid, gen in ((-1, 1), (1 << 32, 1), (1, -1), (1, 256)):
            with self.assertRaises(ValueError):
                b.kdf_input("beacon", uid, gen)

    def test_kcv_is_three_bytes_of_e_zero(self):
        key = hx(mv.MASTER_BEACON_A)
        self.assertEqual(b.kcv(key), b.AES128(key).encrypt_block(bytes(16))[:3])
        self.assertEqual(len(b.kcv(key)), 3)


# ------------------------------------------------------------------ frames

class TestFrames(unittest.TestCase):
    def test_layout_constants(self):
        self.assertEqual((b.MAGIC_V1, b.LEN_V1, b.MAGIC_V2, b.LEN_V2), (0x4C, 18, 0x4D, 30))
        self.assertEqual((b.AAD_LEN, b.BODY_LEN, b.NONCE_LEN, b.TAG_LEN), (9, 13, 13, 8))
        self.assertEqual(b.AAD_LEN + b.BODY_LEN + b.TAG_LEN, b.LEN_V2)
        self.assertEqual((b.DIR_BEACON, b.DIR_COMMAND, b.DIR_COMMAND_ACK), (0, 1, 2))

    def test_counter_split(self):
        self.assertEqual(b.ctr_make(1, 0), 0x01000000)
        self.assertEqual(b.ctr_make(255, 0xFFFFFF), 0xFFFFFFFF)
        self.assertEqual((b.ctr_gen(0x7F123456), b.ctr_seq(0x7F123456)), (0x7F, 0x123456))
        for gen, seq in ((0, -1), (256, 0), (1, 1 << 24)):
            with self.assertRaises(ValueError):
                b.ctr_make(gen, seq)

    def test_nonce(self):
        n = b.nonce(0x7E57C0DE, 0x01000001)
        self.assertEqual(n, bytes.fromhex("dec0577e01000001" + "00" + "00000000"))
        self.assertEqual(b.nonce(0x7E57C0DE, 0x01000001, b.DIR_COMMAND)[8], 1)
        for v in VEC["frames"]:
            self.assertEqual(b.nonce(v["uid"], v["ctr"]).hex(), v["nonce"], v["name"])

    def test_vectors_open_with_key_and_with_master(self):
        self.assertEqual(len(VEC["frames"]), 14)
        for v in VEC["frames"]:
            frame = hx(v["frame"])
            self.assertEqual(len(frame), b.LEN_V2)
            self.assertEqual(b.classify(frame), "v2")
            self.assertEqual(b.peek(frame), (v["uid"], v["ctr"]), v["name"])
            self.assertEqual(frame[:9].hex(), v["aad"])
            self.assertEqual(frame[9:22].hex(), v["ct"])
            self.assertEqual(frame[22:].hex(), v["tag"])
            got = b.open_frame(hx(v["dev_key"]), frame)
            self.assertEqual((got.version, got.uid, got.ctr, got.gen, got.seq, got.lat_e7, got.lon_e7,
                              got.fix_epoch, got.batt_pct),
                             (2, v["uid"], v["ctr"], v["gen"], v["seq"], v["lat_e7"], v["lon_e7"],
                              v["fix_epoch"], v["batt_pct"]), v["name"])
            self.assertEqual(b.open_with_master(hx(v["master"]), frame), got, v["name"])
            self.assertEqual(b.pack_body(v["lat_e7"], v["lon_e7"], v["fix_epoch"], v["batt_pct"]).hex(),
                             v["body"], v["name"])
            self.assertEqual(b.kcv(hx(v["dev_key"])).hex(), v["kcv"])

    def test_vectors_reseal_byte_for_byte(self):
        for v in VEC["frames"]:
            frame = b.seal(hx(v["dev_key"]), v["uid"], v["ctr"], v["lat_e7"], v["lon_e7"],
                           v["fix_epoch"], v["batt_pct"])
            self.assertEqual(frame.hex(), v["frame"], v["name"])

    def test_tamper_every_bit_of_every_frame_vector(self):
        rejected = 0
        for v in VEC["frames"]:
            key, frame = hx(v["dev_key"]), hx(v["frame"])
            for i in range(b.LEN_V2):
                for bit in range(8):
                    t = bytearray(frame)
                    t[i] ^= 1 << bit
                    if i == 0:
                        with self.assertRaises(ValueError):   # not a v2 frame any more
                            b.open_frame(key, bytes(t))
                    else:
                        with self.assertRaises(b.AuthError):
                            b.open_frame(key, bytes(t))
                    rejected += 1
        self.assertEqual(rejected, 14 * 30 * 8)

    def test_wrong_key_length_and_magic(self):
        v = VEC["frames"][0]
        frame = hx(v["frame"])
        with self.assertRaises(b.AuthError):
            b.open_frame(hx(VEC["frames"][12]["dev_key"]), frame)   # same uid/ctr/body, master B
        with self.assertRaises(b.AuthError):
            b.open_with_master(hx(mv.MASTER_BEACON_B), frame)
        for bad in (frame[:-1], frame + b"\x00", b"", bytes([0x4C]) + frame[1:]):
            with self.assertRaises(ValueError):
                b.peek(bad)
            self.assertIsNone(b.classify(bad) if bad[:1] != b"\x4c" else None)

    def test_generation_changes_key_and_frame(self):
        g1 = [v for v in VEC["frames"] if v["name"] == "nominal"][0]
        g2 = [v for v in VEC["frames"] if v["name"].startswith("gen 2 (")][0]
        self.assertEqual((g1["uid"], g1["seq"], g1["master"]), (g2["uid"], g2["seq"], g2["master"]))
        self.assertNotEqual(g1["dev_key"], g2["dev_key"])
        self.assertNotEqual(g1["ct"], g2["ct"])
        with self.assertRaises(b.AuthError):
            b.open_frame(hx(g1["dev_key"]), hx(g2["frame"]))
        self.assertEqual(b.open_with_master(hx(g2["master"]), hx(g2["frame"])).gen, 2)

    def test_body_extremes(self):
        for lat in (-(1 << 31), -1, 0, 1, (1 << 31) - 1):
            for epoch in (0, 1, 0xFFFFFFFF):
                body = b.pack_body(lat, -lat if lat != -(1 << 31) else lat, epoch, 255)
                self.assertEqual(b.unpack_body(body)[0], lat)
                self.assertEqual(b.unpack_body(body)[2], epoch)
        for bad in ((1 << 31, 0, 0, 0), (0, -(1 << 31) - 1, 0, 0), (0, 0, 1 << 32, 0), (0, 0, 0, 256)):
            with self.assertRaises(ValueError):
                b.pack_body(*bad)


class TestV1(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(len(VEC["v1"]), 3)
        for v in VEC["v1"]:
            frame = b.encode_v1(v["uid"], v["lat_e7"], v["lon_e7"], v["fix_epoch"], v["batt_pct"])
            self.assertEqual(frame.hex(), v["frame"], v["name"])
            self.assertEqual(b.classify(frame), "v1")
            got = b.decode_v1(frame)
            self.assertEqual((got.version, got.uid, got.lat_e7, got.lon_e7, got.fix_epoch, got.batt_pct),
                             (1, v["uid"], v["lat_e7"], v["lon_e7"], v["fix_epoch"], v["batt_pct"]))
            self.assertIsNone(got.ctr)

    def test_v2_body_is_v1_bytes_5_to_17(self):
        for v in VEC["frames"]:
            v1 = b.encode_v1(v["uid"], v["lat_e7"], v["lon_e7"], v["fix_epoch"], v["batt_pct"])
            self.assertEqual(v1[5:].hex(), v["body"])
            self.assertEqual(v1[1:5], hx(v["frame"])[1:5])   # same uid bytes

    def test_rejects(self):
        for bad in (b"", bytes(18), bytes([0x4C]) + bytes(16), bytes([0x4D]) + bytes(17)):
            with self.assertRaises(ValueError):
                b.decode_v1(bad)


# ---------------------------------------------------- sealed report (0x52)

class TestReports(unittest.TestCase):
    """The sealed report, added 2026-09-30: the v2 construction with a
    variable-length body, and its three frozen vectors."""

    def test_layout_constants(self):
        self.assertEqual((b.MAGIC_REPORT, b.REPORT_OVERHEAD), (0x52, 17))
        self.assertEqual((b.REPORT_MIN_PAYLOAD, b.REPORT_MAX_PAYLOAD), (1, 238))
        self.assertEqual((b.REPORT_MIN_LEN, b.REPORT_MAX_LEN), (18, 255))
        self.assertEqual(b.REPORT_OVERHEAD, b.AAD_LEN + b.TAG_LEN)

    def test_vectors_are_the_frozen_frames(self):
        self.assertEqual(len(VEC["reports"]), 3)
        self.assertEqual([v["frame"] for v in VEC["reports"]], [c[-1] for c in mv.REPORT_CASES])
        self.assertEqual([v["frame_len"] for v in VEC["reports"]], [49, 18, 255])
        self.assertEqual([v["ctr_hex"] for v in VEC["reports"]], ["01000001", "02abcdef", "fffffffe"])

    def test_vectors_open_with_key_and_with_master(self):
        for v in VEC["reports"]:
            frame, payload = hx(v["frame"]), hx(v["payload"])
            self.assertEqual(len(frame), v["frame_len"])
            self.assertEqual(len(frame), len(payload) + b.REPORT_OVERHEAD)
            self.assertEqual(b.classify(frame), "report", v["name"])
            self.assertEqual(b.peek_report(frame), (v["uid"], v["ctr"]), v["name"])
            self.assertEqual(frame[:9].hex(), v["aad"])
            self.assertEqual(frame[9:9 + len(payload)].hex(), v["ct"])
            self.assertEqual(frame[9 + len(payload):].hex(), v["tag"])
            self.assertEqual(b.nonce(v["uid"], v["ctr"]).hex(), v["nonce"])
            got = b.open_report(hx(v["dev_key"]), frame)
            self.assertEqual((got.uid, got.ctr, got.gen, got.seq, got.payload),
                             (v["uid"], v["ctr"], v["gen"], v["seq"], payload), v["name"])
            self.assertEqual(b.open_report_with_master(hx(v["master"]), frame), got, v["name"])
            self.assertEqual(b.kdf(hx(v["master"]), "beacon", v["uid"], v["gen"]).hex(), v["dev_key"])
            self.assertEqual(b.kcv(hx(v["dev_key"])).hex(), v["kcv"])

    def test_vectors_reseal_byte_for_byte(self):
        for v in VEC["reports"]:
            frame = b.seal_report(hx(v["dev_key"]), v["uid"], v["ctr"], hx(v["payload"]))
            self.assertEqual(frame.hex(), v["frame"], v["name"])

    def test_tamper_every_bit_of_every_report_vector(self):
        rejected = 0
        for v in VEC["reports"]:
            key, frame = hx(v["dev_key"]), hx(v["frame"])
            for i in range(len(frame)):
                for bit in range(8):
                    t = bytearray(frame)
                    t[i] ^= 1 << bit
                    with self.assertRaises(ValueError if i == 0 else b.AuthError):   # byte 0: not a report any more
                        b.open_report(key, bytes(t))
                    rejected += 1
        self.assertEqual(rejected, (49 + 18 + 255) * 8)

    def test_wrong_key_length_and_magic(self):
        r1, r2, r3 = VEC["reports"]
        f1 = hx(r1["frame"])
        for other in (r2, r3):
            with self.assertRaises(b.AuthError):
                b.open_report(hx(other["dev_key"]), f1)
        with self.assertRaises(b.AuthError):
            b.open_report_with_master(hx(mv.MASTER_BEACON_B), f1)
        with self.assertRaises(b.AuthError):                                   # the next generation's key
            b.open_report(b.kdf(hx(r1["master"]), "beacon", r1["uid"], r1["gen"] + 1), f1)
        with self.assertRaises(b.AuthError):
            b.open_report(hx(r1["dev_key"]), f1[:-1])                          # a byte short
        with self.assertRaises(b.AuthError):
            b.open_report(hx(r1["dev_key"]), f1 + b"\x00")                     # a byte long
        f2 = hx(r2["frame"])
        for bad in (f2[:-1], b"", bytes([0x52]) * 8, hx(r3["frame"]) + b"\x00", bytes([0x4D]) + f1[1:]):
            with self.assertRaises(ValueError):
                b.peek_report(bad)
            self.assertNotEqual(b.classify(bad), "report")

    def test_payload_bounds(self):
        key = hx(VEC["reports"][0]["dev_key"])
        for n in (0, 239, 300):
            with self.assertRaises(ValueError):
                b.seal_report(key, 1, 0x01000000, bytes(n))
        self.assertEqual(len(b.seal_report(key, 1, 0x01000000, b"\x0a")), 18)
        self.assertEqual(len(b.seal_report(key, 1, 0x01000000, bytes(238))), 255)
        for uid, ctr in ((-1, 0), (1 << 32, 0), (0, 1 << 32)):
            with self.assertRaises(ValueError):
                b.seal_report(key, uid, ctr, b"\x0a")

    def test_same_construction_as_v2(self):
        # The report recipe with the beacon's magic and its 13-byte body IS
        # beacon_v2.seal; with 0x52 the ciphertext is the same keystream (same
        # key, same nonce) and only the tag differs, because the magic is in
        # the AAD. So a report never opens as a beacon or the other way round.
        for v in VEC["frames"]:
            key, uid, ctr, body = hx(v["dev_key"]), v["uid"], v["ctr"], hx(v["body"])
            hdr4d = bytes([0x4D]) + uid.to_bytes(4, "little") + ctr.to_bytes(4, "little")
            ct, tag = b.ccm_seal(key, b.nonce(uid, ctr), hdr4d, body, 8)
            self.assertEqual((hdr4d + ct + tag).hex(), v["frame"], v["name"])
            rep = b.seal_report(key, uid, ctr, body)
            self.assertEqual(len(rep), b.LEN_V2)                               # 13 + 17: the beacon's length
            self.assertEqual(rep[9:22], hx(v["frame"])[9:22])
            self.assertNotEqual(rep[22:], hx(v["frame"])[22:])
            with self.assertRaises(b.AuthError):
                b.open_frame(key, bytes([0x4D]) + rep[1:])
            with self.assertRaises(b.AuthError):
                b.open_report(key, bytes([0x52]) + hx(v["frame"])[1:])

    def test_one_counter_sequence_is_required(self):
        # Why the collar spends its beacon counter on reports: a report and a
        # beacon under one key and one counter share the CCM keystream, so the
        # XOR of their ciphertexts is the XOR of their plaintexts.
        v = VEC["frames"][0]
        key, uid, ctr, body = hx(v["dev_key"]), v["uid"], v["ctr"], hx(v["body"])
        report = bytes(range(0x0A, 0x0A + 13))
        rep = b.seal_report(key, uid, ctr, report)
        leak = bytes(x ^ y for x, y in zip(rep[9:22], hx(v["frame"])[9:22]))
        self.assertEqual(leak, bytes(x ^ y for x, y in zip(report, body)))

    def test_a_plaintext_report_never_reads_as_sealed(self):
        for n in range(1, 256):
            self.assertIsNone(b.classify(bytes([0x0A]) + bytes(n - 1)))
        for n in range(b.REPORT_MIN_LEN, b.REPORT_MAX_LEN + 1):
            self.assertEqual(b.classify(bytes([0x52]) + bytes(n - 1)), "report")
        self.assertEqual(b.classify(bytes([0x4C]) + bytes(17)), "v1")          # (magic, length) decides
        self.assertEqual(b.classify(bytes([0x4D]) + bytes(29)), "v2")
        self.assertIsNone(b.classify(bytes([0x52]) + bytes(16)))               # 17 B: no body
        self.assertIsNone(b.classify(bytes([0x52]) + bytes(255)))              # 256 B: no LoRa packet


# ---------------------------------------------------------- frozen vectors

class TestVectorsFrozen(unittest.TestCase):
    def test_file_is_what_the_generator_makes(self):
        with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), mv.render(mv.build()))

    def test_format_and_counts(self):
        # The reports section was added (2026-09-30) without touching any
        # earlier entry, so the format version is still 1.
        self.assertEqual((VEC["format"], VEC["version"]), ("collarid-beacon-v2-vectors", 1))
        # old: ... for k in ("aes128", "cmac", "ccm", "kdf", "frames", "v1") ... without "reports"
        self.assertEqual({k: len(VEC[k]) for k in ("aes128", "cmac", "ccm", "kdf", "frames", "v1", "reports")},
                         {"aes128": 1, "cmac": 4, "ccm": 24, "kdf": 8, "frames": 14, "v1": 3, "reports": 3})

    def test_everything_is_synthetic(self):
        masters = {mv.MASTER_BEACON_A, mv.MASTER_BEACON_B, mv.MASTER_COMMAND}
        # old: for v in VEC["kdf"] + VEC["frames"]:
        for v in VEC["kdf"] + VEC["frames"] + VEC["reports"]:
            self.assertIn(v["master"], masters)
        # Real CollarID uids are STM32 UIDw0 wafer coordinates: both 16-bit
        # halves small. None of the synthetic uids has that shape.
        # old: for v in VEC["kdf"] + VEC["frames"] + VEC["v1"]:
        for v in VEC["kdf"] + VEC["frames"] + VEC["v1"] + VEC["reports"]:
            uid = v["uid"]
            self.assertFalse(0 < (uid >> 16) < 0x100 and 0 < (uid & 0xFFFF) < 0x100, "uid looks real: %08x" % uid)
        self.assertIn("synthetic", VEC["note"])


# --------------------------------------------------------------------- CLI

class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = b.main(argv)
        return rc, out.getvalue()

    def test_open_derive_kcv_v1(self):
        v = VEC["frames"][0]
        rc, out = self.run_cli(["open", "--key", v["dev_key"], v["frame"]])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["lat_e7"], v["lat_e7"])
        rc, out = self.run_cli(["open", "--master", v["master"], v["frame"]])
        self.assertEqual((rc, json.loads(out)["gen"]), (0, v["gen"]))
        rc, out = self.run_cli(["derive", "--master", v["master"], "--uid", "0x%08X" % v["uid"], "--gen", str(v["gen"])])
        self.assertEqual((rc, json.loads(out)["key"], json.loads(out)["kcv"]), (0, v["dev_key"], v["kcv"]))
        rc, out = self.run_cli(["kcv", "--key", v["dev_key"]])
        self.assertEqual((rc, json.loads(out)["kcv"]), (0, v["kcv"]))
        w = VEC["v1"][0]
        rc, out = self.run_cli(["v1", w["frame"]])
        self.assertEqual((rc, json.loads(out)["uid"]), (0, w["uid"]))

    def test_open_with_wrong_key_fails_closed(self):
        v = VEC["frames"][0]
        rc, out = self.run_cli(["open", "--key", "00" * 16, v["frame"]])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["error"], "authentication failed")
        self.assertNotIn("lat", out)

    def test_report_peek_open_seal(self):
        for v in VEC["reports"]:
            rc, out = self.run_cli(["report-peek", v["frame"]])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out), {"uid": v["uid"], "ctr": v["ctr"], "gen": v["gen"], "seq": v["seq"],
                                               "len": v["frame_len"], "payload_len": v["frame_len"] - 17})
            rc, out = self.run_cli(["report-open", "--key", v["dev_key"], v["frame"]])
            self.assertEqual((rc, json.loads(out)["payload"], json.loads(out)["ctr"]), (0, v["payload"], v["ctr"]))
            rc, out = self.run_cli(["report-open", "--master", v["master"], v["frame"]])
            self.assertEqual((rc, json.loads(out)["payload"]), (0, v["payload"]))
            rc, out = self.run_cli(["report-seal", "--key", v["dev_key"], "--uid", "0x%08X" % v["uid"],
                                    "--ctr", "0x%08X" % v["ctr"], v["payload"]])
            self.assertEqual((rc, json.loads(out)), (0, {"frame": v["frame"], "len": v["frame_len"]}))

    def test_report_open_with_wrong_key_fails_closed(self):
        v = VEC["reports"][0]
        rc, out = self.run_cli(["report-open", "--key", "00" * 16, v["frame"]])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["error"], "authentication failed")
        self.assertNotIn("payload", out)


# ----------------------------------------------- against `cryptography`

@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "the cryptography package is not installed")
class TestAgainstCryptography(unittest.TestCase):
    def test_ccm_vectors(self):
        for v in VEC["ccm"]:
            out = AESCCM(hx(v["key"]), tag_length=v["tag_len"]).encrypt(hx(v["nonce"]), hx(v["pt"]), hx(v["aad"]))
            self.assertEqual(out.hex(), v["ct"] + v["tag"], v["name"])

    def test_frames(self):
        for v in VEC["frames"]:
            frame = hx(v["frame"])
            body = AESCCM(hx(v["dev_key"]), tag_length=8).decrypt(hx(v["nonce"]), frame[9:], frame[:9])
            self.assertEqual(body.hex(), v["body"], v["name"])

    def test_kdf(self):
        for v in VEC["kdf"]:
            c = _cmac.CMAC(_alg.AES(hx(v["master"])))
            c.update(hx(v["input"]))
            self.assertEqual(c.finalize().hex(), v["dev_key"], v["name"])

    def test_reports(self):
        for v in VEC["reports"]:
            frame = hx(v["frame"])
            payload = AESCCM(hx(v["dev_key"]), tag_length=8).decrypt(hx(v["nonce"]), frame[9:], frame[:9])
            self.assertEqual(payload.hex(), v["payload"], v["name"])


class CommandFrameTests(unittest.TestCase):
    """The signed handheld command (0x44) and its acknowledgement (0x4B)."""

    def setUp(self):
        self.vec = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")))

    def test_vectors_open(self):
        for v in self.vec["commands"]:
            key = bytes.fromhex(v["cmd_key"])
            got = b.open_command(key, bytes.fromhex(v["frame"]))
            self.assertEqual((got.uid, got.ctr, got.echo, got.valid_from, got.valid_to, got.body.hex()),
                             (v["uid"], v["ctr"], v["echo"], v["valid_from"], v["valid_to"], v["body"]))
            self.assertEqual(b.classify(bytes.fromhex(v["frame"])), "command")
        for v in self.vec["command_acks"]:
            got = b.open_command_ack(bytes.fromhex(v["cmd_key"]), bytes.fromhex(v["frame"]))
            self.assertEqual((got.result, got.command, got.detail, got.rssi, got.snr_q4),
                             (v["result"], v["command"], v["detail"], v["rssi"], v["snr_q4"]))
            self.assertEqual(b.classify(bytes.fromhex(v["frame"])), "command_ack")

    def test_beacon_key_never_opens_a_command(self):
        v = self.vec["commands"][0]
        beacon = b.kdf(bytes.fromhex(v["master"]), "beacon", v["uid"], v["gen"])
        with self.assertRaises(b.AuthError):
            b.open_command(beacon, bytes.fromhex(v["frame"]))

    def test_every_byte_is_authenticated(self):
        v = self.vec["commands"][1]
        key, frame = bytes.fromhex(v["cmd_key"]), bytearray.fromhex(v["frame"])
        for i in range(len(frame)):
            bad = bytearray(frame)
            bad[i] ^= 0x01
            if i == 0:
                with self.assertRaises(ValueError):
                    b.open_command(key, bytes(bad))
                continue
            with self.assertRaises(b.AuthError):
                b.open_command(key, bytes(bad))

    def test_ack_direction_differs(self):
        # The same key and counter in the two directions never give the same
        # keystream: a command frame cannot be opened as an ACK or back.
        v = self.vec["command_acks"][0]
        key = bytes.fromhex(v["cmd_key"])
        frame = bytearray.fromhex(v["frame"])
        frame[0] = b.MAGIC_COMMAND
        with self.assertRaises((b.AuthError, ValueError)):
            b.open_command(key, bytes(frame))

    def test_freshness(self):
        c = b.Command(1, 1, 0, 1, 0, 100, 200, b"\x10")
        self.assertTrue(b.command_fresh(c, 0, 100))
        self.assertTrue(b.command_fresh(c, 0, 200))
        self.assertFalse(b.command_fresh(c, 0, 99))
        self.assertFalse(b.command_fresh(c, 0, 201))
        open_ended = c._replace(valid_to=0)
        self.assertFalse(b.command_fresh(open_ended, 0, 150))   # a pre-signed command needs an expiry
        live = c._replace(echo=173)
        self.assertTrue(b.command_fresh(live, 173, 0))
        self.assertFalse(b.command_fresh(live, 174, 150))

    def test_lengths(self):
        key = bytes(16)
        with self.assertRaises(ValueError):
            b.seal_command(key, 1, 1, b"")
        with self.assertRaises(ValueError):
            b.seal_command(key, 1, 1, bytes(227))
        self.assertEqual(len(b.seal_command(key, 1, 1, bytes(226))), 255)
        self.assertEqual(len(b.seal_command_ack(key, 1, 1, 1, 13)), b.COMMAND_ACK_LEN)

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography not installed")
    def test_against_cryptography(self):
        for v in self.vec["commands"]:
            frame = bytes.fromhex(v["frame"])
            pt = AESCCM(bytes.fromhex(v["cmd_key"]), tag_length=8).decrypt(
                bytes.fromhex(v["nonce"]), frame[9:], frame[:9])
            self.assertEqual(pt[12:].hex(), v["body"])


# ------------------------------------------------- LoRa wake (2026-11-13)

class TestWakeTags(unittest.TestCase):
    """tag(uid) = fmix32(uid ^ 'WAKE') & 0xFFFF."""

    def test_mix_is_the_firmware_send_phase_mix(self):
        # murmur3's 32-bit finalizer; these four are what send_phase.h gives.
        self.assertEqual([b.send_phase_mix(x) for x in (0, 1, 0xFFFFFFFF, 0x12345678)],
                         [0, 0x514E28B7, 0x81F16F39, 0xE37CD1BC])
        self.assertEqual(b.WAKE_SALT, int.from_bytes(b"WAKE", "big"))
        for bad in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                b.send_phase_mix(bad)
            with self.assertRaises(ValueError):
                b.wake_tag(bad)

    def test_vectors(self):
        self.assertEqual(len(VEC["wake_tags"]), 15)
        for v in VEC["wake_tags"]:
            self.assertEqual(b.wake_tag(v["uid"]), v["tag"], v["name"])
            self.assertEqual("%08x" % b.send_phase_mix(v["uid"] ^ b.WAKE_SALT), v["mixed_hex"], v["name"])
            self.assertEqual(v["tag"], int(v["mixed_hex"], 16) & 0xFFFF)
            self.assertEqual("%04x" % v["tag"], v["tag_hex"])
            self.assertEqual("%08x" % v["uid"], v["uid_hex"])

    def test_edges(self):
        by_uid = {v["uid"]: v["tag"] for v in VEC["wake_tags"]}
        self.assertEqual(by_uid[b.WAKE_SALT], 0)                    # a tag of 0 is a tag like any other
        self.assertEqual(by_uid[mv.UID_TWIN], by_uid[mv.UID_WAKE[0]])   # two collars, one tag
        self.assertEqual(len({by_uid[u] for u in mv.UID_WAKE}), 8)  # the eight train collars are told apart


class TestWakeFrames(unittest.TestCase):

    def test_layout_constants(self):
        self.assertEqual((b.MAGIC_WAKE, b.WAKE_HEADER_LEN, b.WAKE_MAX_TAGS, b.WAKE_MAX_LEN), (0x57, 5, 4, 13))
        self.assertEqual((b.WAKE_FLAG_MORE, b.WAKE_FLAG_LONG, b.WAKE_FLAG_ROLL, b.WAKE_FLAGS_DEFINED), (1, 2, 4, 7))
        self.assertEqual((b.WAKE_TIME_UNIT_MS, b.WAKE_TIME_LEFT_MAX, b.WAKE_TRAIN_MAX_COLLARS), (10, 65535, 8))
        self.assertEqual(b.WAKE_SYNC_WORD, 0x57)

    def test_vectors_build_and_parse(self):
        good = [v for v in VEC["wake_frames"] if v["ok"]]
        self.assertEqual(len(good), 12)
        self.assertEqual([v["frame"] for v in good], [c[-1] for c in mv.WAKE_FRAME_CASES])   # the frozen frames
        for v in good:
            frame = hx(v["frame"])
            self.assertEqual(len(frame), v["frame_len"])
            self.assertEqual(len(frame), 5 + 2 * len(v["tags"]))
            self.assertEqual(b.classify(frame), "wake", v["name"])
            self.assertEqual(v["tags"], [b.wake_tag(u) for u in v["uids"]], v["name"])
            self.assertEqual(b.wake_frame(v["tags"], v["time_left_10ms"], v["more"], v["long_range"],
                                          v["roll"]).hex(), v["frame"], v["name"])
            f = b.parse_wake_frame(frame)
            self.assertEqual((f.flags, f.more, f.long_range, f.roll, f.time_left_10ms, list(f.tags)),
                             (v["flags"], v["more"], v["long_range"], v["roll"], v["time_left_10ms"], v["tags"]),
                             v["name"])
            self.assertEqual(v["time_left_ms"], 10 * v["time_left_10ms"])
            self.assertEqual(v["flags"], v["more"] * 1 + v["long_range"] * 2 + v["roll"] * 4)
            # bytes, spelled out
            self.assertEqual(frame[0], 0x57)
            self.assertEqual(int.from_bytes(frame[2:4], "little"), v["time_left_10ms"])
            self.assertEqual(frame[4], len(v["tags"]))
            for p in v["verdicts"]:
                self.assertEqual(b.wake_tag(p["uid"]), p["tag"])
                self.assertEqual(b.wake_verdict(f, p["uid"]), p["verdict"], (v["name"], p["uid"]))

    def test_vectors_cover_the_cases(self):
        good = {v["name"]: v for v in VEC["wake_frames"] if v["ok"]}
        self.assertEqual(len(good["one collar"]["tags"]), 1)
        self.assertEqual(len(good["four collars, the most one frame names"]["tags"]), 4)
        a = good["eight collars, list A: the first four, MORE"]
        bb = good["eight collars, list B: the other four, MORE"]
        self.assertTrue(a["more"] and bb["more"])
        self.assertEqual(a["uids"] + bb["uids"], mv.UID_WAKE)
        roll = good["a roll-call train: ROLL, no tags"]
        self.assertEqual((roll["roll"], roll["tags"], roll["frame_len"]), (True, [], 5))
        self.assertEqual(good["the last frame of a train: time left 0"]["time_left_10ms"], 0)
        self.assertEqual(good["time left at its largest, 655.35 s"]["time_left_ms"], 655350)
        self.assertEqual({p["verdict"] for v in good.values() for p in v["verdicts"]},
                         {"called", "more", "not_called", "roll"})

    def test_verdicts(self):
        f = b.parse_wake_frame(b.wake_frame([b.wake_tag(1), b.wake_tag(2)], 100))
        self.assertEqual([b.wake_verdict(f, u) for u in (1, 2, 3)], ["called", "called", "not_called"])
        f = b.parse_wake_frame(b.wake_frame([b.wake_tag(1)], 100, more=True))
        self.assertEqual([b.wake_verdict(f, u) for u in (1, 3)], ["called", "more"])
        f = b.parse_wake_frame(b.wake_frame([], 100, roll=True))
        self.assertEqual([b.wake_verdict(f, u) for u in (1, 3)], ["roll", "roll"])
        # A collar that shares a called collar's tag is called too: the INTENT's uid sorts it out.
        f = b.parse_wake_frame(b.wake_frame([b.wake_tag(mv.UID_WAKE[0])], 100))
        self.assertEqual(b.wake_verdict(f, mv.UID_TWIN), "called")

    def test_malformed_vectors_are_refused_for_the_stated_reason(self):
        bad = [v for v in VEC["wake_frames"] if not v["ok"]]
        self.assertEqual(len(bad), 13)
        for v in bad:
            with self.assertRaises(b.WakeFrameError) as cm:
                b.parse_wake_frame(hx(v["frame"]))
            self.assertEqual(cm.exception.reason, v["refusal"], v["name"])
            self.assertEqual(len(hx(v["frame"])), v["frame_len"])
        self.assertEqual({v["refusal"] for v in bad}, set(b.WAKE_REFUSALS))    # every reason has a vector

    def test_every_reserved_flag_and_length_is_refused(self):
        tags = [b.wake_tag(u) for u in mv.UID_WAKE[:4]]
        for k in range(1, 5):
            frame = b.wake_frame(tags[:k], 7)
            for bit in range(3, 8):
                t = bytearray(frame)
                t[1] |= 1 << bit
                with self.assertRaises(b.WakeFrameError) as cm:
                    b.parse_wake_frame(bytes(t))
                self.assertEqual(cm.exception.reason, "reserved_flags")
            for n in range(0, 16):
                if n == len(frame):
                    continue
                t = (frame + bytes(16))[:n]
                with self.assertRaises(b.WakeFrameError) as cm:
                    b.parse_wake_frame(t)
                self.assertEqual(cm.exception.reason, "length" if not 5 <= n <= 13 else "tag_bytes", (k, n))

    def test_builder_refuses_what_the_parser_refuses(self):
        for args, kw in (((list(range(5)), 0), {}),                 # five tags
                         (([], 0), {}),                             # no tags, no roll
                         (([1], 0), {"roll": True}),                # roll with a tag
                         (([], 0), {"roll": True, "more": True}),   # roll with MORE
                         (([1], -1), {}), (([1], 65536), {}),       # time left out of the field
                         (([65536], 0), {})):                       # a tag over 16 bits
            with self.assertRaises(ValueError):
                b.wake_frame(*args, **kw)

    def test_train_lists(self):
        u = mv.UID_WAKE
        for n in range(1, 5):
            lists = b.wake_train_lists(u[:n])
            self.assertEqual(lists, [[b.wake_tag(x) for x in u[:n]]])
            f = b.parse_wake_frame(b.wake_train_frame(u[:n], 3, 10))
            self.assertFalse(f.more)
        for n in range(5, 9):
            lists = b.wake_train_lists(u[:n])
            self.assertEqual([len(x) for x in lists], [4, n - 4])
            frames = [b.parse_wake_frame(b.wake_train_frame(u[:n], i, 10)) for i in range(4)]
            self.assertTrue(all(f.more for f in frames))                 # both lists carry MORE
            self.assertEqual(frames[0].tags, frames[2].tags)             # they alternate
            self.assertEqual(frames[1].tags, frames[3].tags)
            # every called collar is in one of the two; one more frame always settles it
            for uid in u[:n]:
                self.assertEqual(sorted(b.wake_verdict(f, uid) for f in frames[:2]), ["called", "more"])
            self.assertEqual([b.wake_verdict(f, mv.UID_TEST) for f in frames[:2]], ["more", "more"])
        for bad in ([], u + [1]):
            with self.assertRaises(ValueError):
                b.wake_train_lists(bad)

    def test_no_other_frame_reads_as_a_wake_frame(self):
        for v in VEC["frames"] + VEC["reports"] + VEC["commands"] + VEC["command_acks"] + VEC["v1"]:
            self.assertNotEqual(b.classify(hx(v["frame"])), "wake")
            with self.assertRaises(b.WakeFrameError):
                b.parse_wake_frame(hx(v["frame"]))
        self.assertIsNone(b.classify(bytes([0x57]) + bytes(3)))        # 4 B
        self.assertIsNone(b.classify(bytes([0x57]) + bytes(13)))       # 14 B
        self.assertEqual(b.classify(bytes([0x57]) + bytes(4)), "wake")  # by magic and length only


class TestWakeTiming(unittest.TestCase):
    """CONTRACT_lora_wake.md sections 1 and 3: the wake table and the timing."""

    T = VEC["wake_timing"]

    def test_the_contract_table(self):
        # Setting -> (Ts, frame, W to 0.1 ms; cap to the millisecond).
        table = {(9, 500): (1.024, 45.3, 56.4, 88), (7, 125): (1.024, 50.4, 61.5, 96),
                 (12, 500): (8.192, 321.5, 361.3, 502), (10, 125): (8.192, 321.5, 361.3, 502)}
        self.assertEqual(len(self.T["settings"]), 4)
        for s in self.T["settings"]:
            self.assertEqual((s["ts_ms"], s["frame_ms"], s["w_ms"], s["cap_whole_ms"]),
                             table[(s["sf"], s["bw_khz"])], s["name"])

    def test_settings_vectors(self):
        for s in self.T["settings"]:
            sf, bw = s["sf"], s["bw_khz"]
            t = b.wake_timing(sf, bw)
            self.assertEqual((t.ts_us, t.frame_us, t.tail_us, t.w_us, t.cap_us, t.intent_wait_us,
                              t.cmd_window_us, t.roll_wait_us, t.roll_slot_min_us, t.roll_slot_default_ms),
                             tuple(s[k] for k in ("ts_us", "frame_us", "tail_us", "w_us", "cap_us",
                                                  "intent_wait_us", "cmd_window_us", "roll_wait_us",
                                                  "roll_slot_min_us", "roll_slot_default_ms")), s["name"])
            for k in ("frame", "tail", "w", "cap", "intent_wait", "cmd_window", "roll_wait", "roll_slot_min"):
                self.assertEqual(s[k + "_ms"], mv.ms1(s[k + "_us"]), (s["name"], k))
                self.assertAlmostEqual(s[k + "_ms"], s[k + "_us"] / 1000, delta=0.05)
            self.assertEqual(s["ts_ms"] * 1000, s["ts_us"])
            for a in s["toa"]:
                self.assertEqual(b.lora_toa_us(sf, bw, a["bytes"], a["preamble"]), a["us"], s["name"])
            for tr in s["trains"]:
                self.assertEqual(b.wake_train_us(sf, bw, tr["interval_s"]), tr["train_us"])
                self.assertEqual(tr["train_ms"], mv.ms1(tr["train_us"]))
                self.assertEqual(b.wake_train_frames(sf, bw, tr["interval_s"], 0), tr["frames_gap_0"])
                self.assertEqual(b.wake_train_frames(sf, bw, tr["interval_s"], 5000), tr["frames_gap_5ms"])
            self.assertEqual({tr["interval_s"] for tr in s["trains"]}, {1, 2, 5, 10, 30, 60, 120})
            self.assertEqual(s["call_sniff_s"], 2 if s["long_range"] else 1)
            self.assertEqual(s["call_sniff_s"], b.call_sniff_s(s["long_range"]))
            self.assertEqual(s["roll_slot_min_whole_ms"], -(-s["roll_slot_min_us"] // 1000))
            for r in s["regions"]:
                self.assertEqual(b.wake_setting(r, s["long_range"])[1:3], (bw, sf))

    def test_the_formulas_as_the_contract_writes_them(self):
        """Floating point, straight from the text, against the integer codec."""
        import math

        def toa(sf, bw, n, p):
            ts = 2 ** sf / bw
            de = 1 if ts > 16 else 0
            return (p + 4.25 + 8 + max(math.ceil((8 * n - 4 * sf + 44) / (4 * (sf - 2 * de))) * 5, 0)) * ts

        for sf in range(7, 13):
            for bw in (125, 250, 500):
                ts = 2 ** sf / bw
                frame, tail = toa(sf, bw, 13, 12), toa(sf, bw, 13, 8) - 8 * ts
                w = tail + 16 * ts + 7
                t = b.wake_timing(sf, bw)
                for got_us, want_ms in ((t.ts_us, ts), (t.frame_us, frame), (t.tail_us, tail), (t.w_us, w),
                                        (t.cap_us, 1.5 * frame + 20),
                                        (t.intent_wait_us, 2 * toa(sf, bw, 14, 8) + 150),
                                        (t.cmd_window_us, toa(sf, bw, 255, 8) + 300),
                                        (t.roll_wait_us, 2 * toa(sf, bw, 29, 8) + 150),
                                        (t.roll_slot_min_us, toa(sf, bw, 30, 8) + 5),
                                        (b.wake_train_us(sf, bw, 30), 1.03 * 30 * 1000 + w + frame)):
                    self.assertAlmostEqual(got_us / 1000, want_ms, places=6, msg=(sf, bw))
                self.assertEqual(t.roll_slot_default_ms, math.ceil(toa(sf, bw, 30, 8)) + 10)
                for n in range(256):
                    self.assertAlmostEqual(b.lora_toa_us(sf, bw, n) / 1000, toa(sf, bw, n, 8), places=6)
        # DE applies from Ts > 16 ms: SF11 and SF12 at 125 kHz, SF12 at 250 kHz.
        self.assertEqual([(sf, bw) for sf in range(7, 13) for bw in (125, 250, 500)
                          if b.lora_symbol_us(sf, bw) > 16000], [(11, 125), (12, 125), (12, 250)])

    def test_a_window_anywhere_in_a_train_sees_eight_preamble_symbols(self):
        """Why W is what it is. A detection needs 8 symbols of one frame's
        12-symbol preamble. Opened at the worst moment, when the frame on air
        has just under 8 of them left, the window waits out the rest of that
        frame and the gap and still holds 8 symbols of the next preamble:
        tail + 16 Ts + the gap, and W keeps 2 ms over the 5 ms gap."""
        for s in self.T["settings"]:
            ts, frame, w = s["ts_us"], s["frame_us"], s["w_us"]
            for gap in (0, 2500, 5000):
                period = frame + gap
                worst = 0
                for start in range(0, period, 97):          # the window opens `start` into a frame
                    k = 0                                   # the first frame with 8 preamble symbols left
                    while k * period + 12 * ts - start < 8 * ts:
                        k += 1
                    need = max(k * period, start) + 8 * ts - start
                    worst = max(worst, need)
                self.assertLessEqual(worst, w, (s["name"], gap))
                self.assertGreater(worst, s["tail_us"] + 16 * ts + gap - 97)       # the worst case is that sum
            self.assertEqual(w, s["tail_us"] + 16 * ts + 7000)
            self.assertEqual(frame, s["tail_us"] + 12 * ts)                        # a frame is its preamble and its tail

    def test_train_frames(self):
        for s in self.T["settings"]:
            sf, bw = s["sf"], s["bw_khz"]
            for i in (1, 2, 10, 30, 60):
                for gap in (0, 1000, 5000):
                    n = b.wake_train_frames(sf, bw, i, gap)
                    span = n * s["frame_us"] + (n - 1) * gap
                    self.assertGreaterEqual(span, b.wake_train_us(sf, bw, i))
                    self.assertLess(span - s["frame_us"] - gap, b.wake_train_us(sf, bw, i))   # one fewer is too short
                    # the time-left field of every frame of that train fits its 16 bits
                    self.assertLessEqual(b.wake_time_left_10ms((n - 1) * (s["frame_us"] + gap)), 65535)
            with self.assertRaises(ValueError):
                b.wake_train_frames(sf, bw, 30, 5001)
            # The longest train a handheld sends, 4 x the train of the longest interval, fits the field.
            self.assertLess(4 * b.wake_train_us(sf, bw, 120), 655350 * 1000)

    def test_constants(self):
        c = self.T["constants"]
        self.assertEqual(c, {
            "sync_word": 0x57, "preamble_wake": 12, "preamble_other": 8, "frame_bytes": 13, "max_tags": 4,
            "max_collars_per_train": 8, "salt": 0x57414B45, "time_unit_ms": 10, "gap_max_ms": 5,
            "rx_lead_ms": 10, "first_send_ms": 30, "interval_choices_s": [10, 30, 60], "interval_min_s": 5,
            "interval_max_s": 120, "slow_factor_max": 4, "call_sniff_s": 1, "call_sniff_long_s": 2,
            "called_wait_s": 60, "call_idle_s": 300, "call_max_s": 900, "roll_slots_default": 32,
            # old: "roll_reply_base_ms": 50 (to 2026-11-13)
            "roll_slots_max": 64, "roll_reply_base_ms": 300, "roll_listen_extra_ms": 200, "roll_min_gap_s": 60})

    def test_regions(self):
        self.assertEqual(self.T["regions"], [
            {"region": 1, "name": "US915", "frequency_hz": 919000000, "bw_khz": 500, "sf": 9, "sf_long": 12, "max_dbm": 22},
            {"region": 2, "name": "EU868", "frequency_hz": 869525000, "bw_khz": 125, "sf": 7, "sf_long": 10, "max_dbm": 22},
            {"region": 3, "name": "AU915", "frequency_hz": 919000000, "bw_khz": 500, "sf": 9, "sf_long": 12, "max_dbm": 22}])
        for r in self.T["regions"]:
            self.assertEqual(b.wake_setting(r["region"]), (r["frequency_hz"], r["bw_khz"], r["sf"], r["max_dbm"]))
            self.assertEqual(b.wake_setting(r["region"], True), (r["frequency_hz"], r["bw_khz"], r["sf_long"], r["max_dbm"]))
        self.assertIsNone(b.wake_setting(0))
        self.assertIsNone(b.wake_setting(4))
        self.assertEqual((b.DIRECT_REGION_AUTO, b.DIRECT_REGION_US915, b.DIRECT_REGION_EU868, b.DIRECT_REGION_AU915),
                         (0, 1, 2, 3))

    def test_region_resolve(self):
        self.assertEqual(len(self.T["region_resolve"]), 19)
        for v in self.T["region_resolve"]:
            self.assertEqual(b.direct_region_resolve(v["setting"], v["lorawan_region"], v["frequency_mhz"]),
                             v["region"], v["name"])
        # AUTO never picks AU915 from a frequency; LoRaWAN's region numbers are not the direct radio's.
        self.assertNotIn(3, {b.direct_region_resolve(0, None, f) for f in range(0, 1000)})
        self.assertEqual([b.direct_region_resolve(0, lw, 0) for lw in (0, 1, 2)], [1, 3, 2])

    def test_interval_clamp_and_time_left(self):
        for v in self.T["interval_clamp"]:
            self.assertEqual(b.wake_interval_clamp(v["interval_s"]), v["runs_s"])
        for s in b.WAKE_INTERVAL_CHOICES_S:
            self.assertEqual(b.wake_interval_clamp(s), s)
        for v in self.T["time_left"]:
            self.assertEqual(b.wake_time_left_10ms(v["us"]), v["time_left_10ms"])
        with self.assertRaises(ValueError):
            b.wake_interval_clamp(-1)
        for bad in ((6, 500), (13, 125), (9, 400)):
            with self.assertRaises(ValueError):
                b.lora_symbol_us(*bad)


class TestRollCalls(unittest.TestCase):
    """The roll call (0x43) and the wake key."""

    R = VEC["roll_calls"]

    def test_layout_constants(self):
        self.assertEqual((b.MAGIC_ROLL_CALL, b.ROLL_CALL_LEN, b.ROLL_CALL_BODY_LEN, b.DIR_ROLL_CALL), (0x43, 29, 12, 3))
        self.assertEqual(b.LABEL_WAKE, b"CID-LORA-WAK")
        self.assertEqual(len({b.LABEL_BEACON, b.LABEL_COMMAND, b.LABEL_WAKE}), 3)
        self.assertEqual({len(x) for x in b.PURPOSES.values()}, {12})
        self.assertEqual(len({b.DIR_BEACON, b.DIR_COMMAND, b.DIR_COMMAND_ACK, b.DIR_ROLL_CALL}), 4)

    def test_wake_keys(self):
        self.assertEqual(len(self.R["keys"]), 6)
        for v in self.R["keys"]:
            self.assertEqual((v["purpose"], v["label"], v["master"]), ("wake", "CID-LORA-WAK", mv.MASTER_COMMAND))
            inp = b.kdf_input("wake", v["group"], v["gen"])
            self.assertEqual(inp.hex(), v["input"], v["name"])
            self.assertEqual(inp, b"CID-LORA-WAK" + v["group"].to_bytes(4, "little") + bytes([v["gen"]]))
            key = b.kdf(hx(v["master"]), "wake", v["group"], v["gen"])
            self.assertEqual(key, b.cmac(hx(v["master"]), inp))
            self.assertEqual((key.hex(), b.kcv(key).hex()), (v["wake_key"], v["kcv"]), v["name"])
        self.assertEqual(len({v["wake_key"] for v in self.R["keys"]}), 6)     # group and gen both move the key

    def test_wake_key_is_its_own_family(self):
        m = hx(mv.MASTER_COMMAND)
        wake = b.kdf(m, "wake", 42, 1)
        self.assertNotEqual(wake, b.kdf(m, "command", 42, 1))     # a collar's command key with uid 42
        self.assertNotEqual(wake, b.kdf(m, "beacon", 42, 1))
        self.assertNotEqual(wake, b.kdf(hx(mv.MASTER_BEACON_A), "wake", 42, 1))
        # ... so a command key never opens a roll call, and a wake key never opens a command.
        rc = self.R["frames"][0]
        with self.assertRaises(b.AuthError):
            b.open_roll_call(b.kdf(m, "command", rc["group"], rc["gen"]), hx(rc["frame"]))
        c = VEC["commands"][0]
        with self.assertRaises(b.AuthError):
            b.open_command(b.kdf(m, "wake", c["uid"], c["gen"]), hx(c["frame"]))

    def test_frames_seal_and_open(self):
        frames = self.R["frames"]
        self.assertEqual(len(frames), 5)
        self.assertEqual([v["frame"] for v in frames], [c[-1] for c in mv.ROLL_CALL_CASES])   # the frozen frames
        for v in frames:
            frame, key = hx(v["frame"]), hx(v["wake_key"])
            self.assertEqual((len(frame), v["frame_len"]), (29, 29))
            self.assertEqual(b.classify(frame), "roll_call")
            self.assertEqual(b.peek_roll_call(frame), (v["group"], v["ctr"]))
            self.assertEqual(v["ctr"], (v["gen"] << 24) | v["seq"])
            self.assertEqual(frame[:9].hex(), v["aad"])
            self.assertEqual(frame[9:21].hex(), v["ct"])
            self.assertEqual(frame[21:].hex(), v["tag"])
            self.assertEqual(b.nonce(v["group"], v["ctr"], b.DIR_ROLL_CALL).hex(), v["nonce"])
            self.assertEqual(v["nonce"], frame[1:9].hex() + "03" + "00000000")
            self.assertEqual(b.pack_roll_call_body(v["valid_from"], v["valid_to"], v["slots"], v["slot_ms"],
                                                   v["flags"]).hex(), v["body"])
            self.assertEqual(b.seal_roll_call(key, v["group"], v["ctr"], v["valid_from"], v["valid_to"],
                                              v["slots"], v["slot_ms"], v["flags"]).hex(), v["frame"], v["name"])
            got = b.open_roll_call(key, frame)
            self.assertEqual(got, b.RollCall(v["group"], v["ctr"], v["gen"], v["seq"], v["valid_from"],
                                             v["valid_to"], v["slots"], v["slot_ms"], v["flags"]), v["name"])
            self.assertEqual(b.open_roll_call_with_master(hx(v["master"]), frame), got)
            self.assertEqual(b.kdf(hx(v["master"]), "wake", v["group"], v["gen"]).hex(), v["wake_key"])
            # old: v["slots"] * v["slot_ms"] + 200 (before the 300 ms the collar takes to answer)
            self.assertEqual(v["listen_ms"], 300 + v["slots"] * v["slot_ms"] + 200)
            self.assertEqual(v["listen_ms"], b.roll_call_listen_ms(v["slots"], v["slot_ms"]))
            # the plain construction, spelled out
            ct, tag = b.ccm_seal(key, frame[1:9] + b"\x03" + bytes(4), frame[:9], hx(v["body"]), 8)
            self.assertEqual(frame, frame[:9] + ct + tag)

    def test_tamper_every_bit_of_every_roll_call(self):
        rejected = 0
        for v in self.R["frames"]:
            key, frame = hx(v["wake_key"]), hx(v["frame"])
            for i in range(len(frame)):
                for bit in range(8):
                    t = bytearray(frame)
                    t[i] ^= 1 << bit
                    with self.assertRaises(ValueError if i == 0 else b.AuthError):
                        b.open_roll_call(key, bytes(t))
                    rejected += 1
        self.assertEqual(rejected, 5 * 29 * 8)

    def test_slot_choice(self):
        rows = self.R["slots"]
        self.assertEqual(len(rows), 30)
        for v in rows:
            slot = b.roll_call_slot(v["uid"], v["ctr"], v["slots"])
            self.assertEqual(slot, v["slot"])
            self.assertEqual(slot, b.send_phase_mix(v["uid"] ^ 0x57414B45 ^ v["ctr"]) % v["slots"])
            self.assertLess(slot, v["slots"])
            self.assertEqual(b.roll_call_reply_delay_ms(v["uid"], v["ctr"], v["slots"], v["slot_ms"]),
                             v["reply_delay_ms"])
            # old: 50 + ... (to 2026-11-13)
            self.assertEqual(v["reply_delay_ms"], 300 + v["slot"] * v["slot_ms"])
        # one slot: everybody answers in it; a new counter deals the slots again
        self.assertEqual({v["slot"] for v in rows if v["slots"] == 1}, {0})
        a = [v["slot"] for v in rows if v["slots"] == 64 and v["ctr"] == 0x01000001]
        c = [v["slot"] for v in rows if v["slots"] == 64 and v["ctr"] == 0x01000002]
        self.assertNotEqual(a, c)
        for bad in (0, 256):
            with self.assertRaises(ValueError):
                b.roll_call_slot(1, 1, bad)

    def test_slots_spread(self):
        # 1000 collars over 32 slots: every slot is used, none holds more than twice its share.
        counts = [0] * 32
        for i in range(1000):
            counts[b.roll_call_slot(0x7E600000 + i, 0x01000007, 32)] += 1
        self.assertGreater(min(counts), 0)
        self.assertLess(max(counts), 2 * 1000 // 32)

    def test_checks(self):
        checks = self.R["checks"]
        self.assertEqual(len(checks), 26)
        for v in checks:
            rc, reason = b.roll_call_check(hx(v["frame"]), hx(v["wake_key"]) if v["wake_key"] else None,
                                           v["group"], v["gen"], v["last_ctr"], v["now"], v["sf"], v["bw_khz"],
                                           v["since_answer_s"])
            self.assertEqual(reason, v["reason"], v["name"])
            self.assertEqual(rc is not None, v["accept"], v["name"])
            self.assertEqual(v["accept"], v["reason"] is None)
            if rc is not None:
                self.assertEqual((rc.ctr, rc.slots, rc.slot_ms), (v["ctr"], v["slots"], v["slot_ms"]))
                self.assertGreater(rc.ctr, v["last_ctr"])
        self.assertEqual({v["reason"] for v in checks if not v["accept"]}, set(b.ROLL_CALL_REFUSALS))
        self.assertEqual(sum(v["accept"] for v in checks), 7)
        # the five the task names: wrong group, wrong gen, stale counter, outside the window, bad tag
        for reason in ("group", "gen", "counter", "window", "tag"):
            self.assertTrue([v for v in checks if v["reason"] == reason], reason)

    def test_shortest_slot_per_setting(self):
        for s in VEC["wake_timing"]["settings"]:
            key = hx(self.R["keys"][0]["wake_key"])
            least = s["roll_slot_min_whole_ms"]
            for slot_ms, want in ((least - 1, "slot_ms"), (least, None), (s["roll_slot_default_ms"], None)):
                frame = b.seal_roll_call(key, 42, 0x01000001, 0, 0xFFFFFFFF, 32, slot_ms)
                _, reason = b.roll_call_check(frame, key, 42, 1, 0, 1794600000, s["sf"], s["bw_khz"])
                self.assertEqual(reason, want, (s["name"], slot_ms))
            # The default leaves the answer's airtime and 10 ms.
            self.assertGreaterEqual(s["roll_slot_default_ms"] * 1000, s["roll_slot_min_us"] + 5000)

    def test_the_answer_is_the_beacon(self):
        # A roll call's answer is the 30-byte v2 frame; its airtime is what a slot is sized from.
        self.assertEqual(b.ROLL_CALL_REPLY_LEN, b.LEN_V2)
        for s in VEC["wake_timing"]["settings"]:
            self.assertEqual(s["roll_slot_min_us"], b.lora_toa_us(s["sf"], s["bw_khz"], 30) + 5000)
            self.assertEqual(s["roll_wait_us"], 2 * b.lora_toa_us(s["sf"], s["bw_khz"], 29) + 150000)

    def test_field_ranges(self):
        key = bytes(16)
        for kw in ({"group": -1}, {"group": 1 << 32}, {"ctr": 1 << 32}, {"valid_from": 1 << 32},
                   {"valid_to": -1}, {"slots": 256}, {"slot_ms": 65536}, {"flags": 256}):
            args = dict(group=1, ctr=1, valid_from=0, valid_to=1, slots=1, slot_ms=100, flags=0)
            args.update(kw)
            with self.assertRaises(ValueError):
                b.seal_roll_call(key, **args)
        for bad in (b"", bytes(29), bytes([0x43]) + bytes(27), bytes([0x43]) + bytes(29), bytes([0x44]) + bytes(28)):
            with self.assertRaises(ValueError):
                b.peek_roll_call(bad)
            self.assertNotEqual(b.classify(bad), "roll_call")

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography not installed")
    def test_against_cryptography(self):
        for v in self.R["frames"]:
            frame = hx(v["frame"])
            pt = AESCCM(hx(v["wake_key"]), tag_length=8).decrypt(hx(v["nonce"]), frame[9:], frame[:9])
            self.assertEqual(pt.hex(), v["body"], v["name"])
        for v in self.R["keys"]:
            c = _cmac.CMAC(_alg.AES(hx(v["master"])))
            c.update(hx(v["input"]))
            self.assertEqual(c.finalize().hex(), v["wake_key"], v["name"])


class TestWakeVectorsFrozen(unittest.TestCase):
    """The wake sections were added (2026-11-13) without touching any earlier
    entry: the version is still 1 and the earlier sections keep their counts."""

    def test_sections_and_counts(self):
        self.assertEqual(VEC["version"], 1)
        self.assertEqual(list(VEC)[-4:], ["wake_tags", "wake_frames", "wake_timing", "roll_calls"])
        self.assertEqual({k: len(VEC[k]) for k in ("commands", "command_acks", "wake_tags", "wake_frames")},
                         {"commands": 3, "command_acks": 2, "wake_tags": 15, "wake_frames": 25})
        self.assertEqual(sorted(VEC["wake_timing"]), ["constants", "interval_clamp", "region_resolve", "regions",
                                                      "settings", "time_left"])
        self.assertEqual({k: len(v) for k, v in VEC["roll_calls"].items()},
                         {"keys": 6, "frames": 5, "slots": 30, "checks": 26})
        for k in ("wake", "wake_timing", "wake_key", "roll_call"):
            self.assertIn(k, VEC["layout"])

    def test_everything_is_synthetic(self):
        uids = [v["uid"] for v in VEC["wake_tags"] + VEC["roll_calls"]["slots"]]
        uids += [u for v in VEC["wake_frames"] if v["ok"] for u in v["uids"]]
        uids += [p["uid"] for v in VEC["wake_frames"] if v["ok"] for p in v["verdicts"]]
        for uid in uids:
            self.assertFalse(0 < (uid >> 16) < 0x100 and 0 < (uid & 0xFFFF) < 0x100, "uid looks real: %08x" % uid)
        for v in VEC["roll_calls"]["keys"] + VEC["roll_calls"]["frames"]:
            self.assertEqual(v["master"], mv.MASTER_COMMAND)


class TestWakeCli(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = b.main(argv)
        return rc, json.loads(out.getvalue())

    def test_wake_tag_and_parse(self):
        v = VEC["wake_tags"][0]
        rc, out = self.run_cli(["wake-tag", "0x%08X" % v["uid"], "0"])
        self.assertEqual((rc, out[0]["tag"], out[0]["tag_hex"], out[1]["tag"]), (0, v["tag"], v["tag_hex"], 0x0FC7))
        f = [x for x in VEC["wake_frames"] if x["ok"]][3]
        rc, out = self.run_cli(["wake-parse", f["frame"], "--uid", str(f["uids"][0])])
        self.assertEqual((rc, out["tags"], out["more"], out["time_left_ms"], out["verdict"]),
                         (0, f["tags"], True, f["time_left_ms"], "called"))
        bad = [x for x in VEC["wake_frames"] if not x["ok"]][5]
        rc, out = self.run_cli(["wake-parse", bad["frame"]])
        self.assertEqual((rc, out), (1, {"error": "not a wake frame", "reason": bad["refusal"]}))

    def test_wake_timing(self):
        rc, out = self.run_cli(["wake-timing", "--region", "US915"])
        self.assertEqual((rc, out["sf"], out["bw_khz"], out["frame_ms"], out["w_ms"], out["interval_s"]),
                         (0, 9, 500, 45.312, 56.408, 30))
        rc, out = self.run_cli(["wake-timing", "--region", "EU868", "--long", "--interval", "60"])
        self.assertEqual((out["sf"], out["frequency_hz"], out["train_ms"]), (10, 869525000, 62482.84))

    def test_roll_open_and_derive(self):
        v = VEC["roll_calls"]["frames"][0]
        rc, out = self.run_cli(["roll-open", "--key", v["wake_key"], v["frame"]])
        self.assertEqual((rc, out["group"], out["slots"], out["slot_ms"], out["valid_to"]),
                         (0, v["group"], v["slots"], v["slot_ms"], v["valid_to"]))
        rc, out = self.run_cli(["roll-open", "--master", v["master"], v["frame"]])
        self.assertEqual((rc, out["ctr"]), (0, v["ctr"]))
        rc, out = self.run_cli(["roll-open", "--key", "00" * 16, v["frame"]])
        self.assertEqual((rc, out["error"]), (1, "authentication failed"))
        rc, out = self.run_cli(["derive", "--master", v["master"], "--purpose", "wake",
                                "--uid", str(v["group"]), "--gen", str(v["gen"])])
        self.assertEqual((rc, out["key"], out["kcv"]), (0, v["wake_key"], v["kcv"]))


if __name__ == "__main__":
    unittest.main()
