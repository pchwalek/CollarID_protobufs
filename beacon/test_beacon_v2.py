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


# ---------------------------------------------------------- frozen vectors

class TestVectorsFrozen(unittest.TestCase):
    def test_file_is_what_the_generator_makes(self):
        with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), mv.render(mv.build()))

    def test_format_and_counts(self):
        self.assertEqual((VEC["format"], VEC["version"]), ("collarid-beacon-v2-vectors", 1))
        self.assertEqual({k: len(VEC[k]) for k in ("aes128", "cmac", "ccm", "kdf", "frames", "v1")},
                         {"aes128": 1, "cmac": 4, "ccm": 24, "kdf": 8, "frames": 14, "v1": 3})

    def test_everything_is_synthetic(self):
        masters = {mv.MASTER_BEACON_A, mv.MASTER_BEACON_B, mv.MASTER_COMMAND}
        for v in VEC["kdf"] + VEC["frames"]:
            self.assertIn(v["master"], masters)
        # Real CollarID uids are STM32 UIDw0 wafer coordinates: both 16-bit
        # halves small. None of the synthetic uids has that shape.
        for v in VEC["kdf"] + VEC["frames"] + VEC["v1"]:
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


if __name__ == "__main__":
    unittest.main()
