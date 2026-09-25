#!/usr/bin/env python3
"""Generate beacon/vectors.json from the reference codec (beacon_v2.py).

    python3 make_vectors.py            rewrite vectors.json
    python3 make_vectors.py --check    exit 1 if vectors.json is stale

The file is FROZEN once published: every consumer (collar firmware host tests,
server tests, website tests, third-party receivers) pins it. A change here is a
wire-contract change and needs a new format version, never a silent rewrite.

Every master, key, uid and position below is synthetic. This repository is
public: nothing in it may identify a real collar, a real key or a real place.
The public known-answer vectors (FIPS-197 C.1, RFC 4493 examples 1-4, RFC 3610
packet vectors 1-24) are transcribed from the standards and re-derived by the
codec on every run; a transcription slip fails the run.

Standard library only. Deterministic: the same code gives the same bytes.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import beacon_v2 as b  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vectors.json")

FORMAT = "collarid-beacon-v2-vectors"
VERSION = 1

# ---------------------------------------------------------- public KATs

FIPS197_C1 = dict(name="FIPS-197 C.1 AES-128",
                  key="000102030405060708090a0b0c0d0e0f",
                  pt="00112233445566778899aabbccddeeff",
                  ct="69c4e0d86a7b0430d8cdb78070b4c55a")

RFC4493_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
RFC4493_MSG = ("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
RFC4493 = [
    dict(name="RFC 4493 example 1 (empty)", key=RFC4493_KEY, msg="",
         mac="bb1d6929e95937287fa37d129b756746"),
    dict(name="RFC 4493 example 2 (16 B)", key=RFC4493_KEY, msg=RFC4493_MSG[:32],
         mac="070a16b46b4d4144f79bdd9dd04a287c"),
    dict(name="RFC 4493 example 3 (40 B)", key=RFC4493_KEY, msg=RFC4493_MSG[:80],
         mac="dfa66747de9ae63030ca32611497c827"),
    dict(name="RFC 4493 example 4 (64 B)", key=RFC4493_KEY, msg=RFC4493_MSG,
         mac="51f0bebf7e3b9d92fc49741779363cfe"),
]

RFC3610_VECTORS = [
    dict(name='RFC 3610 packet vector 1',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000003020100a0a1a2a3a4a5',
         aad='0001020304050607',
         pt='08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
         tag_len=8,
         ct='588c979a61c663d2f066d0c2c0f989806d5f6b61dac384',
         tag='17e8d12cfdf926e0'),
    dict(name='RFC 3610 packet vector 2',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000004030201a0a1a2a3a4a5',
         aad='0001020304050607',
         pt='08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
         tag_len=8,
         ct='72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b',
         tag='a091d56e10400916'),
    dict(name='RFC 3610 packet vector 3',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000005040302a0a1a2a3a4a5',
         aad='0001020304050607',
         pt='08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
         tag_len=8,
         ct='51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da859657',
         tag='4adaa76fbd9fb0c5'),
    dict(name='RFC 3610 packet vector 4',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000006050403a0a1a2a3a4a5',
         aad='000102030405060708090a0b',
         pt='0c0d0e0f101112131415161718191a1b1c1d1e',
         tag_len=8,
         ct='a28c6865939a9a79faaa5c4c2a9d4a91cdac8c',
         tag='96c861b9c9e61ef1'),
    dict(name='RFC 3610 packet vector 5',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000007060504a0a1a2a3a4a5',
         aad='000102030405060708090a0b',
         pt='0c0d0e0f101112131415161718191a1b1c1d1e1f',
         tag_len=8,
         ct='dcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e',
         tag='51e83f077d9c2d93'),
    dict(name='RFC 3610 packet vector 6',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000008070605a0a1a2a3a4a5',
         aad='000102030405060708090a0b',
         pt='0c0d0e0f101112131415161718191a1b1c1d1e1f20',
         tag_len=8,
         ct='6fc1b011f006568b5171a42d953d469b2570a4bd87',
         tag='405a0443ac91cb94'),
    dict(name='RFC 3610 packet vector 7',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='00000009080706a0a1a2a3a4a5',
         aad='0001020304050607',
         pt='08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
         tag_len=10,
         ct='0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c',
         tag='048c56602c97acbb7490'),
    dict(name='RFC 3610 packet vector 8',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='0000000a090807a0a1a2a3a4a5',
         aad='0001020304050607',
         pt='08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
         tag_len=10,
         ct='7b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24',
         tag='c17b4433f434963f34b4'),
    dict(name='RFC 3610 packet vector 9',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='0000000b0a0908a0a1a2a3a4a5',
         aad='0001020304050607',
         pt='08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
         tag_len=10,
         ct='82531a60cc24945a4b8279181ab5c84df21ce7f9b73f42e197',
         tag='ea9c07e56b5eb17e5f4e'),
    dict(name='RFC 3610 packet vector 10',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='0000000c0b0a09a0a1a2a3a4a5',
         aad='000102030405060708090a0b',
         pt='0c0d0e0f101112131415161718191a1b1c1d1e',
         tag_len=10,
         ct='07342594157785152b074098330abb141b947b',
         tag='566aa9406b4d999988dd'),
    dict(name='RFC 3610 packet vector 11',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='0000000d0c0b0aa0a1a2a3a4a5',
         aad='000102030405060708090a0b',
         pt='0c0d0e0f101112131415161718191a1b1c1d1e1f',
         tag_len=10,
         ct='676bb20380b0e301e8ab79590a396da78b834934',
         tag='f53aa2e9107a8b6c022c'),
    dict(name='RFC 3610 packet vector 12',
         key='c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
         nonce='0000000e0d0c0ba0a1a2a3a4a5',
         aad='000102030405060708090a0b',
         pt='0c0d0e0f101112131415161718191a1b1c1d1e1f20',
         tag_len=10,
         ct='c0ffa0d6f05bdb67f24d43a4338d2aa4bed7b20e43',
         tag='cd1aa31662e7ad65d6db'),
    dict(name='RFC 3610 packet vector 13',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='00412b4ea9cdbe3c9696766cfa',
         aad='0be1a88bace018b1',
         pt='08e8cf97d820ea258460e96ad9cf5289054d895ceac47c',
         tag_len=8,
         ct='4cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8',
         tag='e78cf7cb0cddd7b3'),
    dict(name='RFC 3610 packet vector 14',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='0033568ef7b2633c9696766cfa',
         aad='63018f76dc8a1bcb',
         pt='9020ea6f91bdd85afa0039ba4baff9bfb79c7028949cd0ec',
         tag_len=8,
         ct='4ccb1e7ca981befaa0726c55d378061298c85c92814abc33',
         tag='c52ee81d7d77c08a'),
    dict(name='RFC 3610 packet vector 15',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='00103fe41336713c9696766cfa',
         aad='aa6cfa36cae86b40',
         pt='b916e0eacc1c00d7dcec68ec0b3bbb1a02de8a2d1aa346132e',
         tag_len=8,
         ct='b1d23a2220ddc0ac900d9aa03c61fcf4a559a4417767089708',
         tag='a776796edb723506'),
    dict(name='RFC 3610 packet vector 16',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='00764c63b8058e3c9696766cfa',
         aad='d0d0735c531e1becf049c244',
         pt='12daac5630efa5396f770ce1a66b21f7b2101c',
         tag_len=8,
         ct='14d253c3967b70609b7cbb7c49916028324526',
         tag='9a6f49975bcadeaf'),
    dict(name='RFC 3610 packet vector 17',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='00f8b678094e3b3c9696766cfa',
         aad='77b60f011c03e1525899bcae',
         pt='e88b6a46c78d63e52eb8c546efb5de6f75e9cc0d',
         tag_len=8,
         ct='5545ff1a085ee2efbf52b2e04bee1e2336c73e3f',
         tag='762c0c7744fe7e3c'),
    dict(name='RFC 3610 packet vector 18',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='00d560912d3f703c9696766cfa',
         aad='cd9044d2b71fdb8120ea60c0',
         pt='6435acbafb11a82e2f071d7ca4a5ebd93a803ba87f',
         tag_len=8,
         ct='009769ecabdf48625594c59251e6035722675e04c8',
         tag='47099e5ae0704551'),
    dict(name='RFC 3610 packet vector 19',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='0042fff8f1951c3c9696766cfa',
         aad='d85bc7e69f944fb8',
         pt='8a19b950bcf71a018e5e6701c91787659809d67dbedd18',
         tag_len=10,
         ct='bc218daa947427b6db386a99ac1aef23ade0b52939cb6a',
         tag='637cf9bec2408897c6ba'),
    dict(name='RFC 3610 packet vector 20',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='00920f40e56cdc3c9696766cfa',
         aad='74a0ebc9069f5b37',
         pt='1761433c37c5a35fc1f39f406302eb907c6163be38c98437',
         tag_len=10,
         ct='5810e6fd25874022e80361a478e3e9cf484ab04f447efff6',
         tag='f0a477cc2fc9bf548944'),
    dict(name='RFC 3610 packet vector 21',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='0027ca0c7120bc3c9696766cfa',
         aad='44a3aa3aae6475ca',
         pt='a434a8e58500c6e41530538862d686ea9e81301b5ae4226bfa',
         tag_len=10,
         ct='f2beed7bc5098e83feb5b31608f8e29c38819a89c8e776f154',
         tag='4d4151a4ed3a8b87b9ce'),
    dict(name='RFC 3610 packet vector 22',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='005b8ccbcd9af83c9696766cfa',
         aad='ec46bb63b02520c33c49fd70',
         pt='b96b49e21d621741632875db7f6c9243d2d7c2',
         tag_len=10,
         ct='31d750a09da3ed7fddd49a2032aabf17ec8ebf',
         tag='7d22c8088c666be5c197'),
    dict(name='RFC 3610 packet vector 23',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='003ebe94044b9a3c9696766cfa',
         aad='47a65ac78b3d594227e85e71',
         pt='e2fcfbb880442c731bf95167c8ffd7895e337076',
         tag_len=10,
         ct='e882f1dbd38ce3eda7c23f04dd65071eb41342ac',
         tag='df7e00dccec7ae52987d'),
    dict(name='RFC 3610 packet vector 24',
         key='d7828d13b2b0bdc325a76236df93cc6b',
         nonce='008d493b30ae8b3c9696766cfa',
         aad='6e37a6ef546d955d34ab6059',
         pt='abf21c0b02feb88f856df4a37381bce3cc128517d4',
         tag_len=10,
         ct='f32905b88a641b04b9c9ffb58cc390900f3da12ab1',
         tag='6dce9e82efa16da62059'),
]

# ------------------------------------------------------- synthetic inputs

# Obviously synthetic 16-byte masters (patterns, never random-looking).
MASTER_BEACON_A = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
MASTER_BEACON_B = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
MASTER_COMMAND = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"

# Synthetic on-air uids. Real CollarID uids are STM32 UIDw0 wafer coordinates
# (small numbers in both halves); none of these has that shape.
UID_TEST = 0x7E57C0DE
UID_ZERO = 0x00000000
UID_ONES = 0xFFFFFFFF
UID_MSB = 0x80000000
UID_BAD = 0x0BADF00D

KDF_CASES = [
    # name, master, purpose, uid, gen
    ("beacon gen 1", MASTER_BEACON_A, "beacon", UID_TEST, 1),
    ("beacon gen 2 (re-provisioned: a different key)", MASTER_BEACON_A, "beacon", UID_TEST, 2),
    ("beacon gen 255 (last generation under this master)", MASTER_BEACON_A, "beacon", UID_TEST, 255),
    ("beacon uid 0", MASTER_BEACON_A, "beacon", UID_ZERO, 1),
    ("beacon uid 0xFFFFFFFF", MASTER_BEACON_A, "beacon", UID_ONES, 1),
    ("beacon, other master", MASTER_BEACON_B, "beacon", UID_TEST, 1),
    ("command gen 1, command master", MASTER_COMMAND, "command", UID_TEST, 1),
    ("command label under the BEACON master (label separation only)", MASTER_BEACON_A, "command", UID_TEST, 1),
]

# Frames: (name, master, uid, gen, seq, lat_e7, lon_e7, fix_epoch, batt_pct).
# Positions are round synthetic numbers; epochs are in 2027 or the extremes.
FRAME_CASES = [
    ("nominal", MASTER_BEACON_A, UID_TEST, 1, 0x000001, 450000000, -900000000, 1800000000, 77),
    ("gen boundary: gen 1, seq 0 (ctr 0x01000000)", MASTER_BEACON_A, UID_TEST, 1, 0x000000, 450000000, -900000000, 1800000000, 77),
    ("seq max: gen 1, seq 0xFFFFFF", MASTER_BEACON_A, UID_TEST, 1, 0xFFFFFF, 450000000, -900000000, 1800000000, 77),
    ("gen 255, mid sequence", MASTER_BEACON_A, UID_TEST, 255, 0x123456, 450000000, -900000000, 1800000000, 77),
    ("gen 2 (re-provisioned, same seq as nominal)", MASTER_BEACON_A, UID_TEST, 2, 0x000001, 450000000, -900000000, 1800000000, 77),
    ("negative extremes: south pole, antimeridian", MASTER_BEACON_A, UID_TEST, 1, 0x000002, -900000000, -1800000000, 1767225600, 0),
    ("positive extremes: north pole, antimeridian", MASTER_BEACON_A, UID_TEST, 1, 0x000003, 900000000, 1800000000, 4294967295, 100),
    ("null island, epoch 1, batt 1", MASTER_BEACON_A, UID_TEST, 1, 0x000004, 0, 0, 1, 1),
    ("small negatives, batt 255 (u8 on the wire, firmware clamps to 100)", MASTER_BEACON_A, UID_TEST, 1, 0x000005, -1, 1, 1800000000, 255),
    ("uid 0", MASTER_BEACON_A, UID_ZERO, 1, 0x000001, 123456789, -987654321, 1800000000, 50),
    ("uid 0xFFFFFFFF", MASTER_BEACON_A, UID_ONES, 1, 0x000001, 123456789, -987654321, 1800000000, 50),
    ("uid msb set", MASTER_BEACON_A, UID_MSB, 7, 0x0F0F0F, -123456789, 987654321, 1800000000, 50),
    ("same uid, ctr and body as nominal under master B", MASTER_BEACON_B, UID_TEST, 1, 0x000001, 450000000, -900000000, 1800000000, 77),
    ("second collar", MASTER_BEACON_A, UID_BAD, 3, 0x00ABCD, 351234567, 1391234567, 1800086400, 33),
]

V1_CASES = [
    ("nominal", UID_TEST, 450000000, -900000000, 1800000000, 77),
    ("negative extremes", UID_TEST, -900000000, -1800000000, 1767225600, 0),
    ("positive extremes, uid 0xFFFFFFFF", UID_ONES, 900000000, 1800000000, 4294967295, 100),
]


def hx(bs):
    return bytes(bs).hex()


def build():
    aes = []
    v = FIPS197_C1
    got = b.AES128(bytes.fromhex(v["key"])).encrypt_block(bytes.fromhex(v["pt"]))
    assert got.hex() == v["ct"], "FIPS-197 C.1 transcription"
    aes.append(dict(v))

    cmac = []
    for v in RFC4493:
        got = b.cmac(bytes.fromhex(v["key"]), bytes.fromhex(v["msg"]))
        assert got.hex() == v["mac"], v["name"]
        cmac.append(dict(v))

    ccm = []
    for v in RFC3610_VECTORS:
        ct, tag = b.ccm_seal(bytes.fromhex(v["key"]), bytes.fromhex(v["nonce"]),
                             bytes.fromhex(v["aad"]), bytes.fromhex(v["pt"]), v["tag_len"])
        assert ct.hex() == v["ct"] and tag.hex() == v["tag"], v["name"]
        pt = b.ccm_open(bytes.fromhex(v["key"]), bytes.fromhex(v["nonce"]),
                        bytes.fromhex(v["aad"]), ct, tag, v["tag_len"])
        assert pt.hex() == v["pt"], v["name"]
        ccm.append(dict(v))

    kdf = []
    for name, master, purpose, uid, gen in KDF_CASES:
        key = b.kdf(bytes.fromhex(master), purpose, uid, gen)
        kdf.append(dict(name=name, master=master, purpose=purpose,
                        label=b.PURPOSES[purpose].decode("ascii"), uid=uid,
                        uid_hex="%08x" % uid, gen=gen,
                        input=hx(b.kdf_input(purpose, uid, gen)),
                        dev_key=hx(key), kcv=hx(b.kcv(key))))

    frames = []
    for name, master, uid, gen, seq, lat, lon, epoch, batt in FRAME_CASES:
        ctr = b.ctr_make(gen, seq)
        key = b.kdf(bytes.fromhex(master), "beacon", uid, gen)
        frame = b.seal(key, uid, ctr, lat, lon, epoch, batt)
        got = b.open_frame(key, frame)
        assert (got.uid, got.ctr, got.lat_e7, got.lon_e7, got.fix_epoch, got.batt_pct) == \
               (uid, ctr, lat, lon, epoch, batt), name
        assert b.open_with_master(bytes.fromhex(master), frame) == got, name
        frames.append(dict(name=name, master=master, uid=uid, uid_hex="%08x" % uid,
                           gen=gen, seq=seq, ctr=ctr, ctr_hex="%08x" % ctr,
                           lat_e7=lat, lon_e7=lon, fix_epoch=epoch, batt_pct=batt,
                           dev_key=hx(key), kcv=hx(b.kcv(key)),
                           nonce=hx(b.nonce(uid, ctr)), aad=hx(frame[:b.AAD_LEN]),
                           body=hx(b.pack_body(lat, lon, epoch, batt)),
                           ct=hx(frame[b.AAD_LEN:b.AAD_LEN + b.BODY_LEN]),
                           tag=hx(frame[b.AAD_LEN + b.BODY_LEN:]), frame=hx(frame)))

    v1 = []
    for name, uid, lat, lon, epoch, batt in V1_CASES:
        frame = b.encode_v1(uid, lat, lon, epoch, batt)
        got = b.decode_v1(frame)
        assert (got.uid, got.lat_e7, got.lon_e7, got.fix_epoch, got.batt_pct) == (uid, lat, lon, epoch, batt)
        v1.append(dict(name=name, uid=uid, uid_hex="%08x" % uid, lat_e7=lat, lon_e7=lon,
                       fix_epoch=epoch, batt_pct=batt, frame=hx(frame)))

    return {
        "format": FORMAT,
        "version": VERSION,
        "generator": "CollarID_protobufs beacon/make_vectors.py from beacon/beacon_v2.py",
        "note": "Frozen. All masters, keys, uids and positions are synthetic. "
                "Hex is lower-case; integers are decimal (uid/ctr also as *_hex).",
        "layout": {
            "v2": "[0]=0x4D [1..4]=uid_le32 [5..8]=ctr_le32 (gen=ctr>>24, seq=ctr&0xFFFFFF) "
                  "[9..21]=CCM ciphertext of body [22..29]=8-byte tag; AAD=[0..8]; "
                  "nonce=uid_le32||ctr_le32||0x00||0x00000000; AES-128-CCM L=2 M=8",
            "body": "lat_e7 i32le || lon_e7 i32le || fix_epoch u32le || batt_pct u8 (13 B, = v1 [5..17])",
            "v1": "[0]=0x4C [1..4]=uid_le32 [5..17]=body (18 B plaintext)",
            "kdf": "dev_key = AES-CMAC(master, label(12 ASCII) || uid_le32 || gen); "
                   "labels CID-LORA-BCN (beacon), CID-LORA-CMD (command)",
            "kcv": "AES(key, 0^16)[0..2]",
        },
        "aes128": aes,
        "cmac": cmac,
        "ccm": ccm,
        "kdf": kdf,
        "frames": frames,
        "v1": v1,
    }


def render(doc):
    return json.dumps(doc, indent=1) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true", help="exit 1 if vectors.json is stale")
    p.add_argument("--out", default=OUT)
    a = p.parse_args(argv)
    text = render(build())
    if a.check:
        try:
            with open(a.out, encoding="utf-8") as fh:
                cur = fh.read()
        except FileNotFoundError:
            cur = None
        if cur != text:
            print("%s is stale; run make_vectors.py" % a.out, file=sys.stderr)
            return 1
        print("%s is up to date" % a.out)
        return 0
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    d = json.loads(text)
    print("wrote %s: %d aes, %d cmac, %d ccm, %d kdf, %d frames, %d v1" % (
        a.out, len(d["aes128"]), len(d["cmac"]), len(d["ccm"]), len(d["kdf"]), len(d["frames"]), len(d["v1"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
