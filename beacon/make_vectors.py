#!/usr/bin/env python3
"""Generate beacon/vectors.json from the reference codec (beacon_v2.py).

    python3 make_vectors.py            rewrite vectors.json
    python3 make_vectors.py --check    exit 1 if vectors.json is stale

The file is FROZEN once published: every consumer (collar firmware host tests,
server tests, website tests, third-party receivers) pins it. A change here is a
wire-contract change and needs a new format version, never a silent rewrite.
A new frame kind may ADD a section without touching an existing entry: the
sealed reports (`reports`, 2026-09-30) were added that way, so the version
stays 1 and every earlier vector is byte for byte what it was.

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

# Sealed reports (0x52), added 2026-09-30 and frozen as first published:
# implementations were built against exactly these frames, so the generator
# re-seals each one and refuses to write a file in which any of them moved.
# (name, master, uid, gen, seq, dev_key, kcv, payload hex, frozen frame hex).
# The payloads are synthetic bytes, not a real report: R1 a short string
# behind a 0x0A byte, R2 the single byte every plaintext report starts with,
# R3 the 238 B maximum as a counting pattern.
UID_REPORT_1 = 0x7E570001
UID_REPORT_2 = 0x7E570002
UID_REPORT_3 = 0x7E570003
REPORT_R3_PAYLOAD = bytes((0x0B + 0x25 * i) & 0xFF for i in range(238)).hex()
REPORT_CASES = [
    ("R1 short report", MASTER_BEACON_A, UID_REPORT_1, 1, 1,
     "30e18c9619028cec318538840698b739", "0d5236",
     "0a0c08011095b6f8f40618dc05200128636f6c6c6172207265706f7274207632",
     "520100577e010000018a8461c8ab41c1b6c8089f19a0d8a5dbdc6fcfd4ca6e3226fde9b450129dfb85907e88296a89970b"),
    ("R2 one byte", MASTER_BEACON_A, UID_REPORT_2, 2, 11259375,
     "08208f96ffa5c4307b75f62031e882b3", "b69253",
     "0a",
     "520200577eefcdab028f148285f7c79f5c83"),
    ("R3 maximum 238 B", MASTER_BEACON_A, UID_REPORT_3, 255, 16777214,
     "d68f086277038ed567d4f67363a24c4b", "27bfa0",
     REPORT_R3_PAYLOAD,
     "520300577efeffffff4bfb8bb6a91d66aec725f747a1ba7f2147195d0f20488e90cb3b0526eaed1a5c9c5b32394faad2ae9836f6c7"
     "d204b1b499e6a3e57d15369384b2a8f68609fec5a8ff39dd0438d7d29c6a0d8f44adad34d9959a3999f5d0a02f0baa86f0cdc09bfb"
     "cb80a1b5c2bf6112587aaa9961777aa999ec6da2af26389b564841ec8d9e352689d2807b4d78c8ea921e495e6514e1a579e0de618c"
     "e40275587df90616b24475121b935753bb36c4751f38e80ea31572491a9eeb69330207c148574ae34fde48b1441695ad63d4b6d5d1"
     "0e4b48c4c3a0199a478d03907a38bdb8d73124aa723a7dcbcbe2598c502b938b0e4a6647cea8b1646d70d6"),
]

# Signed handheld commands (0x44) and their acknowledgements (0x4B), added
# 2026-11-11 as new sections (the version stays 1). Frozen as first
# published, like the reports. (name, uid, gen, seq, echo, valid_from,
# valid_to, DownlinkPacket hex, frozen frame hex), all under MASTER_COMMAND.
# C1 a pre-signed detach "ARM 600 s after receipt" with a two-week window
# (command=13, addon_arm_delay_s=600); C2 a live SESSION_OPEN bound to echo
# 173 (command=23, session {max_s 60, idle_s 6, min_sf 7}); C3 the 226 B
# maximum body as a counting pattern (synthetic, not a DownlinkPacket).
UID_COMMAND_1 = 0x7E570011
UID_COMMAND_2 = 0x7E570012
UID_COMMAND_3 = 0x7E570013
COMMAND_C3_BODY = bytes((0x0D + 0x2B * i) & 0xFF for i in range(226)).hex()
COMMAND_CASES = [
    ("C1 pre-signed detach, windowed", UID_COMMAND_1, 1, 1, 0, 1794000000, 1795209600,
     "100d70d804",
     "441100577e01000001920987c85ed7d120025e2f582649517a7158e61a64e9bb7d2d"),
    ("C2 live session open, echo-bound", UID_COMMAND_2, 2, 42, 173, 0, 0,
     "10176206083c10061807",
     "441200577e2a000002746c54fa4089925852b4652702969e25b363507eaf3848f58b49a47339e6"),
    ("C3 maximum 226 B body", UID_COMMAND_3, 255, 16777214, 0, 1, 4294967295,
     COMMAND_C3_BODY,
     "441300577efeffffff2643f7ea61aaaf3cc490408055195297e16e41ebf12d4ead00b968133bd6b68fe44fb4001b3a8536447c2b2e"
     "190a832e8ecd99c58255c3e199f232d0121e3390c3a634dd85bd2a00ed20b0e7b3e205e8e8b0af7ca90562d3415d88544bda4d28c0"
     "9f1b9253256481742e9e3a522cda3af28ca25ee1ee44e680f1e99cb9813e0487703a64a87a2006693257477e4d80077d4780416374"
     "20ff9ca694e022b181ab6b9ec78b7af989b897ef61b2d739c998d622158eb8b8682178ad0548c14c96f2508a791424f07eaf806634"
     "038f63b8909b1e26dc239949d9bd57af0d1c8e561961250de877a77bccbc459ed8b112d5d8d666be8320b3"),
]
# (name, uid, gen, seq, result, command, detail, rssi, snr_q4, frozen frame hex)
COMMAND_ACK_CASES = [
    ("K1 accepted the C1 detach", UID_COMMAND_1, 1, 1, 1, 13, 600, -42, 30,
     "4b1100577e010000012d6625ed0eb60a0fe5041aada0b46fa2"),
    ("K2 session opened at SF7", UID_COMMAND_2, 2, 42, 9, 23, 7, -97, -29,
     "4b1200577e2a000002b24e13f8d37bd4271f05ee0ecfad61b3"),
]

# LoRa wake, added 2026-11-13 as four new sections (the version stays 1):
# wake_tags, wake_frames, wake_timing and roll_calls. Collar firmware, the
# Handheld Receiver, the server, the website and the app all test against
# them (collarID_thread docs/CONTRACT_lora_wake.md section 11).

# Eight synthetic collars, what one train can call.
UID_WAKE = [0x7E570021 + i for i in range(8)]
UID_SALT = 0x57414B45              # a uid equal to the tag's salt: its tag is 0
UID_TWIN = 0x7E5AE4D9              # shares UID_WAKE[0]'s tag (the first such uid from 0x7E580000 up)
# (name, uid, tag): the tag is pinned here so a change of the mix fails the run.
WAKE_TAG_CASES = [
    ("nominal", UID_TEST, 0xB6B2),
    ("uid 0", UID_ZERO, 0x0FC7),
    ("uid 0xFFFFFFFF", UID_ONES, 0x573E),
    ("uid msb set", UID_MSB, 0x7BF5),
    ("second collar", UID_BAD, 0xE591),
    ("uid equal to the salt 'WAKE': tag 0", UID_SALT, 0x0000),
    ("train collar 1", UID_WAKE[0], 0x67FB),
    ("train collar 2", UID_WAKE[1], 0x9869),
    ("train collar 3", UID_WAKE[2], 0x20C3),
    ("train collar 4", UID_WAKE[3], 0xD257),
    ("train collar 5", UID_WAKE[4], 0xCD14),
    ("train collar 6", UID_WAKE[5], 0xC140),
    ("train collar 7", UID_WAKE[6], 0x809C),
    ("train collar 8", UID_WAKE[7], 0xB41D),
    ("another collar with train collar 1's tag (1 in 65,536)", UID_TWIN, 0x67FB),
]

# The collars each wake frame vector is read by, to pin the verdicts.
WAKE_PROBES = [UID_WAKE[0], UID_WAKE[4], UID_WAKE[7], UID_TWIN, UID_TEST]
# (name, uids called, time left in 10 ms units, more, long range, roll, frozen frame hex)
WAKE_FRAME_CASES = [
    ("one collar", UID_WAKE[:1], 3012, False, False, False,
     "5700c40b01fb67"),
    ("four collars, the most one frame names", UID_WAKE[:4], 1500, False, False, False,
     "5700dc0504fb676998c32057d2"),
    ("eight collars, list A: the first four, MORE", UID_WAKE[:4], 1005, True, False, False,
     "5701ed0304fb676998c32057d2"),
    ("eight collars, list B: the other four, MORE", UID_WAKE[4:], 1000, True, False, False,
     "5701e8030414cd40c19c801db4"),
    ("five collars, list B: the fifth alone, MORE", UID_WAKE[4:5], 59, True, False, False,
     "57013b000114cd"),
    ("the last frame of a train: time left 0", UID_WAKE[:2], 0, False, False, False,
     "5700000002fb676998"),
    ("long range, two collars", UID_WAKE[6:], 6248, False, True, False,
     "57026818029c801db4"),
    ("eight collars at long range, list A (MORE and LONG)", UID_WAKE[:4], 96, True, True, False,
     "5703600004fb676998c32057d2"),
    ("a roll-call train: ROLL, no tags", [], 3101, False, False, True,
     "57041d0c00"),
    ("the last frame of a roll-call train at long range", [], 0, False, True, True,
     "5706000000"),
    ("time left at its largest, 655.35 s", UID_WAKE[7:], 65535, False, False, False,
     "5700ffff011db4"),
    ("a collar whose tag is 0", [UID_SALT], 250, False, False, False,
     "5700fa00010000"),
]
# (name, frame hex, the reason a collar ignores it)
WAKE_MALFORMED_CASES = [
    ("nothing", "", "length"),
    ("four bytes: no room for the tag count", "5700c40b", "length"),
    ("fourteen bytes: four tags and one byte over", "5700dc0504fb676998c32057d200", "length"),
    ("magic 0x56", "5600c40b01fb67", "magic"),
    ("a command's magic, 0x44", "4400c40b01fb67", "magic"),
    ("reserved flag bit 3 set", "5708c40b01fb67", "reserved_flags"),
    ("reserved flag bit 7 set beside MORE", "5781c40b01fb67", "reserved_flags"),
    ("five tags declared", "5700dc0505fb676998c32057d2", "tag_count"),
    ("two tags declared, one sent", "5700c40b02fb67", "tag_bytes"),
    ("one tag declared, two sent", "5700c40b01fb676998", "tag_bytes"),
    ("no tags and no ROLL", "5700c40b00", "no_tags"),
    ("ROLL with a tag", "5704c40b01fb67", "roll_with_tags"),
    ("ROLL with MORE", "5705c40b00", "roll_with_more"),
]

# Roll calls. Groups are the owner's account number on the server: small
# numbers, and the two ends of the range.
GROUP_A = 42
GROUP_B = 43
GROUP_ONE = 1
GROUP_MAX = 0xFFFFFFFF
# (name, group, gen): wake keys, all under MASTER_COMMAND
WAKE_KEY_CASES = [
    ("wake key, group 42, gen 1", GROUP_A, 1),
    ("the same group re-keyed: gen 2", GROUP_A, 2),
    ("gen 255, the last under a master", GROUP_A, 255),
    ("another group", GROUP_B, 1),
    ("group 1", GROUP_ONE, 1),
    ("group 0xFFFFFFFF", GROUP_MAX, 255),
]
ROLL_FROM = 1794000000             # as command C1: a two-week window
ROLL_TO = 1795209600
# (name, group, gen, seq, valid_from, valid_to, slots, slot_ms, flags, frozen frame hex)
ROLL_CALL_CASES = [
    ("RC1 US915 / AU915 standard: 32 slots of 67 ms", GROUP_A, 1, 1, ROLL_FROM, ROLL_TO, 32, 67, 0,
     "432a000000010000011bccfc937bd3c7a0abec677fa77420b02bb5c075"),
    ("RC2 EU868 standard: 32 slots of 82 ms", GROUP_A, 1, 2, ROLL_FROM, ROLL_TO, 32, 82, 0,
     "432a0000000200000186253ca5b92856c41a5badcd6b94a72781981406"),
    ("RC3 EU868 long range: 64 slots of 463 ms, the group's gen 2", GROUP_A, 2, 256, ROLL_FROM, ROLL_TO, 64, 463, 0,
     "432a00000000010002a773bfc26432e50ff79bf104687ba79becd964ff"),
    ("RC4 the first counter of a generation, group 1, one slot", GROUP_ONE, 1, 0, ROLL_FROM, ROLL_TO, 1, 67, 0,
     "4301000000000000019516be8fff120763c2b72968a4d0d1a52330bb32"),
    ("RC5 every field at its largest", GROUP_MAX, 255, 16777215, 4294967295, 4294967295, 255, 65535, 255,
     "43ffffffffffffffff0c5996b5c4cab10c0769270ef015f86849edb915"),
]
ROLL_NOW = 1794600000              # a moment inside the window

# The four wake settings, with the table of CONTRACT_lora_wake.md section 3
# pinned beside them: a frame and the listen window W to 0.1 ms, the cap to
# the millisecond. (name, regions, long range, SF, kHz, frame, W, cap)
WAKE_SETTING_CASES = [
    ("US915 / AU915 standard: SF9 at 500 kHz", [b.DIRECT_REGION_US915, b.DIRECT_REGION_AU915], False, 9, 500,
     45.3, 56.4, 88),
    ("EU868 standard: SF7 at 125 kHz", [b.DIRECT_REGION_EU868], False, 7, 125,
     50.4, 61.5, 96),
    ("US915 / AU915 long range: SF12 at 500 kHz", [b.DIRECT_REGION_US915, b.DIRECT_REGION_AU915], True, 12, 500,
     321.5, 361.3, 502),
    ("EU868 long range: SF10 at 125 kHz", [b.DIRECT_REGION_EU868], True, 10, 125,
     321.5, 361.3, 502),
]
WAKE_TRAIN_INTERVALS = (1, 2, 5, 10, 30, 60, 120)      # 1 and 2 s are the call windows' trains
WAKE_TOA_SAMPLES = ((13, 12), (13, 8), (14, 8), (29, 8), (30, 8), (255, 8))   # (bytes, preamble symbols)
# (name, setting, LoRaWAN region or None when LoRaWAN is not configured,
#  the direct radio's frequency in MHz, the region that results; 0 = none)
REGION_RESOLVE_CASES = [
    ("set to US915", 1, None, 0, 1),
    ("set to EU868, whatever LoRaWAN and the frequency say", 2, 0, 915, 2),
    ("set to AU915", 3, None, 915, 3),
    ("AUTO, LoRaWAN US915: LoRaWAN decides, not the frequency", 0, 0, 868, 1),
    ("AUTO, LoRaWAN AU915 (LoRaWAN's number 1 is direct region 3)", 0, 1, 915, 3),
    ("AUTO, LoRaWAN EU868 (LoRaWAN's number 2 is direct region 2)", 0, 2, 915, 2),
    ("AUTO, no LoRaWAN, 915 MHz", 0, None, 915, 1),
    ("AUTO, no LoRaWAN, 868 MHz", 0, None, 868, 2),
    ("AUTO, no LoRaWAN, 862 MHz: below the EU band", 0, None, 862, 0),
    ("AUTO, no LoRaWAN, 863 MHz: the EU band's first", 0, None, 863, 2),
    ("AUTO, no LoRaWAN, 870 MHz: the EU band's last", 0, None, 870, 2),
    ("AUTO, no LoRaWAN, 871 MHz", 0, None, 871, 0),
    ("AUTO, no LoRaWAN, 901 MHz", 0, None, 901, 0),
    ("AUTO, no LoRaWAN, 902 MHz: the US band's first", 0, None, 902, 1),
    ("AUTO, no LoRaWAN, 928 MHz: the US band's last", 0, None, 928, 1),
    ("AUTO, no LoRaWAN, 929 MHz", 0, None, 929, 0),
    ("AUTO, no LoRaWAN, 433 MHz", 0, None, 433, 0),
    ("AUTO, no LoRaWAN, frequency 0", 0, None, 0, 0),
    ("a setting above 3 is no region", 4, 0, 915, 0),
]
INTERVAL_CLAMP_CASES = [(0, 0), (1, 5), (4, 5), (5, 5), (6, 6), (10, 10), (30, 30), (60, 60), (119, 119),
                        (120, 120), (121, 120), (3600, 120), (4294967295, 120)]
# (microseconds to the train's end, the frame's time-left field)
TIME_LEFT_CASES = [(0, 0), (4999, 0), (5000, 1), (10000, 1), (14999, 1), (15000, 2), (45312, 5),
                   (30120000, 3012), (655350000, 65535), (700000000, 65535)]


def hx(bs):
    return bytes(bs).hex()


def ms1(us):
    """Microseconds as milliseconds to 0.1 ms, a half rounded up."""
    return ((us + 50) // 100) / 10


def build_wake_tags():
    out = []
    for name, uid, tag in WAKE_TAG_CASES:
        assert b.wake_tag(uid) == tag, name + ": the frozen tag changed"
        out.append(dict(name=name, uid=uid, uid_hex="%08x" % uid,
                        mixed_hex="%08x" % b.send_phase_mix(uid ^ b.WAKE_SALT),
                        tag=tag, tag_hex="%04x" % tag))
    assert b.wake_tag(UID_TWIN) == b.wake_tag(UID_WAKE[0]) and UID_TWIN != UID_WAKE[0]
    return out


def build_wake_frames():
    out = []
    for name, uids, left, more, long_range, roll, frozen in WAKE_FRAME_CASES:
        tags = [b.wake_tag(u) for u in uids]
        frame = b.wake_frame(tags, left, more, long_range, roll)
        assert hx(frame) == frozen, name + ": the frozen frame changed"
        got = b.parse_wake_frame(frame)
        assert (list(got.tags), got.time_left_10ms, got.more, got.long_range, got.roll) == \
            (tags, left, more, long_range, roll), name
        assert b.classify(frame) == "wake", name
        out.append(dict(name=name, ok=True, uids=list(uids), tags=tags, flags=got.flags, more=more,
                        long_range=long_range, roll=roll, time_left_10ms=left,
                        time_left_ms=left * b.WAKE_TIME_UNIT_MS,
                        verdicts=[dict(uid=u, tag=b.wake_tag(u), verdict=b.wake_verdict(got, u))
                                  for u in WAKE_PROBES],
                        frame=hx(frame), frame_len=len(frame)))
    for name, frame, reason in WAKE_MALFORMED_CASES:
        try:
            b.parse_wake_frame(bytes.fromhex(frame))
        except b.WakeFrameError as e:
            assert e.reason == reason, (name, e.reason)
        else:
            raise AssertionError(name + ": parsed")
        out.append(dict(name=name, ok=False, refusal=reason, frame=frame, frame_len=len(frame) // 2))
    # The alternating lists of a train are what wake_train_frame builds.
    assert hx(b.wake_train_frame(UID_WAKE, 0, 1005)) == WAKE_FRAME_CASES[2][6]
    assert hx(b.wake_train_frame(UID_WAKE, 1, 1000)) == WAKE_FRAME_CASES[3][6]
    assert hx(b.wake_train_frame(UID_WAKE[:5], 1, 59)) == WAKE_FRAME_CASES[4][6]
    return out


def build_wake_timing():
    regions = [dict(region=c.region, name=c.name, frequency_hz=c.frequency_hz, bw_khz=c.bw_khz,
                    sf=c.sf, sf_long=c.sf_long, max_dbm=c.max_dbm)
               for c in (b.WAKE_TABLE[r] for r in sorted(b.WAKE_TABLE))]
    resolve = []
    for name, setting, lorawan, mhz, want in REGION_RESOLVE_CASES:
        assert b.direct_region_resolve(setting, lorawan, mhz) == want, name
        resolve.append(dict(name=name, setting=setting, lorawan_region=lorawan, frequency_mhz=mhz, region=want))
    settings = []
    for name, regs, long_range, sf, bw, frame_ms, w_ms, cap_ms in WAKE_SETTING_CASES:
        t = b.wake_timing(sf, bw)
        for r in regs:
            assert b.wake_setting(r, long_range)[1:3] == (bw, sf), name
        assert (ms1(t.frame_us), ms1(t.w_us), (t.cap_us + 500) // 1000) == (frame_ms, w_ms, cap_ms), \
            name + ": the table of CONTRACT_lora_wake.md section 3"
        sniff = b.call_sniff_s(long_range)
        settings.append(dict(
            name=name, regions=regs, long_range=long_range, sf=sf, bw_khz=bw, call_sniff_s=sniff,
            ts_us=t.ts_us, ts_ms=t.ts_us / 1000,
            frame_us=t.frame_us, frame_ms=ms1(t.frame_us),
            tail_us=t.tail_us, tail_ms=ms1(t.tail_us),
            w_us=t.w_us, w_ms=ms1(t.w_us),
            cap_us=t.cap_us, cap_ms=ms1(t.cap_us), cap_whole_ms=(t.cap_us + 500) // 1000,
            intent_wait_us=t.intent_wait_us, intent_wait_ms=ms1(t.intent_wait_us),
            cmd_window_us=t.cmd_window_us, cmd_window_ms=ms1(t.cmd_window_us),
            roll_wait_us=t.roll_wait_us, roll_wait_ms=ms1(t.roll_wait_us),
            roll_slot_min_us=t.roll_slot_min_us, roll_slot_min_ms=ms1(t.roll_slot_min_us),
            roll_slot_min_whole_ms=-(-t.roll_slot_min_us // 1000),
            roll_slot_default_ms=t.roll_slot_default_ms,
            toa=[dict(bytes=n, preamble=p, us=b.lora_toa_us(sf, bw, n, p), ms=ms1(b.lora_toa_us(sf, bw, n, p)))
                 for n, p in WAKE_TOA_SAMPLES],
            trains=[dict(interval_s=i, train_us=b.wake_train_us(sf, bw, i), train_ms=ms1(b.wake_train_us(sf, bw, i)),
                         frames_gap_0=b.wake_train_frames(sf, bw, i, 0),
                         frames_gap_5ms=b.wake_train_frames(sf, bw, i, 5000))
                    for i in WAKE_TRAIN_INTERVALS]))
    for a, want in INTERVAL_CLAMP_CASES:
        assert b.wake_interval_clamp(a) == want, a
    for us, want in TIME_LEFT_CASES:
        assert b.wake_time_left_10ms(us) == want, us
    return {
        "constants": {
            "sync_word": b.WAKE_SYNC_WORD, "preamble_wake": b.WAKE_PREAMBLE_SYMBOLS,
            "preamble_other": b.LORA_PREAMBLE_SYMBOLS, "frame_bytes": b.WAKE_MAX_LEN,
            "max_tags": b.WAKE_MAX_TAGS, "max_collars_per_train": b.WAKE_TRAIN_MAX_COLLARS,
            "salt": b.WAKE_SALT, "time_unit_ms": b.WAKE_TIME_UNIT_MS, "gap_max_ms": b.WAKE_GAP_MAX_MS,
            "rx_lead_ms": b.WAKE_RX_LEAD_MS, "first_send_ms": b.WAKE_FIRST_SEND_MS,
            "interval_choices_s": list(b.WAKE_INTERVAL_CHOICES_S),
            "interval_min_s": b.WAKE_INTERVAL_MIN_S, "interval_max_s": b.WAKE_INTERVAL_MAX_S,
            "slow_factor_max": b.WAKE_SLOW_FACTOR_MAX,
            "call_sniff_s": b.CALL_SNIFF_S, "call_sniff_long_s": b.CALL_SNIFF_LONG_S,
            "called_wait_s": b.CALLED_WAIT_S, "call_idle_s": b.CALL_IDLE_S, "call_max_s": b.CALL_MAX_S,
            "roll_slots_default": b.ROLL_CALL_SLOTS_DEFAULT, "roll_slots_max": b.ROLL_CALL_SLOTS_MAX,
            "roll_reply_base_ms": b.ROLL_CALL_REPLY_BASE_MS, "roll_listen_extra_ms": b.ROLL_CALL_LISTEN_EXTRA_MS,
            "roll_min_gap_s": b.ROLL_CALL_MIN_GAP_S,
        },
        "regions": regions,
        "region_resolve": resolve,
        "settings": settings,
        "interval_clamp": [dict(interval_s=a, runs_s=want) for a, want in INTERVAL_CLAMP_CASES],
        "time_left": [dict(us=us, time_left_10ms=want) for us, want in TIME_LEFT_CASES],
    }


def build_roll_calls():
    master = bytes.fromhex(MASTER_COMMAND)
    keys = []
    for name, group, gen in WAKE_KEY_CASES:
        key = b.kdf(master, "wake", group, gen)
        assert key != b.kdf(master, "command", group, gen), name + ": label separation"
        keys.append(dict(name=name, master=MASTER_COMMAND, purpose="wake", label=b.LABEL_WAKE.decode("ascii"),
                         group=group, group_hex="%08x" % group, gen=gen,
                         input=hx(b.kdf_input("wake", group, gen)), wake_key=hx(key), kcv=hx(b.kcv(key))))

    frames, sealed = [], {}
    for name, group, gen, seq, vf, vt, slots, slot_ms, flags, frozen in ROLL_CALL_CASES:
        ctr = b.ctr_make(gen, seq)
        key = b.kdf(master, "wake", group, gen)
        frame = b.seal_roll_call(key, group, ctr, vf, vt, slots, slot_ms, flags)
        assert hx(frame) == frozen, name + ": the frozen frame changed"
        got = b.open_roll_call(key, frame)
        assert got == b.RollCall(group, ctr, gen, seq, vf, vt, slots, slot_ms, flags), name
        assert b.open_roll_call_with_master(master, frame) == got, name
        assert b.classify(frame) == "roll_call", name
        sealed[name[:3]] = (frame, key, group, gen, ctr)
        frames.append(dict(name=name, master=MASTER_COMMAND, group=group, group_hex="%08x" % group,
                           gen=gen, seq=seq, ctr=ctr, ctr_hex="%08x" % ctr,
                           wake_key=hx(key), kcv=hx(b.kcv(key)),
                           nonce=hx(b.nonce(group, ctr, b.DIR_ROLL_CALL)), aad=hx(frame[:b.AAD_LEN]),
                           valid_from=vf, valid_to=vt, slots=slots, slot_ms=slot_ms, flags=flags,
                           body=hx(b.pack_roll_call_body(vf, vt, slots, slot_ms, flags)),
                           ct=hx(frame[b.AAD_LEN:b.AAD_LEN + b.ROLL_CALL_BODY_LEN]),
                           tag=hx(frame[b.AAD_LEN + b.ROLL_CALL_BODY_LEN:]),
                           listen_ms=b.roll_call_listen_ms(slots, slot_ms),
                           frame=hx(frame), frame_len=len(frame)))

    # Where each collar answers: five collars, two counters (a new counter
    # deals the slots again), three slot counts.
    slots_out = []
    for ctr in (0x01000001, 0x01000002):
        for n in (1, 32, 64):
            for uid in UID_WAKE[:4] + [UID_TEST]:
                slots_out.append(dict(uid=uid, uid_hex="%08x" % uid, ctr=ctr, ctr_hex="%08x" % ctr,
                                      slots=n, slot_ms=67, slot=b.roll_call_slot(uid, ctr, n),
                                      reply_delay_ms=b.roll_call_reply_delay_ms(uid, ctr, n, 67)))

    # The collar's rule, one cause per refusal.
    f1, k1, g1, gen1, c1 = sealed["RC1"]
    f2, _, _, _, c2 = sealed["RC2"]
    f3, k3, _, gen3, c3 = sealed["RC3"]
    us, eu, eu_long = (9, 500), (7, 125), (10, 125)

    def seal1(seq, slots=32, slot_ms=67, flags=0, vf=ROLL_FROM, vt=ROLL_TO):
        return b.seal_roll_call(k1, g1, b.ctr_make(gen1, seq), vf, vt, slots, slot_ms, flags)

    def flip(frame, i):
        t = bytearray(frame)
        t[i] ^= 0x01
        return bytes(t)

    cases = [
        # name, frame, key, group, gen, last counter, now, (SF, kHz), since the last answer, reason
        ("accepted: RC1, the first roll call this collar hears", f1, k1, g1, gen1, 0, ROLL_NOW, us, None, None),
        ("accepted: RC2 at the EU setting, a minute after answering RC1", f2, k1, g1, gen1, c1, ROLL_NOW, eu, 60, None),
        ("accepted: RC3 at EU long range under the gen 2 key, after RC2", f3, k3, g1, gen3, c2, ROLL_NOW, eu_long, None, None),
        ("accepted at the window's first second", f1, k1, g1, gen1, 0, ROLL_FROM, us, None, None),
        ("accepted at the window's last second", f1, k1, g1, gen1, 0, ROLL_TO, us, None, None),
        ("accepted: a 62 ms slot is the shortest at SF9 / 500 kHz", seal1(7, slot_ms=62), k1, g1, gen1, c2,
         ROLL_NOW, us, None, None),
        ("accepted: 64 slots, the most", seal1(8, slots=64), k1, g1, gen1, c2, ROLL_NOW, us, None, None),
        ("refused: 28 bytes", f1[:-1], k1, g1, gen1, 0, ROLL_NOW, us, None, "frame"),
        ("refused: a command's magic", bytes([b.MAGIC_COMMAND]) + f1[1:], k1, g1, gen1, 0, ROLL_NOW, us, None, "frame"),
        ("refused: the collar holds no wake key", f1, None, 0, 0, 0, ROLL_NOW, us, None, "no_key"),
        ("refused: wrong group (the collar holds group 43's key)", f1, b.kdf(master, "wake", GROUP_B, 1),
         GROUP_B, 1, 0, ROLL_NOW, us, None, "group"),
        ("refused: wrong generation (the collar holds the group's gen 2 key)", f1, k3, g1, gen3, 0,
         ROLL_NOW, us, None, "gen"),
        ("refused: stale counter, the one last accepted", f1, k1, g1, gen1, c1, ROLL_NOW, us, None, "counter"),
        ("refused: stale counter, below the last accepted", f1, k1, g1, gen1, c2, ROLL_NOW, us, None, "counter"),
        ("refused: bad tag, one bit of the tag changed", flip(f1, 28), k1, g1, gen1, 0, ROLL_NOW, us, None, "tag"),
        ("refused: bad tag, one bit of the body changed", flip(f1, 9), k1, g1, gen1, 0, ROLL_NOW, us, None, "tag"),
        ("refused: bad tag, the right group and gen under another master", f1,
         b.kdf(bytes.fromhex(MASTER_BEACON_A), "wake", g1, gen1), g1, gen1, 0, ROLL_NOW, us, None, "tag"),
        ("refused: a flag is set", seal1(9, flags=1), k1, g1, gen1, c2, ROLL_NOW, us, None, "flags"),
        ("refused: the collar has no valid clock", f1, k1, g1, gen1, 0, None, us, None, "clock"),
        ("refused: one second before the window", f1, k1, g1, gen1, 0, ROLL_FROM - 1, us, None, "window"),
        ("refused: one second after the window", f1, k1, g1, gen1, 0, ROLL_TO + 1, us, None, "window"),
        ("refused: no slots", seal1(10, slots=0), k1, g1, gen1, c2, ROLL_NOW, us, None, "slots"),
        ("refused: 65 slots", seal1(11, slots=65), k1, g1, gen1, c2, ROLL_NOW, us, None, "slots"),
        ("refused: a 61 ms slot is too short at SF9 / 500 kHz", seal1(12, slot_ms=61), k1, g1, gen1, c2,
         ROLL_NOW, us, None, "slot_ms"),
        ("refused: RC1's 67 ms slot is too short at the EU setting", f1, k1, g1, gen1, 0, ROLL_NOW, eu, None, "slot_ms"),
        ("refused: it answered a roll call 59 s ago", f2, k1, g1, gen1, c1, ROLL_NOW, us, 59, "recent"),
    ]
    checks = []
    for name, frame, key, group, gen, last, now, (sf, bw), since, want in cases:
        rc, reason = b.roll_call_check(frame, key, group, gen, last, now, sf, bw, since)
        assert reason == want, (name, reason)
        assert (rc is None) == (want is not None), name
        row = dict(name=name, frame=hx(frame), wake_key=hx(key) if key else None, group=group, gen=gen,
                   last_ctr=last, now=now, sf=sf, bw_khz=bw, since_answer_s=since,
                   accept=want is None, reason=want)
        if rc is not None:
            row.update(ctr=rc.ctr, slots=rc.slots, slot_ms=rc.slot_ms)
        checks.append(row)
    assert {c["reason"] for c in checks if c["reason"]} == set(b.ROLL_CALL_REFUSALS), "every refusal has a vector"
    return {"keys": keys, "frames": frames, "slots": slots_out, "checks": checks}


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

    reports = []
    for name, master, uid, gen, seq, dev_key, kcv, payload, frozen in REPORT_CASES:
        ctr = b.ctr_make(gen, seq)
        key = b.kdf(bytes.fromhex(master), "beacon", uid, gen)
        assert (hx(key), hx(b.kcv(key))) == (dev_key, kcv), name + ": key derivation"
        frame = b.seal_report(key, uid, ctr, bytes.fromhex(payload))
        assert hx(frame) == frozen, name + ": the frozen frame changed"
        got = b.open_report(key, frame)
        assert (got.uid, got.ctr, got.gen, got.seq, hx(got.payload)) == (uid, ctr, gen, seq, payload), name
        assert b.open_report_with_master(bytes.fromhex(master), frame) == got, name
        n = len(payload) // 2
        reports.append(dict(name=name, master=master, uid=uid, uid_hex="%08x" % uid,
                            gen=gen, seq=seq, ctr=ctr, ctr_hex="%08x" % ctr,
                            dev_key=hx(key), kcv=hx(b.kcv(key)),
                            nonce=hx(b.nonce(uid, ctr)), aad=hx(frame[:b.AAD_LEN]),
                            payload=payload, ct=hx(frame[b.AAD_LEN:b.AAD_LEN + n]),
                            tag=hx(frame[b.AAD_LEN + n:]), frame=hx(frame), frame_len=len(frame)))

    commands = []
    master_cmd = bytes.fromhex(MASTER_COMMAND)
    for name, uid, gen, seq, echo, vf, vt, body, frozen in COMMAND_CASES:
        ctr = b.ctr_make(gen, seq)
        key = b.kdf(master_cmd, "command", uid, gen)
        frame = b.seal_command(key, uid, ctr, bytes.fromhex(body), echo, vf, vt)
        assert hx(frame) == frozen, name + ": the frozen frame changed"
        got = b.open_command(key, frame)
        assert (got.uid, got.ctr, got.echo, got.valid_from, got.valid_to, hx(got.body)) == \
            (uid, ctr, echo, vf, vt, body), name
        commands.append(dict(name=name, master=MASTER_COMMAND, uid=uid, uid_hex="%08x" % uid,
                             gen=gen, seq=seq, ctr=ctr, ctr_hex="%08x" % ctr,
                             cmd_key=hx(key), kcv=hx(b.kcv(key)),
                             nonce=hx(b.nonce(uid, ctr, b.DIR_COMMAND)), aad=hx(frame[:b.AAD_LEN]),
                             echo=echo, valid_from=vf, valid_to=vt, body=body,
                             frame=hx(frame), frame_len=len(frame)))
    command_acks = []
    for name, uid, gen, seq, result, command, detail, rssi, snr, frozen in COMMAND_ACK_CASES:
        ctr = b.ctr_make(gen, seq)
        key = b.kdf(master_cmd, "command", uid, gen)
        frame = b.seal_command_ack(key, uid, ctr, result, command, detail, rssi, snr)
        assert hx(frame) == frozen, name + ": the frozen frame changed"
        got = b.open_command_ack(key, frame)
        assert (got.result, got.command, got.detail, got.rssi, got.snr_q4) == \
            (result, command, detail, rssi, snr), name
        command_acks.append(dict(name=name, master=MASTER_COMMAND, uid=uid, uid_hex="%08x" % uid,
                                 gen=gen, seq=seq, ctr=ctr, ctr_hex="%08x" % ctr, cmd_key=hx(key),
                                 nonce=hx(b.nonce(uid, ctr, b.DIR_COMMAND_ACK)),
                                 result=result, command=command, detail=detail,
                                 rssi=rssi, snr_q4=snr, frame=hx(frame), frame_len=len(frame)))

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
            "report": "[0]=0x52 [1..4]=uid_le32 [5..8]=ctr_le32 (the v2 counter sequence) "
                      "[9..9+n-1]=CCM ciphertext of the payload (n=1..238) [9+n..9+n+7]=8-byte tag; "
                      "AAD, nonce and dev_key as v2; frame n+17 = 18..255 B",
            "command": "[0]=0x44 [1..4]=uid_le32 [5..8]=cmd_counter_le32 (gen<<24|seq) "
                       "then CCM ciphertext of echo u32le || valid_from u32le || valid_to u32le || "
                       "DownlinkPacket (n=1..226) and an 8-byte tag; AAD=[0..8]; "
                       "nonce=uid_le32||ctr_le32||0x01||0x00000000; key = the COMMAND key (CID-LORA-CMD); "
                       "frame n+29 = 30..255 B",
            "command_ack": "[0]=0x4B [1..4]=uid_le32 [5..8]=the command's counter, then CCM ciphertext of "
                           "result u8 || command u8 || detail u32le || rssi i8 || snr_q4 i8 and an 8-byte tag; "
                           "nonce dir 0x02; 25 B",
            "wake": "[0]=0x57 [1]=flags (bit 0 MORE, bit 1 LONG, bit 2 ROLL, bits 3..7 = 0) "
                    "[2..3]=time left u16le in 10 ms units, from the end of this frame to the end of the "
                    "train's last frame [4]=k, the number of tags (1..4; 0 with ROLL and only then) "
                    "[5..]=k x u16le tags; tag = fmix32(uid ^ 0x57414B45) & 0xFFFF; 5 + 2k = 5..13 B, cleartext",
            "wake_timing": "Ts = 2^SF / BW; toa(n, p) = (p + 4.25 + 8 + max(ceil((8n - 4SF + 44) / "
                           "(4(SF - 2DE))) x 5, 0)) x Ts with DE = 1 when Ts > 16 ms (coding rate 4/5, explicit "
                           "header, CRC on); frame = toa(13, 12); tail = toa(13, 8) - 8 Ts; W = tail + 16 Ts + 7 ms; "
                           "cap = 1.5 x frame + 20 ms; intent_wait = 2 x toa(14, 8) + 150 ms; "
                           "cmd_window = toa(255, 8) + 300 ms; train >= 1.03 x interval + W + frame; "
                           "roll_wait = 2 x toa(29, 8) + 150 ms; a roll-call slot >= toa(30, 8) + 5 ms, by default "
                           "ceil(toa(30, 8)) + 10 ms. *_us are exact microseconds, *_ms the same to 0.1 ms",
            "wake_key": "wake_key = AES-CMAC(the owner's command master, 'CID-LORA-WAK' || group_le32 || gen)",
            "roll_call": "[0]=0x43 [1..4]=group_le32 [5..8]=ctr_le32 (gen<<24|seq) [9..20]=CCM ciphertext of "
                         "valid_from u32le || valid_to u32le || slots u8 || slot_ms u16le || flags u8 "
                         "[21..28]=8-byte tag; AAD=[0..8]; nonce=group_le32||ctr_le32||0x03||0x00000000; "
                         "key = the group's wake key; 29 B. A collar answers with one v2 beacon starting "
                         "300 ms + (fmix32(uid ^ 0x57414B45 ^ ctr) % slots) x slot_ms after the roll call's end, "
                         "sealed after the roll call is accepted; the receiver listens "
                         "300 ms + slots x slot_ms + 200 ms after sending the roll call",
        },
        "aes128": aes,
        "cmac": cmac,
        "ccm": ccm,
        "kdf": kdf,
        "frames": frames,
        "v1": v1,
        "reports": reports,
        "commands": commands,
        "command_acks": command_acks,
        "wake_tags": build_wake_tags(),
        "wake_frames": build_wake_frames(),
        "wake_timing": build_wake_timing(),
        "roll_calls": build_roll_calls(),
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
    print("wrote %s: %d aes, %d cmac, %d ccm, %d kdf, %d frames, %d v1, %d reports" % (
        a.out, len(d["aes128"]), len(d["cmac"]), len(d["ccm"]), len(d["kdf"]), len(d["frames"]), len(d["v1"]),
        len(d["reports"])))
    print("  %d commands, %d command acks, %d wake tags, %d wake frames, %d wake settings, "
          "%d roll-call keys, %d roll calls, %d slot choices, %d roll-call checks" % (
              len(d["commands"]), len(d["command_acks"]), len(d["wake_tags"]), len(d["wake_frames"]),
              len(d["wake_timing"]["settings"]), len(d["roll_calls"]["keys"]), len(d["roll_calls"]["frames"]),
              len(d["roll_calls"]["slots"]), len(d["roll_calls"]["checks"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
