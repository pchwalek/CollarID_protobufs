#!/usr/bin/env python3
"""CollarID lost-mode beacon: reference codec for the v1 (0x4C, plaintext) and
v2 (0x4D, AES-128-CCM) frames, and the key derivation a receiver needs.

Standard library only, so it runs anywhere (a field laptop, a CI runner, a
receiver's build script). It is a REFERENCE, written for clarity and for
generating test vectors; it is not fast and it is not side-channel hardened.
Where this file and beacon/README.md disagree, one of them has a bug; the
vectors in beacon/vectors.json are generated from this file.

Primitives (each checked against public vectors in test_beacon_v2.py):
  AES-128 forward block          FIPS-197
  AES-CMAC                       RFC 4493
  AES-CCM, L=2, M=8              RFC 3610 (packet vectors 1-24)

Command line:
  beacon_v2.py open   --key HEX FRAMEHEX          open a v2 frame with a device key
  beacon_v2.py open   --master HEX FRAMEHEX       ... deriving the key from a beacon master
  beacon_v2.py derive --master HEX --uid UID --gen N [--purpose command]
  beacon_v2.py kcv    --key HEX
  beacon_v2.py v1     FRAMEHEX                    decode a v1 frame
"""

import argparse
import json
import sys
from collections import namedtuple

# --------------------------------------------------------------------- AES-128

def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _make_sbox():
    """The AES S-box from its definition (GF(2^8) inverse, then the affine
    map), so there is no 256-entry table to mistype."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)   # p *= 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09                                               # q /= 3
        def rotl(v, n):
            return ((v << n) | (v >> (8 - n))) & 0xFF
        x = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4)   # the affine map
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return tuple(sbox)


SBOX = _make_sbox()


class AES128:
    """AES-128, forward direction only (CCM and CMAC never decrypt)."""

    def __init__(self, key):
        key = bytes(key)
        if len(key) != 16:
            raise ValueError("AES-128 key must be 16 bytes")
        w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
        rcon = 1
        for i in range(4, 44):
            t = list(w[i - 1])
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [SBOX[b] for b in t]
                t[0] ^= rcon
                rcon = _xtime(rcon)
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        self._w = w

    def encrypt_block(self, block):
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        w = self._w
        s = [block[i] ^ w[i // 4][i % 4] for i in range(16)]       # i = row + 4*col
        for rnd in range(1, 11):
            s = [SBOX[b] for b in s]
            s = [s[(i % 4) + 4 * ((i // 4 + i % 4) % 4)] for i in range(16)]
            if rnd != 10:
                t = []
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t += [
                        _xtime(a[0]) ^ _xtime(a[1]) ^ a[1] ^ a[2] ^ a[3],
                        a[0] ^ _xtime(a[1]) ^ _xtime(a[2]) ^ a[2] ^ a[3],
                        a[0] ^ a[1] ^ _xtime(a[2]) ^ _xtime(a[3]) ^ a[3],
                        _xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ _xtime(a[3]),
                    ]
                s = t
            s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
        return bytes(s)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ----------------------------------------------------------------- AES-CMAC

def _shift_left(b):
    v = int.from_bytes(b, "big") << 1
    out = (v & ((1 << 128) - 1)).to_bytes(16, "big")
    return _xor(out, b"\x00" * 15 + b"\x87") if b[0] & 0x80 else out


def cmac(key, msg):
    """AES-CMAC (RFC 4493) of msg under key; 16-byte tag."""
    aes = AES128(key)
    msg = bytes(msg)
    k1 = _shift_left(aes.encrypt_block(b"\x00" * 16))
    k2 = _shift_left(k1)
    n = (len(msg) + 15) // 16
    if n == 0:
        n = 1
    if len(msg) and len(msg) % 16 == 0:
        last = _xor(msg[16 * (n - 1):], k1)
    else:
        pad = msg[16 * (n - 1):] + b"\x80"
        last = _xor(pad + b"\x00" * (16 - len(pad)), k2)
    x = b"\x00" * 16
    for i in range(n - 1):
        x = aes.encrypt_block(_xor(x, msg[16 * i:16 * i + 16]))
    return aes.encrypt_block(_xor(x, last))


# ------------------------------------------------------------------ AES-CCM

CCM_L = 2                     # 2-byte length field: nonce is 15 - L = 13 bytes
CCM_NONCE_LEN = 15 - CCM_L
CCM_TAG_LENS = (4, 6, 8, 10, 12, 14, 16)


def _ccm_blocks(nonce, aad, pt_len, tag_len):
    """B_0 and the AAD blocks of RFC 3610 section 2.2 (L=2)."""
    if len(nonce) != CCM_NONCE_LEN:
        raise ValueError("CCM nonce must be %d bytes" % CCM_NONCE_LEN)
    if tag_len not in CCM_TAG_LENS:
        raise ValueError("CCM tag length must be one of %r" % (CCM_TAG_LENS,))
    if pt_len >= 1 << (8 * CCM_L):
        raise ValueError("payload too long for L=2")
    if len(aad) >= (1 << 16) - (1 << 8):
        raise ValueError("AAD too long for the 2-byte encoding")
    flags = (0x40 if aad else 0) | (((tag_len - 2) // 2) << 3) | (CCM_L - 1)
    b = bytes([flags]) + nonce + pt_len.to_bytes(CCM_L, "big")
    if aad:
        a = len(aad).to_bytes(2, "big") + aad
        a += b"\x00" * (-len(a) % 16)
        b += a
    return b


def _ccm_keystream_block(aes, nonce, i):
    """S_i = E(K, A_i), A_i = flags(L-1) || nonce || i (2 bytes, big-endian)."""
    return aes.encrypt_block(bytes([CCM_L - 1]) + nonce + i.to_bytes(CCM_L, "big"))


def _ccm_mac(aes, nonce, aad, pt, tag_len):
    data = _ccm_blocks(nonce, aad, len(pt), tag_len) + pt + b"\x00" * (-len(pt) % 16)
    x = b"\x00" * 16
    for i in range(0, len(data), 16):
        x = aes.encrypt_block(_xor(x, data[i:i + 16]))
    return x[:tag_len]


def _ccm_crypt(aes, nonce, data):
    out = b""
    for i in range(0, len(data), 16):
        out += _xor(data[i:i + 16], _ccm_keystream_block(aes, nonce, i // 16 + 1))
    return out


def ccm_seal(key, nonce, aad, pt, tag_len=8):
    """AES-128-CCM encrypt-and-tag (RFC 3610, L=2). Returns (ciphertext, tag)."""
    aes = AES128(key)
    nonce, aad, pt = bytes(nonce), bytes(aad), bytes(pt)
    t = _ccm_mac(aes, nonce, aad, pt, tag_len)
    tag = _xor(t, _ccm_keystream_block(aes, nonce, 0)[:tag_len])
    return _ccm_crypt(aes, nonce, pt), tag


class AuthError(ValueError):
    """The tag did not verify: wrong key, wrong nonce, or a modified frame."""


def ccm_open(key, nonce, aad, ct, tag, tag_len=8):
    """AES-128-CCM decrypt-and-verify. Returns the plaintext or raises AuthError.
    Nothing about the plaintext is returned on failure."""
    aes = AES128(key)
    nonce, aad, ct, tag = bytes(nonce), bytes(aad), bytes(ct), bytes(tag)
    if len(tag) != tag_len:
        raise AuthError("tag length")
    pt = _ccm_crypt(aes, nonce, ct)
    t = _xor(_ccm_mac(aes, nonce, aad, pt, tag_len), _ccm_keystream_block(aes, nonce, 0)[:tag_len])
    # A reference decoder need not be constant-time; the C codec's compare is.
    if t != tag:
        raise AuthError("tag mismatch")
    return pt


# ------------------------------------------------------- keys and derivation

LABEL_BEACON = b"CID-LORA-BCN"     # beacon (confidentiality) key family
LABEL_COMMAND = b"CID-LORA-CMD"    # command (authentication) key family, never exported
PURPOSES = {"beacon": LABEL_BEACON, "command": LABEL_COMMAND}


def kdf_input(purpose, uid, gen):
    """label(12) || uid_le32(4) || gen(1) = 17 bytes."""
    label = PURPOSES[purpose]
    if not 0 <= uid <= 0xFFFFFFFF:
        raise ValueError("uid must be a uint32")
    if not 0 <= gen <= 255:
        raise ValueError("gen must be 0..255")
    return label + uid.to_bytes(4, "little") + bytes([gen])


def kdf(master, purpose, uid, gen):
    """dev_key = AES-CMAC(master, label || uid_le32 || gen). The two purposes
    are meant to use two INDEPENDENT masters; the label is a second fence."""
    return cmac(master, kdf_input(purpose, uid, gen))


def kcv(key):
    """Key check value: first 3 bytes of AES(key, 0^16). Safe to show and log;
    it never lets anyone recover the key or forge a frame."""
    return AES128(key).encrypt_block(b"\x00" * 16)[:3]


# ------------------------------------------------------------ frame layout

MAGIC_V1 = 0x4C
LEN_V1 = 18
MAGIC_V2 = 0x4D
LEN_V2 = 30
BODY_LEN = 13
AAD_LEN = 9
NONCE_LEN = 13
TAG_LEN = 8
DIR_BEACON = 0x00          # collar-originated beacon (this file)
DIR_COMMAND = 0x01         # reserved: finder -> collar command
DIR_COMMAND_ACK = 0x02     # reserved: collar -> finder command acknowledgement

Beacon = namedtuple("Beacon", "version uid ctr gen seq lat_e7 lon_e7 fix_epoch batt_pct")


def ctr_make(gen, seq):
    if not 0 <= gen <= 255 or not 0 <= seq <= 0xFFFFFF:
        raise ValueError("gen is 8 bits, seq is 24 bits")
    return (gen << 24) | seq


def ctr_gen(ctr):
    return (ctr >> 24) & 0xFF


def ctr_seq(ctr):
    return ctr & 0xFFFFFF


def nonce(uid, ctr, direction=DIR_BEACON):
    """13-byte CCM nonce: uid_le32 || ctr_le32 || direction || 0x00000000."""
    if not 0 <= uid <= 0xFFFFFFFF or not 0 <= ctr <= 0xFFFFFFFF:
        raise ValueError("uid and ctr are uint32")
    if not 0 <= direction <= 255:
        raise ValueError("direction is one byte")
    return uid.to_bytes(4, "little") + ctr.to_bytes(4, "little") + bytes([direction]) + b"\x00" * 4


def _i32(v, what):
    if not -(1 << 31) <= v < (1 << 31):
        raise ValueError("%s must be an int32" % what)
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


def pack_body(lat_e7, lon_e7, fix_epoch, batt_pct):
    """The 13-byte body, identical to v1 bytes [5..17]."""
    if not 0 <= fix_epoch <= 0xFFFFFFFF:
        raise ValueError("fix_epoch must be a uint32")
    if not 0 <= batt_pct <= 255:
        raise ValueError("batt_pct is one byte")
    return _i32(lat_e7, "lat_e7") + _i32(lon_e7, "lon_e7") + fix_epoch.to_bytes(4, "little") + bytes([batt_pct])


def unpack_body(body):
    body = bytes(body)
    if len(body) != BODY_LEN:
        raise ValueError("body must be %d bytes" % BODY_LEN)
    lat = int.from_bytes(body[0:4], "little", signed=True)
    lon = int.from_bytes(body[4:8], "little", signed=True)
    epoch = int.from_bytes(body[8:12], "little")
    return lat, lon, epoch, body[12]


def header_v2(uid, ctr):
    """The 9 cleartext bytes, which are also the AAD."""
    return bytes([MAGIC_V2]) + uid.to_bytes(4, "little") + ctr.to_bytes(4, "little")


def seal(dev_key, uid, ctr, lat_e7, lon_e7, fix_epoch, batt_pct):
    """Build a 30-byte v2 frame."""
    hdr = header_v2(uid, ctr)
    ct, tag = ccm_seal(dev_key, nonce(uid, ctr, DIR_BEACON), hdr,
                       pack_body(lat_e7, lon_e7, fix_epoch, batt_pct), TAG_LEN)
    frame = hdr + ct + tag
    assert len(frame) == LEN_V2
    return frame


def peek(frame):
    """(uid, ctr) from a v2 frame's cleartext header; no key needed.
    A receiver without the key still learns WHICH collar it hears and can
    RSSI-home on it, but nothing about where the collar is."""
    frame = bytes(frame)
    if len(frame) != LEN_V2 or frame[0] != MAGIC_V2:
        raise ValueError("not a v2 beacon frame")
    return int.from_bytes(frame[1:5], "little"), int.from_bytes(frame[5:9], "little")


def open_frame(dev_key, frame):
    """Open a v2 frame with the device's beacon key. Raises AuthError."""
    frame = bytes(frame)
    uid, ctr = peek(frame)
    body = ccm_open(dev_key, nonce(uid, ctr, DIR_BEACON), frame[:AAD_LEN],
                    frame[AAD_LEN:AAD_LEN + BODY_LEN], frame[AAD_LEN + BODY_LEN:], TAG_LEN)
    lat, lon, epoch, batt = unpack_body(body)
    return Beacon(2, uid, ctr, ctr_gen(ctr), ctr_seq(ctr), lat, lon, epoch, batt)


def open_with_master(master, frame):
    """Open a v2 frame holding only the owner's BEACON master: the generation
    in the cleartext counter selects the key."""
    uid, ctr = peek(frame)
    return open_frame(kdf(master, "beacon", uid, ctr_gen(ctr)), frame)


def encode_v1(uid, lat_e7, lon_e7, fix_epoch, batt_pct):
    """The legacy 18-byte plaintext frame (what an unkeyed collar sends)."""
    if not 0 <= uid <= 0xFFFFFFFF:
        raise ValueError("uid must be a uint32")
    return bytes([MAGIC_V1]) + uid.to_bytes(4, "little") + pack_body(lat_e7, lon_e7, fix_epoch, batt_pct)


def decode_v1(frame):
    frame = bytes(frame)
    if len(frame) != LEN_V1 or frame[0] != MAGIC_V1:
        raise ValueError("not a v1 beacon frame")
    uid = int.from_bytes(frame[1:5], "little")
    lat, lon, epoch, batt = unpack_body(frame[5:])
    return Beacon(1, uid, None, None, None, lat, lon, epoch, batt)


def classify(frame):
    """'v1', 'v2' or None, by magic byte and length only."""
    frame = bytes(frame)
    if len(frame) == LEN_V1 and frame[0] == MAGIC_V1:
        return "v1"
    if len(frame) == LEN_V2 and frame[0] == MAGIC_V2:
        return "v2"
    return None


# ------------------------------------------------------------------- CLI

def _hex(s):
    return bytes.fromhex(s.replace(" ", ""))


def _uid(s):
    return int(s, 0)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open", help="open a v2 frame")
    g = o.add_mutually_exclusive_group(required=True)
    g.add_argument("--key", type=_hex, help="device beacon key, 16 bytes hex")
    g.add_argument("--master", type=_hex, help="owner's beacon master, 16 bytes hex")
    o.add_argument("frame", type=_hex, help="30 bytes hex")
    d = sub.add_parser("derive", help="derive a device key from a master")
    d.add_argument("--master", type=_hex, required=True)
    d.add_argument("--uid", type=_uid, required=True, help="on-air uid32 (0x... or decimal)")
    d.add_argument("--gen", type=int, required=True, help="provision generation 1..255")
    d.add_argument("--purpose", choices=sorted(PURPOSES), default="beacon")
    k = sub.add_parser("kcv", help="key check value of a key")
    k.add_argument("--key", type=_hex, required=True)
    v = sub.add_parser("v1", help="decode a v1 frame")
    v.add_argument("frame", type=_hex, help="18 bytes hex")
    a = p.parse_args(argv)
    if a.cmd == "open":
        try:
            b = open_with_master(a.master, a.frame) if a.master else open_frame(a.key, a.frame)
        except AuthError as e:
            print(json.dumps({"error": "authentication failed", "detail": str(e)}))
            return 1
        print(json.dumps(b._asdict()))
    elif a.cmd == "derive":
        key = kdf(a.master, a.purpose, a.uid, a.gen)
        print(json.dumps({"purpose": a.purpose, "uid": "0x%08X" % a.uid, "gen": a.gen,
                          "key": key.hex(), "kcv": kcv(key).hex()}))
    elif a.cmd == "kcv":
        print(json.dumps({"kcv": kcv(a.key).hex()}))
    elif a.cmd == "v1":
        print(json.dumps(decode_v1(a.frame)._asdict()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
