#!/usr/bin/env python3
"""CollarID lost-mode beacon: reference codec for the v1 (0x4C, plaintext) and
v2 (0x4D, AES-128-CCM) frames, the sealed report (0x52, the v2 construction
with a variable-length body), the signed handheld command (0x44) and its
acknowledgement (0x4B), the wake frame (0x57) with the timing both ends of a
wake compute, the roll call (0x43), and the key derivation a receiver needs.

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
  beacon_v2.py report-peek FRAMEHEX               uid and counter of a sealed report, no key
  beacon_v2.py report-open --key HEX FRAMEHEX     open a sealed report (also --master HEX)
  beacon_v2.py report-seal --key HEX --uid UID --ctr CTR PAYLOADHEX
  beacon_v2.py wake-tag UID [UID ...]             the 16-bit tags a wake frame carries
  beacon_v2.py wake-parse FRAMEHEX [--uid UID]    decode a wake frame (0x57)
  beacon_v2.py wake-timing --region R [--long] [--interval S]
  beacon_v2.py roll-open --key HEX FRAMEHEX       open a roll call (0x43) with a wake key
  beacon_v2.py roll-open --master HEX FRAMEHEX    ... deriving it from the owner's command master
  beacon_v2.py derive --master HEX --purpose wake --uid GROUP --gen N
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
# The wake key family (roll calls, 0x43, below; 2026-11-13). Derived from the
# owner's COMMAND master, per GROUP (the owner's account) and generation, not
# per collar: the group takes the uid's place in the input.
LABEL_WAKE = b"CID-LORA-WAK"
# old: PURPOSES = {"beacon": LABEL_BEACON, "command": LABEL_COMMAND}
PURPOSES = {"beacon": LABEL_BEACON, "command": LABEL_COMMAND, "wake": LABEL_WAKE}


def kdf_input(purpose, uid, gen):
    """label(12) || uid_le32(4) || gen(1) = 17 bytes. For purpose "wake" the
    uid argument is the group."""
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
DIR_COMMAND = 0x01         # handheld -> collar command (0x44, below)
DIR_COMMAND_ACK = 0x02     # collar -> handheld command acknowledgement (0x4B, below)
# old: DIR_COMMAND = 0x01         # reserved: finder -> collar command
# old: DIR_COMMAND_ACK = 0x02     # reserved: collar -> finder command acknowledgement

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


# ------------------------------------------------- sealed report (0x52)
#
# Added 2026-09-30. A keyed collar's regular direct-radio report (the
# protobuf it sends in the clear when it holds no key) sealed exactly as a v2
# beacon: the same device key, the same AAD (the nine header bytes), the same
# nonce (dir 0x00) and the same transmit counter sequence, shared with its v2
# beacons so that no nonce repeats. Only the magic and the body length differ.

MAGIC_REPORT = 0x52                                # 'R'
REPORT_OVERHEAD = AAD_LEN + TAG_LEN                # 17: the cleartext header and the tag
REPORT_MAX_LEN = 255                               # one LoRa packet
REPORT_MIN_PAYLOAD = 1
REPORT_MAX_PAYLOAD = REPORT_MAX_LEN - REPORT_OVERHEAD   # 238
REPORT_MIN_LEN = REPORT_MIN_PAYLOAD + REPORT_OVERHEAD    # 18

Report = namedtuple("Report", "uid ctr gen seq payload")


def header_report(uid, ctr):
    """The 9 cleartext bytes of a sealed report, which are also its AAD."""
    if not 0 <= uid <= 0xFFFFFFFF or not 0 <= ctr <= 0xFFFFFFFF:
        raise ValueError("uid and ctr are uint32")
    return bytes([MAGIC_REPORT]) + uid.to_bytes(4, "little") + ctr.to_bytes(4, "little")


def seal_report(dev_key, uid, ctr, payload):
    """Build a sealed report frame (len(payload) + 17 bytes) from the report's
    plaintext bytes (1..238), under the device's beacon key."""
    payload = bytes(payload)
    if not REPORT_MIN_PAYLOAD <= len(payload) <= REPORT_MAX_PAYLOAD:
        raise ValueError("report payload must be %d..%d bytes" % (REPORT_MIN_PAYLOAD, REPORT_MAX_PAYLOAD))
    hdr = header_report(uid, ctr)
    ct, tag = ccm_seal(dev_key, nonce(uid, ctr, DIR_BEACON), hdr, payload, TAG_LEN)
    frame = hdr + ct + tag
    assert len(frame) == len(payload) + REPORT_OVERHEAD
    return frame


def peek_report(frame):
    """(uid, ctr) from a sealed report's cleartext header; no key needed. A
    receiver without the key learns which collar it hears and its counter,
    never the report."""
    frame = bytes(frame)
    if not REPORT_MIN_LEN <= len(frame) <= REPORT_MAX_LEN or frame[0] != MAGIC_REPORT:
        raise ValueError("not a sealed report frame")
    return int.from_bytes(frame[1:5], "little"), int.from_bytes(frame[5:9], "little")


def open_report(dev_key, frame):
    """Open a sealed report with the device's beacon key. Raises AuthError;
    nothing of the payload is returned on failure."""
    frame = bytes(frame)
    uid, ctr = peek_report(frame)
    payload = ccm_open(dev_key, nonce(uid, ctr, DIR_BEACON), frame[:AAD_LEN],
                       frame[AAD_LEN:-TAG_LEN], frame[-TAG_LEN:], TAG_LEN)
    return Report(uid, ctr, ctr_gen(ctr), ctr_seq(ctr), payload)


def open_report_with_master(master, frame):
    """Open a sealed report holding only the owner's BEACON master: the
    generation in the cleartext counter selects the key, as for v2."""
    uid, ctr = peek_report(frame)
    return open_report(kdf(master, "beacon", uid, ctr_gen(ctr)), frame)


# ------------------------------------------- signed handheld command (0x44)
#
# DESIGN_finder_two_way.md sections 6 and 6A. A Handheld Receiver sends it in
# the receive window a collar opens after its own direct-radio frame. The
# server signs it under the device's COMMAND key (label CID-LORA-CMD, a
# master that never leaves the server); the collar opens it, checks the
# counter (strictly above the last accepted, persisted before acting) and the
# freshness, and runs the DownlinkPacket inside it as if it came over LoRaWAN.
#
#   [0]          0x44                     magic ('D')
#   [1..4]       uid32                    cleartext
#   [5..8]       cmd_counter              cleartext; [31:24] provision
#                                         generation, [23:0] sequence
#   [9..20]      ciphertext of echo u32 || valid_from u32 || valid_to u32
#   [21..21+n-1] ciphertext of the DownlinkPacket bytes (n = 1..226)
#   last 8       tag
#   AAD = bytes [0..8], nonce = uid || ctr || 0x01 || 0^4
#
# Freshness: echo != 0 binds it to the collar frame that opened the window
# (that frame's echo, as the INTENT carries); else the command is pre-signed:
# valid_to must be set and now must lie in [valid_from, valid_to]. A collar
# with no valid clock answers a pre-signed command with nothing and does not
# use its counter up (the handheld's INTENT can give it the time).
#
# Acknowledgement (0x4B), sealed by the collar under the same command key with
# the command's counter and dir 0x02 (the counter is accepted once, so this
# nonce is used once; a repeated last frame gets the same ACK bytes again):
#   [0] 0x4B  [1..4] uid  [5..8] the command's counter
#   ciphertext of result u8 || command u8 || detail u32 || rssi i8 || snr_q4 i8
#   8-byte tag                                                  25 bytes

MAGIC_COMMAND = 0x44                 # 'D'
MAGIC_COMMAND_ACK = 0x4B             # 'K'
COMMAND_FIXED = 12                   # echo, valid_from, valid_to
COMMAND_OVERHEAD = AAD_LEN + COMMAND_FIXED + TAG_LEN     # 29
COMMAND_MAX_LEN = 255
COMMAND_MIN_BODY = 1
COMMAND_MAX_BODY = COMMAND_MAX_LEN - COMMAND_OVERHEAD    # 226
COMMAND_ACK_BODY = 8
COMMAND_ACK_LEN = AAD_LEN + COMMAND_ACK_BODY + TAG_LEN   # 25

# Acknowledgement results (cmd_frame.h CMD_ACK_*).
ACK_ACCEPTED = 1          # opened, fresh, dispatched
ACK_NO_ADDON = 2          # detach command with no paired release unit
ACK_BAD_ECHO = 3          # echo set and not the frame that opened the window
ACK_EXPIRED = 4           # outside [valid_from, valid_to]
ACK_UNKNOWN_CMD = 5
ACK_QUEUE_FULL = 6
ACK_REFUSED_CARRIER = 7   # not allowed over the direct radio (BLE-only commands)
ACK_NO_CLOCK = 8          # reserved: a collar with no clock answers nothing instead
ACK_SESSION_OPEN = 9      # CMD_SESSION_OPEN accepted; detail = session SF
ACK_SESSION_CLOSED = 10   # CMD_SESSION_CLOSE accepted
ACK_CFG_NOT_USED = 11     # a settings piece the collar did not use; detail = the unfinished transaction in the way (0 = none)
ACK_BLE_REFUSED = 12      # CMD_BLE_WINDOW refused; detail = BLE_REFUSED_* (an opened window answers ACK_ACCEPTED, detail = minutes).
                          # 2026-11-16: also CMD_CARD_SUMMARY's card refusals (detail 3 no card, 7 index being built)
BLE_REFUSED_NO_KEY = 1    # no window key, or an all-zero one
BLE_REFUSED_RADIO = 2     # the radio cannot serve files (no bulk capability seen)
BLE_REFUSED_NO_CARD = 3   # location-only: no card to read
BLE_REFUSED_BATTERY = 4   # battery low or critical
BLE_REFUSED_UPDATING = 5  # a firmware update is running
BLE_REFUSED_RANGE = 6     # 2026-11-16: kinds has audio (bit 2; 2026-11-27: or the sound log, bit 4) and audio_from/audio_to is missing, reversed or over 86400 s
BLE_REFUSED_CARD_INDEX = 7  # 2026-11-16, CMD_CARD_SUMMARY: the card's day index is still being built (ask again later)
# 2026-11-26, a window with the update kind (BleWindow.kinds bit 3, downlink.proto):
BLE_REFUSED_IMAGE_LEN = 8     # image_len outside 1024 .. 2048000 (the room of a bank)
BLE_REFUSED_IMAGE_HASH = 9    # image_sha256 or image_sig absent (all zeros)
BLE_REFUSED_IMAGE_BUILD = 10  # image_build is not above the collar's own build
BLE_REFUSED_NO_RELEASE_KEY = 11   # the collar has no release public key
BLE_REFUSED_UPDATE_BATTERY = 12   # battery below 50 %
BLE_REFUSED_WINDOW_OPEN = 13  # a window is open already
BLE_REFUSED_UPDATE_CARRIER = 14   # the update kind did not come in a signed direct-radio frame (LoRaWAN, the tunnel): checked first

# BleWindow.kinds (downlink.proto, 2026-11-16): what a window opened by
# CMD_BLE_WINDOW serves (../bulk/README.md "What a window serves"). 0 = all.
BLE_FILES_KIND_LOG = 1    # the card log, /METADATA.CSV
BLE_FILES_KIND_ACCEL = 2  # movement data: /accelerometer/ (and /accelerometer_recovery/)
BLE_FILES_KIND_AUDIO = 4  # sound: takes overlapping [audio_from, audio_to] (start up to an hour before), range at most 24 h
BLE_FILES_KIND_UPDATE = 8  # 2026-11-26: the window takes one image of the collar's main software (../bulk/README.md "An image towards the collar")
BLE_FILES_KIND_SOUNDLOG = 16  # 2026-11-27: the sound logs (<take>.lvl) of the takes overlapping [audio_from, audio_to], no sound
BLE_UPDATE_IMAGE_MIN = 1024
BLE_UPDATE_IMAGE_MAX = 2048000    # a bank (2 MB) less the 48 KB of the flash stores at its end
BLE_UPDATE_MIN_BATTERY_PCT = 50
BLE_FILES_AUDIO_SPAN_MAX_S = 86400
BLE_FILES_TAKE_MAX_S = 3600   # the longest a take runs (hourly file rotation): the overlap reaches back this far

Command = namedtuple("Command", "uid ctr gen seq echo valid_from valid_to body")
CommandAck = namedtuple("CommandAck", "uid ctr result command detail rssi snr_q4")


def header_command(uid, ctr, magic=MAGIC_COMMAND):
    """The 9 cleartext bytes of a command (or ACK) frame, also its AAD."""
    if not 0 <= uid <= 0xFFFFFFFF or not 0 <= ctr <= 0xFFFFFFFF:
        raise ValueError("uid and ctr are uint32")
    return bytes([magic]) + uid.to_bytes(4, "little") + ctr.to_bytes(4, "little")


def seal_command(cmd_key, uid, ctr, body, echo=0, valid_from=0, valid_to=0):
    """Build a signed command frame (len(body) + 29 bytes) carrying the
    DownlinkPacket bytes `body` (1..226), under the device's COMMAND key."""
    body = bytes(body)
    if not COMMAND_MIN_BODY <= len(body) <= COMMAND_MAX_BODY:
        raise ValueError("command body must be %d..%d bytes" % (COMMAND_MIN_BODY, COMMAND_MAX_BODY))
    for v, what in ((echo, "echo"), (valid_from, "valid_from"), (valid_to, "valid_to")):
        if not 0 <= v <= 0xFFFFFFFF:
            raise ValueError("%s is uint32" % what)
    hdr = header_command(uid, ctr)
    pt = (echo.to_bytes(4, "little") + valid_from.to_bytes(4, "little")
          + valid_to.to_bytes(4, "little") + body)
    ct, tag = ccm_seal(cmd_key, nonce(uid, ctr, DIR_COMMAND), hdr, pt, TAG_LEN)
    frame = hdr + ct + tag
    assert len(frame) == len(body) + COMMAND_OVERHEAD
    return frame


def peek_command(frame):
    """(uid, ctr) from a command frame's cleartext header; no key needed."""
    frame = bytes(frame)
    if not COMMAND_OVERHEAD + COMMAND_MIN_BODY <= len(frame) <= COMMAND_MAX_LEN or frame[0] != MAGIC_COMMAND:
        raise ValueError("not a command frame")
    return int.from_bytes(frame[1:5], "little"), int.from_bytes(frame[5:9], "little")


def open_command(cmd_key, frame):
    """Open and verify a command frame. Raises AuthError on a bad tag."""
    frame = bytes(frame)
    uid, ctr = peek_command(frame)
    pt = ccm_open(cmd_key, nonce(uid, ctr, DIR_COMMAND), frame[:AAD_LEN],
                  frame[AAD_LEN:-TAG_LEN], frame[-TAG_LEN:], TAG_LEN)
    echo = int.from_bytes(pt[0:4], "little")
    vf = int.from_bytes(pt[4:8], "little")
    vt = int.from_bytes(pt[8:12], "little")
    return Command(uid, ctr, ctr_gen(ctr), ctr_seq(ctr), echo, vf, vt, pt[12:])


def command_fresh(cmd, echo_expected, now):
    """The collar's freshness rule: a live echo match, or a closed window
    (cmd_frame.h cmd_frame_fresh)."""
    if cmd.echo != 0:
        return cmd.echo == echo_expected
    return cmd.valid_to != 0 and cmd.valid_from <= now <= cmd.valid_to


def _i8(v, what):
    if not -128 <= v <= 127:
        raise ValueError("%s is int8" % what)
    return v & 0xFF


def seal_command_ack(cmd_key, uid, ctr, result, command, detail=0, rssi=0, snr_q4=0):
    """The collar's 25-byte acknowledgement of the command with counter ctr."""
    if not 0 <= result <= 255 or not 0 <= command <= 255 or not 0 <= detail <= 0xFFFFFFFF:
        raise ValueError("result and command are uint8, detail uint32")
    hdr = header_command(uid, ctr, MAGIC_COMMAND_ACK)
    pt = (bytes([result, command]) + detail.to_bytes(4, "little")
          + bytes([_i8(rssi, "rssi"), _i8(snr_q4, "snr_q4")]))
    ct, tag = ccm_seal(cmd_key, nonce(uid, ctr, DIR_COMMAND_ACK), hdr, pt, TAG_LEN)
    return hdr + ct + tag


def open_command_ack(cmd_key, frame):
    frame = bytes(frame)
    if len(frame) != COMMAND_ACK_LEN or frame[0] != MAGIC_COMMAND_ACK:
        raise ValueError("not a command acknowledgement")
    uid = int.from_bytes(frame[1:5], "little")
    ctr = int.from_bytes(frame[5:9], "little")
    pt = ccm_open(cmd_key, nonce(uid, ctr, DIR_COMMAND_ACK), frame[:AAD_LEN],
                  frame[AAD_LEN:-TAG_LEN], frame[-TAG_LEN:], TAG_LEN)
    rssi = pt[6] - 256 if pt[6] > 127 else pt[6]
    snr = pt[7] - 256 if pt[7] > 127 else pt[7]
    return CommandAck(uid, ctr, pt[0], pt[1], int.from_bytes(pt[2:6], "little"), rssi, snr)


# ------------------------------------------------- LoRa wake: the wake frame (0x57)
#
# Added 2026-11-13 (collarID_thread docs/CONTRACT_lora_wake.md; README "Wake
# frame"). A Handheld Receiver calls sleeping collars with a TRAIN of wake
# frames, sent back to back on the wake channel for a little longer than the
# collars' listening interval. A listening collar opens its receiver for one
# short window per interval and so catches one frame of the train. The frame
# is cleartext and unauthenticated: it only says "collars with these tags,
# stay up for what follows". What follows, an INTENT and then signed 0x44
# commands, or a signed roll call (0x43, below), is where the authority is.
#
#   [0]      0x57            magic ('W')
#   [1]      flags           bit 0 MORE: the tag list continues in the
#                                  alternating frame (more than 4 collars called)
#                            bit 1 LONG: sent at the long-range setting (for
#                                  the record; it changes nothing)
#                            bit 2 ROLL: a roll call follows the train; no tags
#                            bits 3..7 = 0 (a frame with any set is ignored)
#   [2..3]   u16 time left   10 ms units, from the END of this frame to the
#                            END of the train's last frame (0 in the last one)
#   [4]      u8  k           number of tags, 1..4 (0 with ROLL, and only then)
#   [5..]    k x u16 tags    tag(uid) = fmix32(uid ^ 'WAKE') & 0xFFFF
#                                                    5 + 2k = 5..13 bytes

MAGIC_WAKE = 0x57                    # 'W'
WAKE_SYNC_WORD = 0x57                # LoRa sync word of every frame on the wake channel
WAKE_HEADER_LEN = 5
WAKE_MAX_TAGS = 4
WAKE_MAX_LEN = WAKE_HEADER_LEN + 2 * WAKE_MAX_TAGS     # 13
WAKE_FLAG_MORE = 0x01
WAKE_FLAG_LONG = 0x02
WAKE_FLAG_ROLL = 0x04
WAKE_FLAGS_DEFINED = WAKE_FLAG_MORE | WAKE_FLAG_LONG | WAKE_FLAG_ROLL
WAKE_SALT = 0x57414B45               # 'WAKE': the tag's salt, and the roll-call slot's
WAKE_TIME_UNIT_MS = 10               # the time-left field counts 10 ms
WAKE_TIME_LEFT_MAX = 0xFFFF          # 655.35 s
WAKE_TRAIN_MAX_COLLARS = 2 * WAKE_MAX_TAGS             # 8: two alternating lists

# Why a parser refused a frame (WakeFrameError.reason), in the order checked.
WAKE_REFUSALS = ("length",           # not 5..13 bytes
                 "magic",            # byte 0 is not 0x57
                 "reserved_flags",   # a flag bit 3..7 is set
                 "tag_count",        # k above 4
                 "tag_bytes",        # the length is not 5 + 2k
                 "no_tags",          # k = 0 without ROLL
                 "roll_with_tags",   # ROLL with k above 0
                 "roll_with_more")   # ROLL with MORE: there is no list to continue

WakeFrame = namedtuple("WakeFrame", "flags more long_range roll time_left_10ms tags")


class WakeFrameError(ValueError):
    """Not a wake frame a collar acts on; .reason is one of WAKE_REFUSALS."""

    def __init__(self, reason):
        ValueError.__init__(self, "not a wake frame: %s" % reason)
        self.reason = reason


def send_phase_mix(x):
    """The collar firmware's send_phase_mix (send_phase.h): murmur3's 32-bit
    finalizer, so neighbouring uids land far apart."""
    if not 0 <= x <= 0xFFFFFFFF:
        raise ValueError("a uint32")
    x ^= x >> 16
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x ^= x >> 13
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x ^= x >> 16
    return x


def wake_tag(uid):
    """The 16 bits a wake frame names a collar by. Two collars share a tag
    once in 65,536: the other then stays up for nothing, because the INTENT
    that follows carries the whole uid."""
    if not 0 <= uid <= 0xFFFFFFFF:
        raise ValueError("uid must be a uint32")
    return send_phase_mix(uid ^ WAKE_SALT) & 0xFFFF


def wake_frame(tags, time_left_10ms, more=False, long_range=False, roll=False):
    """Build one wake frame: up to 4 tags (none with roll), the time left in
    the train after this frame in 10 ms units."""
    tags = list(tags)
    if not 0 <= time_left_10ms <= WAKE_TIME_LEFT_MAX:
        raise ValueError("time left is a uint16 of 10 ms units")
    if len(tags) > WAKE_MAX_TAGS:
        raise ValueError("at most %d tags in a frame" % WAKE_MAX_TAGS)
    if roll and (tags or more):
        raise ValueError("a roll-call frame carries no tags and no MORE")
    if not roll and not tags:
        raise ValueError("a frame without tags is a roll-call frame")
    for t in tags:
        if not 0 <= t <= 0xFFFF:
            raise ValueError("a tag is 16 bits")
    flags = ((WAKE_FLAG_MORE if more else 0) | (WAKE_FLAG_LONG if long_range else 0)
             | (WAKE_FLAG_ROLL if roll else 0))
    frame = (bytes([MAGIC_WAKE, flags]) + time_left_10ms.to_bytes(2, "little") + bytes([len(tags)])
             + b"".join(t.to_bytes(2, "little") for t in tags))
    assert len(frame) == WAKE_HEADER_LEN + 2 * len(tags)
    return frame


def parse_wake_frame(frame):
    """Decode a wake frame as a collar does. Raises WakeFrameError (its
    reason says why) for anything a collar does not act on."""
    frame = bytes(frame)
    if not WAKE_HEADER_LEN <= len(frame) <= WAKE_MAX_LEN:
        raise WakeFrameError("length")
    if frame[0] != MAGIC_WAKE:
        raise WakeFrameError("magic")
    flags, k = frame[1], frame[4]
    if flags & ~WAKE_FLAGS_DEFINED:
        raise WakeFrameError("reserved_flags")
    if k > WAKE_MAX_TAGS:
        raise WakeFrameError("tag_count")
    if len(frame) != WAKE_HEADER_LEN + 2 * k:
        raise WakeFrameError("tag_bytes")
    roll = bool(flags & WAKE_FLAG_ROLL)
    more = bool(flags & WAKE_FLAG_MORE)
    if k == 0 and not roll:
        raise WakeFrameError("no_tags")
    if roll and k:
        raise WakeFrameError("roll_with_tags")
    if roll and more:
        raise WakeFrameError("roll_with_more")
    tags = tuple(int.from_bytes(frame[5 + 2 * i:7 + 2 * i], "little") for i in range(k))
    return WakeFrame(flags, more, bool(flags & WAKE_FLAG_LONG), roll,
                     int.from_bytes(frame[2:4], "little"), tags)


def wake_verdict(frame, uid):
    """What a parsed frame means to the collar with this uid:
      "called"      its tag is in the frame: wait for the train's end, then
                    for the INTENT
      "roll"        a roll-call train: wait for its end, then for the roll call
      "more"        its tag is not here but the list continues: read one more
                    frame before giving up
      "not_called"  back to listening, nothing charged"""
    if frame.roll:
        return "roll"
    if wake_tag(uid) in frame.tags:
        return "called"
    return "more" if frame.more else "not_called"


def wake_train_lists(uids):
    """The tag list or lists of a train that calls these collars (1..8): one
    list for up to 4, else two (the first four, then the rest), which the
    train's frames carry in turn, every frame with MORE set. How a train
    splits its collars is the sender's choice; this is the reference's."""
    uids = list(uids)
    if not 1 <= len(uids) <= WAKE_TRAIN_MAX_COLLARS:
        raise ValueError("a train calls 1..%d collars" % WAKE_TRAIN_MAX_COLLARS)
    tags = [wake_tag(u) for u in uids]
    if len(tags) <= WAKE_MAX_TAGS:
        return [tags]
    return [tags[:WAKE_MAX_TAGS], tags[WAKE_MAX_TAGS:]]


def wake_train_frame(uids, index, time_left_10ms, long_range=False):
    """Frame number `index` (0 = first) of the train that calls these collars."""
    lists = wake_train_lists(uids)
    return wake_frame(lists[index % len(lists)], time_left_10ms,
                      more=len(lists) > 1, long_range=long_range)


# ------------------------------------------- LoRa wake: regions and the wake channel
#
# The direct radio's region (ble.proto DirectRegion, LoRaConfig.region) picks
# the wake channel from this table, the same in the collar and the receiver.
# Every frame on it: coding rate 4/5, explicit header, CRC on, IQ normal, sync
# word 0x57; a 12-symbol preamble on wake frames and 8 on every other frame
# (a receiver set for 12 takes both). Transmit power is the device's
# direct-radio power, held to the table's cap.

DIRECT_REGION_AUTO = 0
DIRECT_REGION_US915 = 1
DIRECT_REGION_EU868 = 2
DIRECT_REGION_AU915 = 3
# 4..15 (2026-11-17, collarID_thread docs/CONTRACT_direct_regions.md section 9):
# the other rule sets of CollarID_protobufs contracts/collarid_contracts.json
# direct_regions; contracts/test_contracts.py holds this table to that one.
DIRECT_REGION_BR915 = 4
DIRECT_REGION_LA915 = 5
DIRECT_REGION_IN865 = 6
DIRECT_REGION_JP920 = 7
DIRECT_REGION_KR920 = 8
DIRECT_REGION_SG920 = 9
DIRECT_REGION_MY919 = 10
DIRECT_REGION_TH920 = 11
DIRECT_REGION_VN920 = 12
DIRECT_REGION_ID920 = 13
DIRECT_REGION_TW920 = 14
DIRECT_REGION_RU868 = 15
DIRECT_REGION_MAX = 15               # a setting above this is no region
WAKE_REGION_NONE = 0                 # what AUTO resolves to when nothing decides it: no listening
# ble.proto RadioRegion (the LoRaWAN region): NOT the numbers above.
LORAWAN_REGION_US915 = 0
LORAWAN_REGION_AU915 = 1
LORAWAN_REGION_EU868 = 2

WakeChannel = namedtuple("WakeChannel", "region name frequency_hz bw_khz sf sf_long max_dbm")
# max_dbm: the cap of the wake channel's band for a collar of unknown board
# (direct_regions, the generic device): 22 where the band allows it, less in
# Japan, Korea, Singapore, Vietnam, Indonesia and Russia. A device sends at
# its direct-radio power held to the cap for its own antenna and radio.
WAKE_TABLE = {
    DIRECT_REGION_US915: WakeChannel(DIRECT_REGION_US915, "US915", 919000000, 500, 9, 12, 22),
    DIRECT_REGION_EU868: WakeChannel(DIRECT_REGION_EU868, "EU868", 869525000, 125, 7, 10, 22),
    DIRECT_REGION_AU915: WakeChannel(DIRECT_REGION_AU915, "AU915", 919000000, 500, 9, 12, 22),
    DIRECT_REGION_BR915: WakeChannel(DIRECT_REGION_BR915, "BR915", 919000000, 500, 9, 12, 22),
    DIRECT_REGION_LA915: WakeChannel(DIRECT_REGION_LA915, "LA915", 919000000, 500, 9, 12, 22),
    DIRECT_REGION_IN865: WakeChannel(DIRECT_REGION_IN865, "IN865", 867000000, 125, 7, 10, 22),
    DIRECT_REGION_JP920: WakeChannel(DIRECT_REGION_JP920, "JP920", 922000000, 125, 7, 10, 13),
    DIRECT_REGION_KR920: WakeChannel(DIRECT_REGION_KR920, "KR920", 923100000, 125, 7, 10, 13),
    DIRECT_REGION_SG920: WakeChannel(DIRECT_REGION_SG920, "SG920", 922000000, 125, 7, 10, 21),
    DIRECT_REGION_MY919: WakeChannel(DIRECT_REGION_MY919, "MY919", 922000000, 125, 7, 10, 22),
    DIRECT_REGION_TH920: WakeChannel(DIRECT_REGION_TH920, "TH920", 922000000, 125, 7, 10, 22),
    DIRECT_REGION_VN920: WakeChannel(DIRECT_REGION_VN920, "VN920", 922000000, 125, 7, 10, 15),
    DIRECT_REGION_ID920: WakeChannel(DIRECT_REGION_ID920, "ID920", 922000000, 125, 7, 10, 19),
    DIRECT_REGION_TW920: WakeChannel(DIRECT_REGION_TW920, "TW920", 923000000, 500, 9, 12, 22),
    DIRECT_REGION_RU868: WakeChannel(DIRECT_REGION_RU868, "RU868", 869100000, 125, 7, 10, 21),
}
# The three regions of the wake contract (2026-11-13), whose rows the wake
# vectors' "regions" section keeps; contracts_v1.json direct_regions has all.
WAKE_REGIONS_2026_11_13 = (DIRECT_REGION_US915, DIRECT_REGION_EU868, DIRECT_REGION_AU915)
WAKE_PREAMBLE_SYMBOLS = 12           # wake frames
LORA_PREAMBLE_SYMBOLS = 8            # every other frame on the wake channel


def direct_region_resolve(setting, lorawan_region=None, frequency_mhz=0):
    """The region a collar or receiver runs: 1..15 (1 US915, 2 EU868, 3
    AU915, 4..15 the other rule sets), or 0 for none (no listening). setting
    is the DirectRegion value; AUTO takes the LoRaWAN region when LoRaWAN is
    configured (lorawan_region, a ble.proto RadioRegion value; None = not
    configured), else reads the direct radio's frequency in whole MHz:
    863..870 is EU868, 902..928 is US915, never AU915. A setting above 15 is
    no region (old, to 2026-11-17: above 3)."""
    if 1 <= setting <= DIRECT_REGION_MAX:
        return setting
    if setting != DIRECT_REGION_AUTO:
        return WAKE_REGION_NONE
    if lorawan_region is not None:
        return {LORAWAN_REGION_US915: DIRECT_REGION_US915,
                LORAWAN_REGION_AU915: DIRECT_REGION_AU915,
                LORAWAN_REGION_EU868: DIRECT_REGION_EU868}.get(lorawan_region, WAKE_REGION_NONE)
    if 863 <= frequency_mhz <= 870:
        return DIRECT_REGION_EU868
    if 902 <= frequency_mhz <= 928:
        return DIRECT_REGION_US915
    return WAKE_REGION_NONE


def wake_setting(region, long_range=False):
    """(frequency_hz, bw_khz, sf, max_dbm) of a resolved region's wake
    channel, standard or long range; None for no region."""
    ch = WAKE_TABLE.get(region)
    if ch is None:
        return None
    return ch.frequency_hz, ch.bw_khz, ch.sf_long if long_range else ch.sf, ch.max_dbm


# --------------------------------------------------- LoRa wake: timing
#
# Both ends compute these the same way, from the wake channel's SF and
# bandwidth. Whole microseconds throughout (every value below is one), so a
# C port in integers gets the same numbers; the *_ms helpers divide by 1000.
#
#   Ts          = 2^SF / BW                       one symbol
#   toa(n, p)   = (p + 4.25 + 8 + max(ceil((8n - 4 SF + 44) / (4 (SF - 2 DE))) x 5, 0)) x Ts
#                 n payload bytes, p preamble symbols; coding rate 4/5,
#                 explicit header, CRC on; DE = 1 when Ts > 16 ms, else 0
#   frame       = toa(13, 12)                     one full wake frame
#   tail        = toa(13, 8) - 8 Ts               a wake frame after its preamble
#   W           = tail + 16 Ts + 7 ms             the collar's listen window
#   cap         = 1.5 x frame + 20 ms             how long a detection may hold the collar
#   train       >= 1.03 x I + W + frame           I = the called collars' listening interval
#   intent_wait = 2 x toa(14, 8) + 150 ms         the collar's wait for the INTENT, from T0 - 10 ms
#   cmd_window  = toa(255, 8) + 300 ms            the existing command window
#   T0 = the end of the train: the caught frame's end + its time left.

WAKE_INTERVAL_CHOICES_S = (10, 30, 60)   # what configurators offer
WAKE_INTERVAL_MIN_S = 5                  # the firmware holds a non-zero interval to 5..120
WAKE_INTERVAL_MAX_S = 120
WAKE_SLOW_FACTOR_MAX = 4                 # over budget: the interval x2, at most x4, to the hour's end
WAKE_GAP_MAX_MS = 5                      # between one frame's end and the next one's start
WAKE_RX_LEAD_MS = 10                     # the collar receives from T0 - 10 ms
WAKE_FIRST_SEND_MS = 30                  # the handheld's INTENT (or roll call) goes out at T0 + 30 ms
CALL_SNIFF_S = 1                         # the interval while called, standard setting
CALL_SNIFF_LONG_S = 2                    # ... long range
CALLED_WAIT_S = 60                       # listening at CALL_SNIFF after a train, before any signed command
CALL_IDLE_S = 300                        # the call window ends this long after the last accepted command
CALL_MAX_S = 900                         # ... or this long after the first


def wake_interval_clamp(seconds):
    """The listening interval a collar runs: 0 stays 0 (not listening), any
    other value is held to 5..120 s."""
    if seconds < 0:
        raise ValueError("an interval is not negative")
    if seconds == 0:
        return 0
    return min(max(seconds, WAKE_INTERVAL_MIN_S), WAKE_INTERVAL_MAX_S)


def call_sniff_s(long_range=False):
    return CALL_SNIFF_LONG_S if long_range else CALL_SNIFF_S


def lora_symbol_us(sf, bw_khz):
    """Ts in microseconds."""
    if not 7 <= sf <= 12 or bw_khz not in (125, 250, 500):
        raise ValueError("SF7..12 at 125, 250 or 500 kHz")
    return (1 << sf) * 1000 // bw_khz


def lora_toa_us(sf, bw_khz, n, preamble=LORA_PREAMBLE_SYMBOLS):
    """Time on air of an n-byte frame with a p-symbol preamble, microseconds
    (coding rate 4/5, explicit header, CRC on)."""
    if not 0 <= n <= 255 or preamble < 0:
        raise ValueError("0..255 payload bytes")
    ts = lora_symbol_us(sf, bw_khz)
    de = 1 if ts > 16000 else 0
    num, den = 8 * n - 4 * sf + 44, 4 * (sf - 2 * de)
    payload_symbols = max(-(-num // den) * 5, 0)
    quarter_symbols = 4 * preamble + 17 + 32 + 4 * payload_symbols     # (p + 4.25 + 8 + payload) x 4
    return quarter_symbols * (ts // 4)                                   # ts is a multiple of 4 us


def wake_frame_us(sf, bw_khz):
    return lora_toa_us(sf, bw_khz, WAKE_MAX_LEN, WAKE_PREAMBLE_SYMBOLS)


def wake_tail_us(sf, bw_khz):
    return lora_toa_us(sf, bw_khz, WAKE_MAX_LEN, LORA_PREAMBLE_SYMBOLS) - 8 * lora_symbol_us(sf, bw_khz)


def wake_window_us(sf, bw_khz):
    """W: a window opened anywhere in a train holds 8 preamble symbols of
    some frame (the tail of one frame, 16 symbols, 5 ms of gap and 2 ms)."""
    return wake_tail_us(sf, bw_khz) + 16 * lora_symbol_us(sf, bw_khz) + 7000


def wake_cap_us(sf, bw_khz):
    return wake_frame_us(sf, bw_khz) * 3 // 2 + 20000


def wake_intent_wait_us(sf, bw_khz):
    return 2 * lora_toa_us(sf, bw_khz, 14) + 150000


def wake_cmd_window_us(sf, bw_khz):
    return lora_toa_us(sf, bw_khz, 255) + 300000


def wake_train_us(sf, bw_khz, interval_s):
    """The shortest train that reaches a collar listening every interval_s:
    3 % for the two clocks, one listen window and one frame over."""
    if interval_s < 1:
        raise ValueError("an interval of at least 1 s")
    return 1030000 * interval_s + wake_window_us(sf, bw_khz) + wake_frame_us(sf, bw_khz)


def wake_train_frames(sf, bw_khz, interval_s, gap_us=0):
    """How many frames make that train when gap_us lies between one frame's
    end and the next one's start (at most 5 ms): the fewest whose span, first
    start to last end, is at least wake_train_us. The sender's arithmetic,
    not a wire rule."""
    if not 0 <= gap_us <= WAKE_GAP_MAX_MS * 1000:
        raise ValueError("the gap is 0..5 ms")
    frame = wake_frame_us(sf, bw_khz)
    return -(-(wake_train_us(sf, bw_khz, interval_s) + gap_us) // (frame + gap_us))


def wake_time_left_10ms(us):
    """A time to the train's end as the frame's field: 10 ms units, rounded
    to the nearest (a half up), held to the field's 16 bits."""
    if us < 0:
        raise ValueError("time left is not negative")
    return min((us + 5000) // 10000, WAKE_TIME_LEFT_MAX)


def us_to_ms(us):
    return us / 1000.0


WakeTiming = namedtuple("WakeTiming", "ts_us frame_us tail_us w_us cap_us intent_wait_us cmd_window_us "
                                      "roll_wait_us roll_slot_min_us roll_slot_default_ms")


def wake_timing(sf, bw_khz):
    """Every timing constant of one wake setting."""
    return WakeTiming(lora_symbol_us(sf, bw_khz), wake_frame_us(sf, bw_khz), wake_tail_us(sf, bw_khz),
                      wake_window_us(sf, bw_khz), wake_cap_us(sf, bw_khz),
                      wake_intent_wait_us(sf, bw_khz), wake_cmd_window_us(sf, bw_khz),
                      roll_call_wait_us(sf, bw_khz), roll_call_slot_min_us(sf, bw_khz),
                      roll_call_slot_default_ms(sf, bw_khz))


# ---------------------------------------- LoRa wake: the roll call (0x43) and the wake key
#
# "Every collar of this group in range, answer once." Sent once by a Handheld
# Receiver 30 ms after the end of a train whose frames carry ROLL, on the
# wake channel. It cannot be unauthenticated (anyone could then make collars
# give themselves away), so it is sealed under the group's WAKE KEY:
#
#   wake_key = AES-CMAC(the owner's command master, "CID-LORA-WAK" || group_le32 || gen)
#
# one key for every collar of a group (the owner's account) and generation,
# installed over Bluetooth in key slot 2 (downlink.proto BEACON_KEY_SLOT_WAKE).
#
#   [0]      0x43                     magic ('C')
#   [1..4]   group u32                cleartext (key lookup)
#   [5..8]   counter u32              cleartext; [31:24] generation, [23:0]
#                                     strictly increasing per group
#   [9..20]  ciphertext of valid_from u32 || valid_to u32 || slots u8 ||
#            slot_ms u16 || flags u8 (0)
#   [21..28] tag                                              29 bytes
#   AAD = bytes [0..8]; nonce = group_le32 || ctr_le32 || 0x03 || 0x00000000
#
# A collar that accepts it sends ONE sealed beacon (0x4D, under its beacon
# key; a collar without one sends nothing) starting
#   300 ms + (fmix32(uid ^ 'WAKE' ^ counter) % slots) x slot_ms
# after the roll call's end, so the collars of a group spread over the slots
# and a new counter shuffles them again. The 300 ms are the collar's: it
# seals its beacon AFTER it has accepted the roll call (checking and sealing
# take it about 0.2 s), so a ROLL train that brings no valid roll call
# spends no beacon counter. The receiver listens for
#   300 ms + slots x slot_ms + 200 ms
# after sending the roll call.
# old: 50 ms + ... (to 2026-11-13: slots 0 and 1 could not be met in time)

MAGIC_ROLL_CALL = 0x43               # 'C'
DIR_ROLL_CALL = 0x03                 # the nonce's direction byte
ROLL_CALL_BODY_LEN = 12              # valid_from, valid_to, slots, slot_ms, flags
ROLL_CALL_LEN = AAD_LEN + ROLL_CALL_BODY_LEN + TAG_LEN     # 29
ROLL_CALL_SLOTS_MAX = 64
ROLL_CALL_SLOTS_DEFAULT = 32
ROLL_CALL_REPLY_LEN = LEN_V2         # the answer is a v2 beacon, 30 bytes
# old: ROLL_CALL_REPLY_BASE_MS = 50
ROLL_CALL_REPLY_BASE_MS = 300        # the first slot starts this long after the roll call's end
ROLL_CALL_SLOT_MARGIN_MIN_MS = 5     # a slot is at least the beacon's airtime + 5 ms
ROLL_CALL_SLOT_MARGIN_MS = 10        # ... and by default its airtime, rounded up, + 10 ms
ROLL_CALL_LISTEN_EXTRA_MS = 200      # the handheld listens 300 ms + slots x slot_ms + 200 ms
ROLL_CALL_MIN_GAP_S = 60             # a collar answers at most one roll call a minute

# Why a collar does not answer (roll_call_check), in the order checked.
ROLL_CALL_REFUSALS = ("frame",       # not 0x43 and 29 bytes
                      "no_key",      # the collar holds no wake key
                      "group",       # not the group of its key
                      "gen",         # the counter's generation is not its key's
                      "counter",     # not above the last roll call it accepted
                      "tag",         # the tag does not verify
                      "flags",       # a flag bit is set (none is defined)
                      "clock",       # the collar has no valid clock
                      "window",      # now is outside [valid_from, valid_to]
                      "slots",       # slots is not 1..64
                      "slot_ms",     # a slot is shorter than the beacon's airtime + 5 ms
                      "recent")      # it answered a roll call less than 60 s ago

RollCall = namedtuple("RollCall", "group ctr gen seq valid_from valid_to slots slot_ms flags")


def header_roll_call(group, ctr):
    """The 9 cleartext bytes of a roll call, also its AAD."""
    if not 0 <= group <= 0xFFFFFFFF or not 0 <= ctr <= 0xFFFFFFFF:
        raise ValueError("group and ctr are uint32")
    return bytes([MAGIC_ROLL_CALL]) + group.to_bytes(4, "little") + ctr.to_bytes(4, "little")


def pack_roll_call_body(valid_from, valid_to, slots, slot_ms, flags=0):
    for v, top, what in ((valid_from, 0xFFFFFFFF, "valid_from"), (valid_to, 0xFFFFFFFF, "valid_to"),
                         (slots, 0xFF, "slots"), (slot_ms, 0xFFFF, "slot_ms"), (flags, 0xFF, "flags")):
        if not 0 <= v <= top:
            raise ValueError("%s out of range" % what)
    return (valid_from.to_bytes(4, "little") + valid_to.to_bytes(4, "little") + bytes([slots])
            + slot_ms.to_bytes(2, "little") + bytes([flags]))


def seal_roll_call(wake_key, group, ctr, valid_from, valid_to, slots, slot_ms, flags=0):
    """Build the 29-byte roll call (the server's side). The codec seals any
    field values; what a collar accepts is roll_call_check."""
    hdr = header_roll_call(group, ctr)
    ct, tag = ccm_seal(wake_key, nonce(group, ctr, DIR_ROLL_CALL), hdr,
                       pack_roll_call_body(valid_from, valid_to, slots, slot_ms, flags), TAG_LEN)
    frame = hdr + ct + tag
    assert len(frame) == ROLL_CALL_LEN
    return frame


def peek_roll_call(frame):
    """(group, ctr) from a roll call's cleartext header; no key needed."""
    frame = bytes(frame)
    if len(frame) != ROLL_CALL_LEN or frame[0] != MAGIC_ROLL_CALL:
        raise ValueError("not a roll call")
    return int.from_bytes(frame[1:5], "little"), int.from_bytes(frame[5:9], "little")


def open_roll_call(wake_key, frame):
    """Open and verify a roll call. Raises AuthError on a bad tag."""
    frame = bytes(frame)
    group, ctr = peek_roll_call(frame)
    pt = ccm_open(wake_key, nonce(group, ctr, DIR_ROLL_CALL), frame[:AAD_LEN],
                  frame[AAD_LEN:-TAG_LEN], frame[-TAG_LEN:], TAG_LEN)
    return RollCall(group, ctr, ctr_gen(ctr), ctr_seq(ctr),
                    int.from_bytes(pt[0:4], "little"), int.from_bytes(pt[4:8], "little"),
                    pt[8], int.from_bytes(pt[9:11], "little"), pt[11])


def open_roll_call_with_master(command_master, frame):
    """Open a roll call holding the owner's COMMAND master: the group and the
    generation in the cleartext header select the wake key."""
    group, ctr = peek_roll_call(frame)
    return open_roll_call(kdf(command_master, "wake", group, ctr_gen(ctr)), frame)


def roll_call_wait_us(sf, bw_khz):
    """How long a collar that caught a ROLL train waits for the roll call,
    from T0 - 10 ms."""
    return 2 * lora_toa_us(sf, bw_khz, ROLL_CALL_LEN) + 150000


def roll_call_slot_min_us(sf, bw_khz):
    """The shortest slot a collar accepts: its answer's airtime + 5 ms."""
    return lora_toa_us(sf, bw_khz, ROLL_CALL_REPLY_LEN) + ROLL_CALL_SLOT_MARGIN_MIN_MS * 1000


def roll_call_slot_default_ms(sf, bw_khz):
    """The slot a server signs by default: the answer's airtime rounded up to
    a millisecond, + 10 ms."""
    return -(-lora_toa_us(sf, bw_khz, ROLL_CALL_REPLY_LEN) // 1000) + ROLL_CALL_SLOT_MARGIN_MS


def roll_call_listen_ms(slots, slot_ms):
    """How long the handheld listens after sending its roll call:
    300 ms + slots x slot_ms + 200 ms."""
    # old: return slots * slot_ms + ROLL_CALL_LISTEN_EXTRA_MS
    return ROLL_CALL_REPLY_BASE_MS + slots * slot_ms + ROLL_CALL_LISTEN_EXTRA_MS


def roll_call_slot(uid, ctr, slots):
    """The slot this collar answers in."""
    if not 1 <= slots <= 255:
        raise ValueError("slots is 1..255")
    return send_phase_mix(uid ^ WAKE_SALT ^ ctr) % slots


def roll_call_reply_delay_ms(uid, ctr, slots, slot_ms):
    """From the end of the roll call (the collar's RxDone) to the start of
    this collar's answer."""
    return ROLL_CALL_REPLY_BASE_MS + roll_call_slot(uid, ctr, slots) * slot_ms


def roll_call_check(frame, wake_key, group, gen, last_ctr, now, sf, bw_khz, since_answer_s=None):
    """The collar's rule. wake_key, group and gen are the wake key it holds
    (wake_key None = none); last_ctr is the last roll-call counter it
    accepted (0 = none yet); now is its clock in UTC seconds (None = no valid
    clock); sf and bw_khz are its wake setting; since_answer_s is how long
    ago it last answered a roll call (None = never). Returns (roll call,
    None) when it answers, else (None, reason), reason one of
    ROLL_CALL_REFUSALS. Only an accepted roll call moves last_ctr."""
    try:
        f_group, f_ctr = peek_roll_call(frame)
    except ValueError:
        return None, "frame"
    if wake_key is None:
        return None, "no_key"
    if f_group != group:
        return None, "group"
    if ctr_gen(f_ctr) != gen:
        return None, "gen"
    if f_ctr <= last_ctr:
        return None, "counter"
    try:
        rc = open_roll_call(wake_key, frame)
    except AuthError:
        return None, "tag"
    if rc.flags != 0:
        return None, "flags"
    if now is None:
        return None, "clock"
    if not rc.valid_from <= now <= rc.valid_to:
        return None, "window"
    if not 1 <= rc.slots <= ROLL_CALL_SLOTS_MAX:
        return None, "slots"
    if rc.slot_ms * 1000 < roll_call_slot_min_us(sf, bw_khz):
        return None, "slot_ms"
    if since_answer_s is not None and since_answer_s < ROLL_CALL_MIN_GAP_S:
        return None, "recent"
    return rc, None


def classify(frame):
    """'v1', 'v2', 'report', 'command', 'command_ack', 'wake', 'roll_call' or
    None, by magic byte and length only. A plaintext report starts 0x0A (its
    protobuf header field), so it is None here, never 'report'."""
    frame = bytes(frame)
    if len(frame) == LEN_V1 and frame[0] == MAGIC_V1:
        return "v1"
    if len(frame) == LEN_V2 and frame[0] == MAGIC_V2:
        return "v2"
    if REPORT_MIN_LEN <= len(frame) <= REPORT_MAX_LEN and frame[0] == MAGIC_REPORT:
        return "report"
    if COMMAND_OVERHEAD + COMMAND_MIN_BODY <= len(frame) <= COMMAND_MAX_LEN and frame[0] == MAGIC_COMMAND:
        return "command"
    if len(frame) == COMMAND_ACK_LEN and frame[0] == MAGIC_COMMAND_ACK:
        return "command_ack"
    if WAKE_HEADER_LEN <= len(frame) <= WAKE_MAX_LEN and frame[0] == MAGIC_WAKE:
        return "wake"
    if len(frame) == ROLL_CALL_LEN and frame[0] == MAGIC_ROLL_CALL:
        return "roll_call"
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
    d.add_argument("--uid", type=_uid, required=True,
                   help="on-air uid32 (0x... or decimal); the group for --purpose wake")
    d.add_argument("--gen", type=int, required=True, help="provision generation 1..255")
    d.add_argument("--purpose", choices=sorted(PURPOSES), default="beacon")
    k = sub.add_parser("kcv", help="key check value of a key")
    k.add_argument("--key", type=_hex, required=True)
    v = sub.add_parser("v1", help="decode a v1 frame")
    v.add_argument("frame", type=_hex, help="18 bytes hex")
    rp = sub.add_parser("report-peek", help="uid and counter of a sealed report (0x52), no key")
    rp.add_argument("frame", type=_hex, help="18..255 bytes hex")
    ro = sub.add_parser("report-open", help="open a sealed report (0x52)")
    rg = ro.add_mutually_exclusive_group(required=True)
    rg.add_argument("--key", type=_hex, help="device beacon key, 16 bytes hex")
    rg.add_argument("--master", type=_hex, help="owner's beacon master, 16 bytes hex")
    ro.add_argument("frame", type=_hex, help="18..255 bytes hex")
    rs = sub.add_parser("report-seal", help="seal a report payload into a 0x52 frame")
    rs.add_argument("--key", type=_hex, required=True, help="device beacon key, 16 bytes hex")
    rs.add_argument("--uid", type=_uid, required=True, help="on-air uid32 (0x... or decimal)")
    rs.add_argument("--ctr", type=_uid, required=True, help="tx_counter, gen<<24 | seq (0x... or decimal)")
    rs.add_argument("payload", type=_hex, help="the report's plaintext bytes, 1..238, hex")
    wt = sub.add_parser("wake-tag", help="the 16-bit tag a wake frame (0x57) names a collar by")
    wt.add_argument("uids", type=_uid, nargs="+", help="on-air uid32 (0x... or decimal)")
    wp = sub.add_parser("wake-parse", help="decode a wake frame (0x57)")
    wp.add_argument("frame", type=_hex, help="5..13 bytes hex")
    wp.add_argument("--uid", type=_uid, help="also say what the frame means to this collar")
    wm = sub.add_parser("wake-timing", help="the timing constants of a wake setting")
    wm.add_argument("--region", required=True, choices=sorted(c.name for c in WAKE_TABLE.values()))
    wm.add_argument("--long", action="store_true", help="the long-range setting")
    wm.add_argument("--interval", type=int, default=30, help="the collars' listening interval, s")
    rc = sub.add_parser("roll-open", help="open a roll call (0x43)")
    rcg = rc.add_mutually_exclusive_group(required=True)
    rcg.add_argument("--key", type=_hex, help="the group's wake key, 16 bytes hex")
    rcg.add_argument("--master", type=_hex, help="the owner's command master, 16 bytes hex")
    rc.add_argument("frame", type=_hex, help="29 bytes hex")
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
    elif a.cmd == "report-peek":
        uid, ctr = peek_report(a.frame)
        print(json.dumps({"uid": uid, "ctr": ctr, "gen": ctr_gen(ctr), "seq": ctr_seq(ctr),
                          "len": len(a.frame), "payload_len": len(a.frame) - REPORT_OVERHEAD}))
    elif a.cmd == "report-open":
        try:
            r = open_report_with_master(a.master, a.frame) if a.master else open_report(a.key, a.frame)
        except AuthError as e:
            print(json.dumps({"error": "authentication failed", "detail": str(e)}))
            return 1
        print(json.dumps({"uid": r.uid, "ctr": r.ctr, "gen": r.gen, "seq": r.seq,
                          "payload": r.payload.hex()}))
    elif a.cmd == "report-seal":
        frame = seal_report(a.key, a.uid, a.ctr, a.payload)
        print(json.dumps({"frame": frame.hex(), "len": len(frame)}))
    elif a.cmd == "wake-tag":
        print(json.dumps([{"uid": "0x%08X" % u, "tag": wake_tag(u), "tag_hex": "%04x" % wake_tag(u)}
                          for u in a.uids]))
    elif a.cmd == "wake-parse":
        try:
            f = parse_wake_frame(a.frame)
        except WakeFrameError as e:
            print(json.dumps({"error": "not a wake frame", "reason": e.reason}))
            return 1
        out = f._asdict()
        out["time_left_ms"] = f.time_left_10ms * WAKE_TIME_UNIT_MS
        if a.uid is not None:
            out["tag"] = wake_tag(a.uid)
            out["verdict"] = wake_verdict(f, a.uid)
        print(json.dumps(out))
    elif a.cmd == "wake-timing":
        ch = [c for c in WAKE_TABLE.values() if c.name == a.region][0]
        sf = ch.sf_long if a.long else ch.sf
        t = wake_timing(sf, ch.bw_khz)
        out = {"region": ch.name, "frequency_hz": ch.frequency_hz, "bw_khz": ch.bw_khz, "sf": sf,
               "long_range": a.long, "interval_s": a.interval,
               "train_ms": us_to_ms(wake_train_us(sf, ch.bw_khz, a.interval)),
               "roll_slot_default_ms": t.roll_slot_default_ms}
        out.update((k[:-3] + "_ms", us_to_ms(v)) for k, v in t._asdict().items() if k.endswith("_us"))
        print(json.dumps(out))
    elif a.cmd == "roll-open":
        try:
            r = open_roll_call_with_master(a.master, a.frame) if a.master else open_roll_call(a.key, a.frame)
        except AuthError as e:
            print(json.dumps({"error": "authentication failed", "detail": str(e)}))
            return 1
        print(json.dumps(r._asdict()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
