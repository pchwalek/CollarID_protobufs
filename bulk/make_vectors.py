#!/usr/bin/env python3
"""Generate bulk/vectors.json from the reference codec (bulk_v1.py).

    python3 make_vectors.py            rewrite vectors.json
    python3 make_vectors.py --check    exit 1 if vectors.json is stale

Frozen once published, like beacon/vectors.json: the collar firmware's host
tests (collarID_thread test/host/test_ble_bulk_proto.cpp) replay every
transcript byte for byte. A change is a protocol version, never a rewrite.

Everything here is synthetic: no real uid, key or file.

A transcript is a list of steps. Each step: the request the phone writes,
the tick the collar uses for that request (its challenge input), and the
bytes the collar sends back: its immediate answer, then `pull` frames of a
running READ (-1 = until the READ ends). The collar's settings for the
transcript (uid, key or none, window_left_s, data_max) and its files
(sorted by name in every directory, as the model lists them) are in the
transcript's header.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bulk_v1 as b  # noqa: E402

OUT = os.path.join(HERE, "vectors.json")
FORMAT = "collarid-bulk-v1-vectors"

UID = 0x00C0FFEE
KEY = bytes(range(0x40, 0x50))
CNONCE = bytes(range(0xA0, 0xA8))
WINDOW_S = 600
DATA_MAX = 64


def files():
    gps = bytes((i * 7 + 3) & 0xFF for i in range(300))
    flac = b"fLaC" + bytes((i * 13) & 0xFF for i in range(196))
    ring = bytes((0xC0 + i) & 0xFF for i in range(130))
    cfg = b"engaged,1\nverbose_logging,0\nlora_sf,7\n\n"
    return ({"/CONFIG.CSV": cfg,
             "/2026/11/12/GPS_0012.CSV": gps,
             "/2026/11/12/AUDIO/12-00-00.flac": flac,
             "/uplink_ring.bin": ring},
            {"/CONFIG.CSV": 1762905600,
             "/2026/11/12/GPS_0012.CSV": 1762948800,
             "/2026/11/12/AUDIO/12-00-00.flac": 1762948800,
             "/uplink_ring.bin": 1762952400})


def run(model, steps):
    out = []
    for st in steps:
        model.tick = st["tick"]
        req = st["req"]
        ans = model.on_request(req)
        pull = st.get("pull", -1)
        n = 0
        while pull < 0 or n < pull:
            f = model.next_stream()
            if not f:
                break
            ans += f
            n += 1
        out.append(dict(note=st["note"], tick=st["tick"], pull=pull, req=req.hex(), ans=ans.hex()))
    return out


def keyed_transcript():
    fs, mt = files()
    m = b.CollarModel(UID, fs, key=KEY, mtimes=mt, window_s=WINDOW_S, data_max=DATA_MAX)
    m.tick = 0
    # the collar's challenge is known once the HELLO is answered: replay to get it
    chal = b.challenge(KEY, UID, 1, 0x1001)
    tag = b.auth_tag(KEY, UID, chal, CNONCE)
    ks = b.session_key(KEY, UID, chal, CNONCE)
    gps = "/2026/11/12/GPS_0012.CSV"
    steps = [
        dict(note="STAT before AUTH: auth required", tick=0x1000, req=b.stat_req(1, gps)),
        dict(note="HELLO", tick=0x1001, req=b.hello_req(2, CNONCE)),
        dict(note="AUTH with a wrong tag", tick=0x1002, req=b.auth_req(3, bytes(16))),
        dict(note="AUTH", tick=0x1003, req=b.auth_req(4, tag)),
        dict(note="STAT a file (ctr 0)", tick=0x1004, req=b.stat_req(5, gps, ks, 0)),
        dict(note="LIST / (ctr 1)", tick=0x1005, req=b.list_req(6, "/", 0, ks, 1)),
        dict(note="LIST a day (ctr 2)", tick=0x1006, req=b.list_req(7, "/2026/11/12", 0, ks, 2)),
        dict(note="READ a whole file (ctr 3)", tick=0x1007, req=b.read_req(8, gps, 0, 0, ks, 3)),
        dict(note="READ a range (ctr 4)", tick=0x1008, req=b.read_req(9, gps, 100, 50, ks, 4)),
        dict(note="a MAC under the wrong counter", tick=0x1009, req=b.stat_req(10, gps, ks, 9)),
        dict(note="STAT a missing file (ctr 5)", tick=0x100A, req=b.stat_req(11, "/NOPE.TXT", ks, 5)),
        dict(note="READ a directory (ctr 6)", tick=0x100B, req=b.read_req(12, "/2026", 0, 0, ks, 6)),
        dict(note="LIST a file (ctr 7)", tick=0x100C, req=b.list_req(13, "/CONFIG.CSV", 0, ks, 7)),
        dict(note="STAT a bad path (ctr 8)", tick=0x100D, req=b.request(b.OP_STAT, 14, b"/../x", ks, 8)),
        dict(note="READ past the end (ctr 9)", tick=0x100E, req=b.read_req(15, gps, 1000, 0, ks, 9)),
        dict(note="READ, two frames, then CANCEL (ctr 10)", tick=0x100F, pull=2,
             req=b.read_req(16, "/uplink_ring.bin", 0, 0, ks, 10)),
        dict(note="CANCEL mid-READ (ctr 11)", tick=0x1010, req=b.cancel_req(17, ks, 11)),
        dict(note="an unknown op (ctr 12)", tick=0x1011, req=b.request(0x09, 18, b"", ks, 12)),
        dict(note="BYE (ctr 13)", tick=0x1012, req=b.bye_req(19, ks, 13)),
    ]
    head = dict(uid=UID, key=KEY.hex(), window_s=WINDOW_S, data_max=DATA_MAX,
                cnonce=CNONCE.hex(), challenge=chal.hex(), auth_tag=tag.hex(),
                session_key=ks.hex(), proof=b.proof(KEY, UID, chal, CNONCE).hex())
    return head, run(m, steps)


def open_transcript():
    fs, mt = files()
    m = b.CollarModel(UID, fs, key=None, mtimes=mt, window_s=WINDOW_S, data_max=DATA_MAX)
    steps = [
        dict(note="HELLO, no key", tick=0x2000, req=b.hello_req(1, CNONCE)),
        dict(note="AUTH not needed", tick=0x2001, req=b.auth_req(2, bytes(16))),
        dict(note="LIST a folder", tick=0x2002, req=b.list_req(3, "/2026/11/12/AUDIO")),
        dict(note="READ a file", tick=0x2003, req=b.read_req(4, "/CONFIG.CSV")),
        dict(note="CANCEL with nothing running", tick=0x2004, req=b.cancel_req(5)),
        dict(note="a short READ payload", tick=0x2005, req=b.request(b.OP_READ, 6, b"\x00" * 5)),
        dict(note="LIST page 2 of /", tick=0x2006, req=b.list_req(7, "/", 1)),
    ]
    return dict(uid=UID, key=None, window_s=WINDOW_S, data_max=DATA_MAX), run(m, steps)


BATTERY = (64, 3850, 20)   # INFO's synthetic battery: 64 %, 3.850 V, closes itself at 20 %


def info_transcript():
    """INFO (op 0x08, 2026-11-16): a keyed window; before and after AUTH,
    with a payload, in the middle of a READ (answered at once, the READ goes
    on), then BYE. A new transcript: the keyed and open ones are unchanged."""
    fs, mt = files()
    m = b.CollarModel(UID, fs, key=KEY, mtimes=mt, window_s=WINDOW_S, data_max=DATA_MAX, battery=BATTERY)
    chal = b.challenge(KEY, UID, 1, 0x3001)
    tag = b.auth_tag(KEY, UID, chal, CNONCE)
    ks = b.session_key(KEY, UID, chal, CNONCE)
    gps = "/2026/11/12/GPS_0012.CSV"
    steps = [
        dict(note="INFO before AUTH: auth required", tick=0x3000, req=b.info_req(1)),
        dict(note="HELLO", tick=0x3001, req=b.hello_req(2, CNONCE)),
        dict(note="AUTH", tick=0x3002, req=b.auth_req(3, tag)),
        dict(note="INFO (ctr 0)", tick=0x3003, req=b.info_req(4, ks, 0)),
        dict(note="INFO with a payload (ctr 1): bad request", tick=0x3004,
             req=b.request(b.OP_INFO, 5, b"\x01", ks, 1)),
        dict(note="READ, two frames (ctr 2)", tick=0x3005, pull=2, req=b.read_req(6, gps, 0, 0, ks, 2)),
        dict(note="INFO mid-READ (ctr 3): answered at once, then the READ goes on", tick=0x3006,
             req=b.info_req(7, ks, 3)),
        dict(note="BYE (ctr 4)", tick=0x3007, req=b.bye_req(8, ks, 4)),
    ]
    head = dict(uid=UID, key=KEY.hex(), window_s=WINDOW_S, data_max=DATA_MAX, cnonce=CNONCE.hex(),
                battery_pct=BATTERY[0], battery_mv=BATTERY[1], floor_pct=BATTERY[2])
    return head, run(m, steps)


IMAGE_BUILD = 700
IMAGE_SIG = bytes(range(0x80, 0xC0))    # a stand-in: the transcript's collar accepts this one signature


def image():
    """A synthetic image: a stack pointer and a reset vector the collar's
    shape check takes, its build stamp, 1200 bytes in all."""
    import struct
    head = struct.pack("<II", 0x20270000, 0x08001235)
    body = bytes((i * 11 + 5) & 0xFF for i in range(500)) + b"FWBUILD:%d:" % IMAGE_BUILD
    img = head + body
    return img + bytes((i * 3 + 1) & 0xFF for i in range(1200 - len(img)))


def image_transcript():
    """An image towards the collar (ops 0x09..0x0B, 2026-11-26): a keyed
    window whose command named the image. The edges first, then a delivery
    with one byte wrong (refused at IMG_END, discarded), then the image
    (verified). A new transcript: the others are unchanged, and `keyed` still
    shows op 0x09 answered UNKNOWN_OP in a window that takes no image."""
    import hashlib
    img = image()
    fs, mt = files()
    spec = dict(length=len(img), sha256=hashlib.sha256(img).digest(), build=IMAGE_BUILD, sig=IMAGE_SIG,
                sig_verify=lambda h, sig: sig == IMAGE_SIG)
    m = b.CollarModel(UID, fs, key=KEY, mtimes=mt, window_s=WINDOW_S, data_max=DATA_MAX, image=spec)
    chal = b.challenge(KEY, UID, 1, 0x4001)
    tag = b.auth_tag(KEY, UID, chal, CNONCE)
    ks = b.session_key(KEY, UID, chal, CNONCE)
    n = [0, 0x4002, 3]     # request counter, tick, seq

    def st(note, op, payload):
        n[1] += 1
        n[2] = (n[2] + 1) & 0xFF
        s = dict(note="%s (ctr %d)" % (note, n[0]), tick=n[1], req=b.request(op, n[2], payload, ks, n[0]))
        n[0] += 1
        return s

    def begin(note, length, flags=0):
        import struct
        return st(note, b.OP_IMG_BEGIN, struct.pack("<IB", length, flags))

    def data(note, off, chunk):
        return st(note, b.OP_IMG_DATA, b.u32le(off) + chunk)

    def whole(what, src, start=0):
        return [data("IMG_DATA %sat %d" % (what, o), o, src[o:o + b.IMG_DATA_MAX])
                for o in range(start, len(src), b.IMG_DATA_MAX)]

    bad = bytearray(img)
    bad[777] ^= 0x01
    steps = [
        dict(note="IMG_BEGIN before AUTH: auth required", tick=0x4000, req=b.img_begin_req(1, len(img))),
        dict(note="HELLO", tick=0x4001, req=b.hello_req(2, CNONCE)),
        dict(note="AUTH", tick=0x4002, req=b.auth_req(3, tag)),
        data("IMG_DATA with no image begun", 0, img[:16]),
        st("IMG_END with no image begun", b.OP_IMG_END, b""),
        begin("IMG_BEGIN with a length that is not the command's", len(img) + 1),
        st("IMG_BEGIN with a short payload: bad request", b.OP_IMG_BEGIN, b.u32le(len(img))),
        begin("IMG_BEGIN", len(img)),
        data("IMG_DATA, the first bytes", 0, bytes(bad[:b.IMG_DATA_MAX])),
        data("IMG_DATA again at 0: wrong offset, next says where", 0, bytes(bad[:b.IMG_DATA_MAX])),
        data("IMG_DATA ahead of the next byte: wrong offset", 500, bytes(bad[500:600])),
        st("IMG_END before the last byte: wrong length, the image stays", b.OP_IMG_END, b""),
        begin("IMG_BEGIN again: resumed, nothing erased", len(img)),
        st("INFO between the pieces: answered as ever", b.OP_INFO, b""),
    ]
    steps += whole("(one byte wrong) ", bytes(bad), b.IMG_DATA_MAX)
    steps += [
        data("IMG_DATA past the end: wrong length", len(img), b"\x00"),
        st("IMG_END: the SHA-256 is not the command's, discarded", b.OP_IMG_END, b""),
        data("IMG_DATA after the discard: no image begun", 0, img[:16]),
        begin("IMG_BEGIN, second try", len(img)),
        data("IMG_DATA, part of it", 0, img[:100]),
        begin("IMG_BEGIN with the restart flag: from 0 again, third try", len(img), b.IMG_FLAG_RESTART),
    ]
    steps += whole("", img)
    steps += [
        st("IMG_END with a payload: bad request", b.OP_IMG_END, b"\x00"),
        st("IMG_END: verified", b.OP_IMG_END, b""),
        data("IMG_DATA after that: done", 0, img[:16]),
        begin("IMG_BEGIN after that: done", len(img)),
    ]
    head = dict(uid=UID, key=KEY.hex(), window_s=WINDOW_S, data_max=DATA_MAX, cnonce=CNONCE.hex(),
                kinds=8, image=img.hex(), image_len=len(img), image_sha256=spec["sha256"].hex(),
                image_build=IMAGE_BUILD, image_sig=IMAGE_SIG.hex(),
                signed_hash=b.image_signed_hash(img, IMAGE_BUILD).hex(),
                note="image_sig is a stand-in the transcript's collar accepts, not an ECDSA signature")
    return head, run(m, steps)


def windows():
    """bb_window_close_s cases (the collar's window rule; window_left_s =
    close - now)."""
    t0 = 1000
    cases = [
        ("no request yet: the minutes asked", t0, 10, 0, False, 0),
        ("a request near the end: 120 s past it", t0, 10, t0 + 590, False, 0),
        ("files keep moving: two hours at most", t0, 30, t0 + 7190, False, 0),
        ("the phone left at 300 s with no BYE: 120 s later", t0, 30, t0 + 290, True, t0 + 300),
        ("the phone left near the normal end: the normal end", t0, 10, t0 + 100, True, t0 + 590),
        ("no phone has connected yet: the full time", t0, 30, 0, False, 0),
    ]
    return [dict(note=n, open_s=o, minutes=mi, last_activity_s=la, phone_gone=pg, gone_s=gs,
                 close_s=b.window_close_s(o, mi, la, pg, gs)) for n, o, mi, la, pg, gs in cases]


def primitives():
    crc = [dict(data=b"123456789".hex(), crc="%08x" % b.crc32(b"123456789")),
           dict(data="", crc="%08x" % b.crc32(b""))]
    paths_ok = ["/", "/CONFIG.CSV", "/2026/11/12/AUDIO/12-00-00.flac", "/a" * 63]
    paths_bad = ["", "CONFIG.CSV", "/a/", "//a", "/a//b", "/a/../b", "/.", "/a/./b", "/a\\b",
                 "/a\x01b", "/" + "a" * 127]
    epochs = [dict(t=[2026, 11, 12, 12, 30, 0], e=b.fat_mtime_epoch(2026, 11, 12, 12, 30, 0)),
              dict(t=[1980, 1, 1, 0, 0, 0], e=b.fat_mtime_epoch(1980, 1, 1, 0, 0, 0)),
              dict(t=[2024, 2, 29, 23, 59, 58], e=b.fat_mtime_epoch(2024, 2, 29, 23, 59, 58)),
              dict(t=[1979, 12, 31, 0, 0, 0], e=0), dict(t=[2026, 13, 1, 0, 0, 0], e=0)]
    return dict(crc32=crc, paths_ok=paths_ok, paths_bad=[p for p in paths_bad], fat_epoch=epochs)


def build():
    fs, mt = files()
    kh, kt = keyed_transcript()
    oh, ot = open_transcript()
    ih, it = info_transcript()
    mh, mt_ = image_transcript()
    return dict(format=FORMAT, version=b.VERSION,
                note="Synthetic. Generated by make_vectors.py from bulk_v1.py; frozen.",
                files=[dict(path=p, data=d.hex(), mtime=mt[p]) for p, d in sorted(fs.items())],
                keyed=dict(header=kh, steps=kt),
                open=dict(header=oh, steps=ot),
                primitives=primitives(),
                info=dict(header=ih, steps=it),
                windows=windows(),
                image=dict(header=mh, steps=mt_))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    text = json.dumps(build(), indent=1, sort_keys=False) + "\n"
    if a.check:
        cur = open(OUT).read() if os.path.exists(OUT) else ""
        if cur != text:
            print("%s is stale: rerun make_vectors.py" % OUT)
            return 1
        print("%s is up to date" % OUT)
        return 0
    open(OUT, "w").write(text)
    print("wrote %s" % OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
