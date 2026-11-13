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
    return dict(format=FORMAT, version=b.VERSION,
                note="Synthetic. Generated by make_vectors.py from bulk_v1.py; frozen.",
                files=[dict(path=p, data=d.hex(), mtime=mt[p]) for p, d in sorted(fs.items())],
                keyed=dict(header=kh, steps=kt),
                open=dict(header=oh, steps=ot),
                primitives=primitives())


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
