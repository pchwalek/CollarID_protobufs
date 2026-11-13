#!/usr/bin/env python3
"""Tests of the bulk protocol reference (bulk_v1.py) and its vectors.

    cd bulk && python3 -m unittest
"""
import json
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bulk_v1 as b  # noqa: E402
import make_vectors  # noqa: E402


def wire(model, chunk_sizes):
    """A transport: requests go to the model; the collar's stream is cut into
    notifications of the sizes given (cycled), as a radio might."""
    q = bytearray()
    sizes = list(chunk_sizes)
    state = {"i": 0}

    def write(f):
        q.extend(model.on_request(f))

    def read():
        if not q:
            q.extend(model.next_stream())
        if not q:
            raise TimeoutError("the collar sent nothing")
        n = sizes[state["i"] % len(sizes)]
        state["i"] += 1
        out = bytes(q[:n])
        del q[:n]
        return out
    return write, read


class Vectors(unittest.TestCase):
    def test_vectors_are_current(self):
        with open(make_vectors.OUT) as f:
            self.assertEqual(f.read(), json.dumps(make_vectors.build(), indent=1) + "\n")

    def test_crc_is_zlibs(self):
        self.assertEqual(b.crc32(b"123456789"), 0xCBF43926)


class Paths(unittest.TestCase):
    def test_good(self):
        for p in make_vectors.primitives()["paths_ok"]:
            b.check_path(p)

    def test_bad(self):
        for p in make_vectors.primitives()["paths_bad"]:
            with self.assertRaises(b.ProtocolError, msg=repr(p)):
                b.check_path(p)


class Sessions(unittest.TestCase):
    def setUp(self):
        self.fs, self.mt = make_vectors.files()
        self.key = make_vectors.KEY

    def client(self, key, model_key, chunks=(244,), data_max=b.DATA_MAX):
        m = b.CollarModel(0x1234ABCD, self.fs, key=model_key, mtimes=self.mt, data_max=data_max)
        w, r = wire(m, chunks)
        return b.Client(w, r, key=key), m

    def test_keyed_round_trip_with_any_notification_cut(self):
        rng = random.Random(7)
        for _ in range(20):
            chunks = [rng.randint(1, 244) for _ in range(5)]
            c, _ = self.client(self.key, self.key, chunks, data_max=rng.choice([64, 512, 2048]))
            h = c.open()
            self.assertTrue(h.flags & b.FLAG_AUTH_REQUIRED)
            names = [e.name for e in c.list("/")]
            self.assertEqual(names, ["2026", "CONFIG.CSV", "uplink_ring.bin"])
            gps = "/2026/11/12/GPS_0012.CSV"
            self.assertEqual(c.read(gps), self.fs[gps])
            self.assertEqual(c.read(gps, 10, 77), self.fs[gps][10:87])
            self.assertEqual(c.stat(gps).size, 300)
            self.assertEqual(c.bye(), b.R_OK)

    def test_wrong_key_is_refused_and_the_collar_proves_itself(self):
        c, _ = self.client(bytes(16), self.key)
        with self.assertRaises(b.ProtocolError):
            c.open()

    def test_no_key_window_needs_no_auth(self):
        c, _ = self.client(None, None)
        h = c.open()
        self.assertEqual(h.flags & b.FLAG_AUTH_REQUIRED, 0)
        self.assertEqual(c.read("/CONFIG.CSV"), self.fs["/CONFIG.CSV"])

    def test_a_request_without_auth_is_refused(self):
        m = b.CollarModel(1, self.fs, key=self.key)
        ans = m.on_request(b.stat_req(1, "/CONFIG.CSV"))
        self.assertEqual(ans, b.frame(b.OP_STAT | b.RESP, 1, bytes([b.R_AUTH_REQUIRED])))

    def test_a_replayed_request_is_refused(self):
        c, m = self.client(self.key, self.key)
        c.open()
        c.stat("/CONFIG.CSV")                                   # ctr 0
        old = b.stat_req(9, "/CONFIG.CSV", c.ks, 0)             # ctr 0 again
        self.assertEqual(m.on_request(old), b.frame(b.OP_STAT | b.RESP, 9, bytes([b.R_BAD_MAC])))

    def test_a_data_frame_sent_twice_is_ignored(self):
        m = b.CollarModel(1, self.fs, data_max=64)
        q = bytearray()
        sent = []

        def w(f):
            q.extend(m.on_request(f))

        def r():
            if not q:
                f = m.next_stream()
                if f and f[0] == b.OP_DATA and len(sent) == 1:
                    q.extend(sent[0])          # the previous blob again
                if f and f[0] == b.OP_DATA:
                    sent.append(f)
                q.extend(f)
            if not q:
                raise TimeoutError
            out = bytes(q)
            q.clear()
            return out
        c = b.Client(w, r)
        c.open()
        self.assertEqual(c.read("/uplink_ring.bin"), self.fs["/uplink_ring.bin"])

    def test_list_pages(self):
        many = {"/D/F%03d.TXT" % i: b"x" for i in range(100)}
        m = b.CollarModel(1, many)
        w, r = wire(m, [244])
        c = b.Client(w, r)
        c.open()
        self.assertEqual(len(c.list("/D")), 100)


if __name__ == "__main__":
    unittest.main()
