#!/usr/bin/env python3
"""CollarID Bluetooth file transfer, protocol v1 ("CIDB"): reference codec.

The collar serves its card's files read-only on the bulk characteristic
(1a17b2cd-7314-493d-a4b5-32a2d53e6fdc) of the CollarID service. A phone (or,
later, the Handheld Receiver) writes one request per ATT write; the collar
answers with frames on a byte stream carried by notifications, split at any
point by the radio. bulk/README.md is the normative text; this file is the
reference, written for clarity and for the vectors (vectors.json). Where the
two disagree, one of them has a bug.

Standard library only (AES-128 and AES-CMAC come from ../beacon/beacon_v2.py).
Not fast, not side-channel hardened: a reference.

Frame (both directions):
    [0] op u8   [1] seq u8   [2..3] len u16 LE   [4..] payload (len bytes)
    requests in a keyed session, after AUTH: + mac[8] =
        CMAC(K_s, "CIDB-Q" || ctr_le32 || frame without the mac)[0:8]
"""

import hmac
import os
import struct
import sys
import zlib
from collections import namedtuple

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "beacon"))   # appended: beacon/ has its own make_vectors.py
import beacon_v2 as _b  # noqa: E402

VERSION = 1
UUID_BULK_CHAR = "1a17b2cd-7314-493d-a4b5-32a2d53e6fdc"

HDR_LEN = 4
MAC_LEN = 8
REQUEST_MAX = 244            # one ATT write (the radio refuses longer)
TX_BLOB_MAX = 2064           # one radio TX slot: the largest frame the collar sends
DATA_MAX = 2048              # data bytes per DATA frame (512 while the collar is busy)
LIST_PAYLOAD_MAX = 1024      # a LIST answer's payload at most
PATH_MAX = 127               # bytes of a path
NONCE_LEN = 8                # the client's nonce in HELLO
CHALLENGE_LEN = 16
KEY_LEN = 16

OP_HELLO = 0x01
OP_AUTH = 0x02
OP_LIST = 0x03
OP_STAT = 0x04
OP_READ = 0x05
OP_CANCEL = 0x06
OP_BYE = 0x07
RESP = 0x80                  # an answer is the request's op | 0x80
OP_DATA = 0xC5               # READ's data frames (then the 0x85 answer ends it)

R_OK = 0
R_BAD_REQUEST = 1            # malformed: length, field, path syntax
R_AUTH_REQUIRED = 2          # keyed window, not authenticated yet
R_BAD_MAC = 3                # the request's MAC is wrong (the counter does not move)
R_AUTH_FAILED = 4            # AUTH tag wrong, or AUTH without a HELLO first
R_NOT_FOUND = 5
R_IO_ERROR = 6
R_BUSY = 7                   # a READ is running (send CANCEL first)
R_BAD_PATH = 8               # not absolute, "..", control bytes, too long
R_CANCELLED = 9              # a READ ended by CANCEL
R_NOT_A_DIR = 10             # LIST of a file
R_NO_CARD = 11
R_UNKNOWN_OP = 12
R_NOT_NEEDED = 13            # AUTH in a window that needs none (the magnet session)
R_IS_A_DIR = 14              # READ of a directory

FLAG_AUTH_REQUIRED = 0x01    # HELLO answer flags
FLAG_AUTHENTICATED = 0x02

ATTR_READ_ONLY = 0x01        # FAT / FileX attribute bits, as on the card
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

LABEL_AUTH = b"CIDB-AUTH"
LABEL_PROOF = b"CIDB-PROOF"
LABEL_SESS = b"CIDB-SESS"
LABEL_REQ = b"CIDB-Q"
LABEL_CHAL = b"CIDB-CHAL"

Frame = namedtuple("Frame", "op seq payload")
Entry = namedtuple("Entry", "name attr size mtime")
Stat = namedtuple("Stat", "attr size mtime")
Hello = namedtuple("Hello", "result version flags uid challenge window_s data_max")
ReadEnd = namedtuple("ReadEnd", "result offset count crc")


class ProtocolError(ValueError):
    pass


# ------------------------------------------------------------- crypto

def u32le(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def auth_input(uid, challenge, cnonce):
    return u32le(uid) + bytes(challenge) + bytes(cnonce)


def auth_tag(key, uid, challenge, cnonce):
    """What the client proves it holds the window key with (AUTH payload)."""
    return _b.cmac(key, LABEL_AUTH + auth_input(uid, challenge, cnonce))


def proof(key, uid, challenge, cnonce):
    """The collar's answer to AUTH: it holds the key too (8 bytes)."""
    return _b.cmac(key, LABEL_PROOF + auth_input(uid, challenge, cnonce))[:8]


def session_key(key, uid, challenge, cnonce):
    """K_s, the key of every request MAC after AUTH."""
    return _b.cmac(key, LABEL_SESS + auth_input(uid, challenge, cnonce))


def challenge(key, uid, hello_count, tick):
    """How the collar makes its challenge (informative: any value it never
    repeats under one window key will do). A fresh key per window and a
    counter per HELLO keep it unique."""
    return _b.cmac(key, LABEL_CHAL + u32le(uid) + u32le(hello_count) + u32le(tick))


def request_mac(ks, ctr, frame_wo_mac):
    return _b.cmac(ks, LABEL_REQ + u32le(ctr) + bytes(frame_wo_mac))[:MAC_LEN]


def crc32(data, crc=0):
    """IEEE CRC-32 (zlib's), as the END frame of a READ carries it."""
    return zlib.crc32(bytes(data), crc) & 0xFFFFFFFF


# ------------------------------------------------------------- frames

def frame(op, seq, payload=b""):
    payload = bytes(payload)
    if not 0 <= op <= 255 or not 0 <= seq <= 255 or len(payload) > 0xFFFF:
        raise ProtocolError("op and seq are u8, payload at most 65535 B")
    return bytes([op, seq]) + struct.pack("<H", len(payload)) + payload


def request(op, seq, payload=b"", ks=None, ctr=0):
    """A request frame; with ks (a keyed, authenticated session) it carries
    the MAC under the given request counter."""
    f = frame(op, seq, payload)
    if ks is not None:
        f += request_mac(ks, ctr, f)
    if len(f) > REQUEST_MAX:
        raise ProtocolError("a request is at most %d B (one ATT write)" % REQUEST_MAX)
    return f


def check_path(path):
    """The collar's path rule; returns the bytes or raises."""
    p = path.encode("ascii") if isinstance(path, str) else bytes(path)
    if not 1 <= len(p) <= PATH_MAX or p[0:1] != b"/":
        raise ProtocolError("a path is absolute and 1..%d bytes" % PATH_MAX)
    if any(c < 0x20 or c > 0x7E or c == 0x5C for c in p):
        raise ProtocolError("printable ASCII only, no backslash")
    if p != b"/" and (p.endswith(b"/") or b"//" in p):
        raise ProtocolError("no empty path element")
    if any(part in (b".", b"..") for part in p.split(b"/")):
        raise ProtocolError("no . or .. element")
    return p


def hello_req(seq, cnonce):
    if len(cnonce) != NONCE_LEN:
        raise ProtocolError("the client nonce is 8 bytes")
    return request(OP_HELLO, seq, cnonce)


def auth_req(seq, tag):
    return request(OP_AUTH, seq, tag)


def list_req(seq, path, cookie=0, ks=None, ctr=0):
    return request(OP_LIST, seq, u32le(cookie) + check_path(path), ks, ctr)


def stat_req(seq, path, ks=None, ctr=0):
    return request(OP_STAT, seq, check_path(path), ks, ctr)


def read_req(seq, path, offset=0, length=0, ks=None, ctr=0):
    """length 0 = to the end of the file."""
    return request(OP_READ, seq, struct.pack("<QI", offset, length) + check_path(path), ks, ctr)


def cancel_req(seq, ks=None, ctr=0):
    return request(OP_CANCEL, seq, b"", ks, ctr)


def bye_req(seq, ks=None, ctr=0):
    return request(OP_BYE, seq, b"", ks, ctr)


# ------------------------------------------------------- answer payloads

def hello_answer(result, flags, uid, chal, window_s, data_max):
    return struct.pack("<BBBI", result, VERSION, flags, uid) + bytes(chal) + \
        struct.pack("<HH", min(window_s, 0xFFFF), data_max)


def parse_hello(payload):
    if len(payload) != 27:
        raise ProtocolError("HELLO answer is 27 bytes")
    r, v, f, uid = struct.unpack_from("<BBBI", payload, 0)
    w, dm = struct.unpack_from("<HH", payload, 23)
    return Hello(r, v, f, uid, bytes(payload[7:23]), w, dm)


def entry_bytes(e):
    name = e.name.encode("ascii") if isinstance(e.name, str) else bytes(e.name)
    if not 1 <= len(name) <= 255:
        raise ProtocolError("a name is 1..255 bytes")
    return struct.pack("<BQIB", e.attr, e.size, e.mtime, len(name)) + name


def list_answer(result, next_cookie, entries):
    body = b"".join(entry_bytes(e) for e in entries)
    return struct.pack("<BIB", result, next_cookie, len(entries)) + body


def parse_list(payload):
    if len(payload) < 6:
        raise ProtocolError("LIST answer is at least 6 bytes")
    r, nxt, count = struct.unpack_from("<BIB", payload, 0)
    out, i = [], 6
    for _ in range(count):
        if i + 14 > len(payload):
            raise ProtocolError("LIST entry cut short")
        attr, size, mtime, nlen = struct.unpack_from("<BQIB", payload, i)
        i += 14
        if i + nlen > len(payload):
            raise ProtocolError("LIST name cut short")
        out.append(Entry(payload[i:i + nlen].decode("ascii", "replace"), attr, size, mtime))
        i += nlen
    if i != len(payload):
        raise ProtocolError("LIST answer has trailing bytes")
    return r, nxt, out


def stat_answer(result, st):
    return struct.pack("<BBQI", result, st.attr, st.size, st.mtime)


def parse_stat(payload):
    if len(payload) != 14:
        raise ProtocolError("STAT answer is 14 bytes")
    r, attr, size, mtime = struct.unpack("<BBQI", payload)
    return r, Stat(attr, size, mtime)


def data_payload(offset, data):
    return struct.pack("<Q", offset) + bytes(data)


def parse_data(payload):
    if len(payload) < 8:
        raise ProtocolError("DATA is at least 8 bytes")
    return struct.unpack_from("<Q", payload, 0)[0], bytes(payload[8:])


def read_end(result, offset, count, crc):
    return struct.pack("<BQII", result, offset, count, crc)


def parse_read_end(payload):
    if len(payload) != 17:
        raise ProtocolError("READ answer is 17 bytes")
    return ReadEnd(*struct.unpack("<BQII", payload))


# ------------------------------------------------------- stream reader

class StreamReader:
    """Reassembles the collar's frames from notifications cut anywhere."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, chunk):
        self.buf += bytes(chunk)
        out = []
        while len(self.buf) >= HDR_LEN:
            n = struct.unpack_from("<H", self.buf, 2)[0]
            if len(self.buf) < HDR_LEN + n:
                break
            out.append(Frame(self.buf[0], self.buf[1], bytes(self.buf[HDR_LEN:HDR_LEN + n])))
            del self.buf[:HDR_LEN + n]
        return out


# ------------------------------------------------- the collar, in Python

def fat_mtime_epoch(year, month, day, hour, minute, second):
    """A card timestamp (UTC on the collar) as epoch seconds; 0 if invalid."""
    if not (1980 <= year <= 2107 and 1 <= month <= 12 and 1 <= day <= 31 and
            hour < 24 and minute < 60 and second < 60):
        return 0
    import calendar
    return calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))


class CollarModel:
    """The collar's side of v1 over a dict {path: bytes} (directories are the
    path prefixes), for tests and for the bench client's self-test. Follows
    the firmware (collarID_thread Core/Src/ble_bulk_proto.c) rule for rule.

    files: {"/A/B.TXT": b"...", ...}; mtimes: {path: epoch} optional.
    key: the window key (keyed window), or None (the magnet session)."""

    def __init__(self, uid, files, key=None, mtimes=None, window_s=600, data_max=DATA_MAX):
        self.uid = uid
        self.files = dict(files)
        self.mtimes = dict(mtimes or {})
        self.key = key
        self.window_s = window_s
        self.data_max = data_max
        self.hello_count = 0
        self.tick = 0
        self.chal = None
        self.cnonce = None
        self.ks = None
        self.ctr = 0
        self.stream = None       # (seq, path, next_offset, left, start, sent, crc)
        self.after_stream = b""
        self.bye = False

    # -- the file system
    def _dirs(self):
        d = {b"/"}
        for p in self.files:
            parts = p.encode().split(b"/")[1:-1]
            for i in range(1, len(parts) + 1):
                d.add(b"/" + b"/".join(parts[:i]))
        return d

    def _children(self, path):
        pre = path if path.endswith(b"/") else path + b"/"
        names = {}
        for p, data in self.files.items():
            pb = p.encode()
            if pb.startswith(pre):
                rest = pb[len(pre):]
                head = rest.split(b"/")[0]
                if b"/" in rest:
                    names[head] = Entry(head.decode(), ATTR_DIRECTORY, 0, 0)
                else:
                    names[head] = Entry(head.decode(), ATTR_ARCHIVE, len(data), self.mtimes.get(p, 0))
        return [names[k] for k in sorted(names)]

    # -- requests
    def on_request(self, req):
        """One request frame in, the answer bytes out (b"" when the answer
        waits for a running READ to end)."""
        if len(req) < HDR_LEN:
            return b""                      # no op, no seq: nothing to answer
        op, seq = req[0], req[1]
        n = struct.unpack_from("<H", req, 2)[0]
        authed = self.ks is not None
        want_mac = self.key is not None and authed and op not in (OP_HELLO, OP_AUTH)
        if len(req) != HDR_LEN + n + (MAC_LEN if want_mac else 0):
            return frame(op | RESP, seq, bytes([R_BAD_REQUEST]))
        payload = req[HDR_LEN:HDR_LEN + n]
        if want_mac:
            if not hmac.compare_digest(request_mac(self.ks, self.ctr, req[:HDR_LEN + n]),
                                       bytes(req[HDR_LEN + n:])):
                return frame(op | RESP, seq, bytes([R_BAD_MAC]))
            self.ctr += 1
        if op == OP_HELLO:
            return self._hello(seq, payload)
        if op == OP_AUTH:
            return self._auth(seq, payload)
        if self.key is not None and not authed:
            return frame(op | RESP, seq, bytes([R_AUTH_REQUIRED]))
        if op == OP_CANCEL:
            ans = frame(OP_CANCEL | RESP, seq, bytes([R_OK]))
            if self.stream:
                self.stream = self.stream._replace(left=-1)     # ends with CANCELLED
                self.after_stream = ans
                return b""
            return ans
        if op == OP_BYE:
            self.stream = None
            self.bye = True
            return frame(OP_BYE | RESP, seq, bytes([R_OK]))
        if op not in (OP_LIST, OP_STAT, OP_READ):
            return frame(op | RESP, seq, bytes([R_UNKNOWN_OP]))
        if self.stream:
            return frame(op | RESP, seq, bytes([R_BUSY]))
        fixed = 4 if op == OP_LIST else 12 if op == OP_READ else 0
        if len(payload) < fixed + 1:
            return frame(op | RESP, seq, bytes([R_BAD_REQUEST]))
        try:
            path = check_path(payload[fixed:])
        except ProtocolError:
            # the op's own answer, full length, with BAD_PATH
            if op == OP_READ:
                return frame(op | RESP, seq, read_end(R_BAD_PATH, struct.unpack_from("<Q", payload, 0)[0], 0, 0))
            if op == OP_LIST:
                return frame(op | RESP, seq, list_answer(R_BAD_PATH, 0, []))
            return frame(op | RESP, seq, stat_answer(R_BAD_PATH, Stat(0, 0, 0)))
        if op == OP_STAT:
            return self._stat(seq, path)
        if op == OP_LIST:
            return self._list(seq, path, struct.unpack_from("<I", payload, 0)[0])
        return self._read(seq, path, *struct.unpack_from("<QI", payload, 0))

    def _hello(self, seq, payload):
        if len(payload) != NONCE_LEN:
            return frame(OP_HELLO | RESP, seq, bytes([R_BAD_REQUEST]))
        self.stream = None
        self.after_stream = b""
        self.ks = None
        self.ctr = 0
        self.cnonce = bytes(payload)
        self.hello_count += 1
        if self.key is not None:
            self.chal = challenge(self.key, self.uid, self.hello_count, self.tick)
            flags = FLAG_AUTH_REQUIRED
        else:
            self.chal = bytes(CHALLENGE_LEN)
            flags = 0
        return frame(OP_HELLO | RESP, seq,
                     hello_answer(R_OK, flags, self.uid, self.chal, self.window_s, self.data_max))

    def _auth(self, seq, payload):
        if self.key is None:
            return frame(OP_AUTH | RESP, seq, bytes([R_NOT_NEEDED]) + bytes(8))
        if len(payload) != 16:
            return frame(OP_AUTH | RESP, seq, bytes([R_BAD_REQUEST]) + bytes(8))
        if self.chal is None or auth_tag(self.key, self.uid, self.chal, self.cnonce) != bytes(payload):
            self.ks = None
            return frame(OP_AUTH | RESP, seq, bytes([R_AUTH_FAILED]) + bytes(8))
        self.ks = session_key(self.key, self.uid, self.chal, self.cnonce)
        self.ctr = 0
        return frame(OP_AUTH | RESP, seq,
                     bytes([R_OK]) + proof(self.key, self.uid, self.chal, self.cnonce))

    def _stat(self, seq, path):
        ps = path.decode()
        if ps in self.files:
            st = Stat(ATTR_ARCHIVE, len(self.files[ps]), self.mtimes.get(ps, 0))
        elif path in self._dirs():
            st = Stat(ATTR_DIRECTORY, 0, 0)
        else:
            return frame(OP_STAT | RESP, seq, stat_answer(R_NOT_FOUND, Stat(0, 0, 0)))
        return frame(OP_STAT | RESP, seq, stat_answer(R_OK, st))

    def _list(self, seq, path, cookie):
        if path.decode() in self.files:
            return frame(OP_LIST | RESP, seq, list_answer(R_NOT_A_DIR, 0, []))
        if path not in self._dirs():
            return frame(OP_LIST | RESP, seq, list_answer(R_NOT_FOUND, 0, []))
        kids = self._children(path)
        out, size, i = [], 6, cookie
        while i < len(kids):
            eb = len(entry_bytes(kids[i]))
            if size + eb > LIST_PAYLOAD_MAX:
                break
            out.append(kids[i])
            size += eb
            i += 1
        nxt = i if i < len(kids) else 0
        return frame(OP_LIST | RESP, seq, list_answer(R_OK, nxt, out))

    def _read(self, seq, path, offset, length):
        ps = path.decode()
        if ps not in self.files:
            r = R_IS_A_DIR if path in self._dirs() else R_NOT_FOUND
            return frame(OP_READ | RESP, seq, read_end(r, offset, 0, 0))
        size = len(self.files[ps])
        left = max(0, size - offset) if offset <= size else 0
        if length:
            left = min(left, length)
        S = namedtuple("S", "seq path nxt left start sent crc")
        self.stream = S(seq, ps, offset, left, offset, 0, 0)
        return b""

    def next_stream(self):
        """The next frame(s) of a running READ (b"" when none)."""
        s = self.stream
        if not s:
            return b""
        if s.left == -1:                                   # cancelled
            self.stream = None
            out = frame(OP_READ | RESP, s.seq, read_end(R_CANCELLED, s.start, s.sent, s.crc))
            out += self.after_stream
            self.after_stream = b""
            return out
        if s.left == 0:
            self.stream = None
            return frame(OP_READ | RESP, s.seq, read_end(R_OK, s.start, s.sent, s.crc))
        n = min(s.left, self.data_max)
        data = self.files[s.path][s.nxt:s.nxt + n]
        self.stream = s._replace(nxt=s.nxt + n, left=s.left - n, sent=s.sent + n,
                                 crc=crc32(data, s.crc))
        return frame(OP_DATA, s.seq, data_payload(s.nxt, data))


# ---------------------------------------------- the phone, over a transport

class Client:
    """The phone's side over any transport: write(bytes) sends one request,
    read() returns the next notification chunk (or raises on timeout).
    The bench client binds it to Bluetooth (bleak); the tests to CollarModel."""

    def __init__(self, write, read, key=None, cnonce=None):
        self._write = write
        self._read = read
        self.key = key
        self.cnonce = cnonce if cnonce is not None else os.urandom(NONCE_LEN)
        self.rx = StreamReader()
        self.pending = []
        self.seq = 0
        self.ks = None
        self.ctr = 0
        self.hello = None

    def _next_frame(self):
        while not self.pending:
            self.pending.extend(self.rx.feed(self._read()))
        return self.pending.pop(0)

    def _send(self, op, payload=b"", mac=True):
        self.seq = (self.seq + 1) & 0xFF
        use = self.ks if (mac and self.ks is not None) else None
        f = request(op, self.seq, payload, use, self.ctr)
        self._write(f)
        if use is not None:
            self.ctr += 1     # the collar counts a request whose MAC it accepted
        return self.seq

    def _answer(self, seq, op):
        while True:
            fr = self._next_frame()
            if fr.seq == seq and fr.op == (op | RESP):
                return fr.payload

    def open(self):
        """HELLO, then AUTH when the collar asks for it. Returns the Hello."""
        seq = self._send(OP_HELLO, self.cnonce, mac=False)
        self.ks, self.ctr = None, 0
        self.hello = parse_hello(self._answer(seq, OP_HELLO))
        if self.hello.flags & FLAG_AUTH_REQUIRED:
            if self.key is None:
                raise ProtocolError("this window needs its key")
            tag = auth_tag(self.key, self.hello.uid, self.hello.challenge, self.cnonce)
            seq = self._send(OP_AUTH, tag, mac=False)
            ans = self._answer(seq, OP_AUTH)
            if ans[0] != R_OK:
                raise ProtocolError("AUTH refused (result %d)" % ans[0])
            if ans[1:9] != proof(self.key, self.hello.uid, self.hello.challenge, self.cnonce):
                raise ProtocolError("the collar's proof is wrong: not the collar that holds this key")
            self.ks = session_key(self.key, self.hello.uid, self.hello.challenge, self.cnonce)
            self.ctr = 0
        return self.hello

    def list(self, path):
        out, cookie = [], 0
        while True:
            seq = self._send(OP_LIST, u32le(cookie) + check_path(path))
            r, nxt, entries = parse_list(self._answer(seq, OP_LIST))
            if r != R_OK:
                raise ProtocolError("LIST %s: result %d" % (path, r))
            out.extend(entries)
            if nxt == 0:
                return out
            cookie = nxt

    def stat(self, path):
        seq = self._send(OP_STAT, check_path(path))
        r, st = parse_stat(self._answer(seq, OP_STAT))
        if r != R_OK:
            raise ProtocolError("STAT %s: result %d" % (path, r))
        return st

    def read(self, path, offset=0, length=0, sink=None):
        """Stream a range. sink(offset, bytes) gets each DATA frame; without
        a sink the bytes are returned. Raises unless the range CRC matches."""
        seq = self._send(OP_READ, struct.pack("<QI", offset, length) + check_path(path))
        chunks, crc, count = [], 0, 0
        while True:
            fr = self._next_frame()
            if fr.seq != seq:
                continue
            if fr.op == OP_DATA:
                off, data = parse_data(fr.payload)
                if off + len(data) <= offset + count and off >= offset:
                    continue      # a frame sent again (the collar resent a blob it could not confirm): already have it
                if off != offset + count:
                    raise ProtocolError("DATA at %d, expected %d" % (off, offset + count))
                crc = crc32(data, crc)
                count += len(data)
                if sink:
                    sink(off, data)
                else:
                    chunks.append(data)
            elif fr.op == OP_READ | RESP:
                end = parse_read_end(fr.payload)
                if end.result != R_OK:
                    raise ProtocolError("READ %s: result %d after %d B" % (path, end.result, end.count))
                if end.count != count or end.crc != crc:
                    raise ProtocolError("READ %s: range check failed (%d B crc %08x, collar says %d B crc %08x)"
                                        % (path, count, crc, end.count, end.crc))
                return b"".join(chunks) if not sink else count

    def cancel(self):
        seq = self._send(OP_CANCEL)
        return self._answer(seq, OP_CANCEL)[0]

    def bye(self):
        seq = self._send(OP_BYE)
        return self._answer(seq, OP_BYE)[0]
