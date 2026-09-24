"""GPS block v1: reference codec (Python 3, standard library only).

The normative description is GPS_BLOCK_V1.md next to this file. This module is
the executable form of it: the firmware encoder and the server decoder are
checked against the vectors it generates (test_vectors/gps_block_v1.json).

Everything is integer arithmetic. Coordinates are int32 in 1e-7 degree
(lat_e7, lon_e7); divide by 1e7 only for display.

Input fix (a mapping):
    lat_e7    int32
    lon_e7    int32
    t         uint32, Unix seconds, GNSS time of the fix
    h_acc_dm  uint32, horizontal accuracy in decimetres; 0, None or absent
              means unknown
    ttff_s    uint32, time to fix in seconds; None or absent is read as 0

Decoded fix (a dict, the same keys the vectors use):
    lat_e7, lon_e7   int, 100 * the quantized value
    t                int
    h_acc_m          int 1..63 (63 = "63 m or worse", still an int), or
                     None (unknown)
    gps_fix_time_s   int 0..1023
Altitude and HDOP are not carried; a server row built from a block has them
as NULL.

API (sections 4 and 8 of the spec):
    is_excluded(fix) -> bool                              (C: gps_block_fix_excluded)
    gps_block_bits(fixes, header_epoch) -> int            (alias: bits)
    gps_block_encode(fixes, header_epoch, cap) -> bytes   (alias: encode)
    decode(block, header_epoch) -> ('ok', [fix, ...])     oldest first
                                   ('empty', [])          zero-length block
                                   ('ignored', reason)    other version or
                                                          corrupt; log it
The decoder has no size limit: FIRMWARE_CAP binds the encoder only.
"""

VERSION = 1
MAX_FIXES = 32
CLOCK_GATE_EPOCH = 1767225600          # 2026-01-01T00:00:00Z
FIRMWARE_CAP = 180                     # nanopb max_size of Deployment.gps_block
ACCUMULATOR_FIXES = 24                 # the collar's accumulator (gps_data max_count)

INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
UINT32_MAX = (1 << 32) - 1

LAT_E7_LIMIT = 900000000
LON_E7_LIMIT = 1800000000
Q_LAT_LIMIT = 9000000
Q_LON_LIMIT = 18000000

TTFF_SAT = 1023
ACC_CODE_WORST = 63

# Largest legal value of each width field (decoder rejects anything above).
AGE_W_MAX = 33
LAT_W_MAX = 26
LON_W_MAX = 27
DTMIN_W_MAX = 32
DT_W_MAX = 32


# ---------------------------------------------------------------- primitives

def W(u):
    """Bit length of an unsigned integer; W(0) == 0."""
    if u < 0:
        raise ValueError("W() of a negative number")
    return u.bit_length()


def zz(x):
    """Zigzag: 0, -1, 1, -2, ... -> 0, 1, 2, 3, ..."""
    return 2 * x if x >= 0 else 2 * (-(x + 1)) + 1


def unzz(u):
    return -(u >> 1) - 1 if (u & 1) else (u >> 1)


def q(v):
    """1e-7 degree -> 1e-5 degree, round half up: floor((v + 50) / 100)."""
    return (v + 50) // 100              # Python // is floor division


def acc_code(h_acc_dm):
    """6-bit accuracy code: 0 unknown, 1..62 whole metres rounded up, 63 worse."""
    if not h_acc_dm:
        return 0
    if h_acc_dm > 620:
        return ACC_CODE_WORST
    return (h_acc_dm + 9) // 10         # ceil(h_acc_dm / 10), h_acc_dm <= 620


def acc_code_to_m(code):
    """0 -> None (unknown); 1..63 -> the same integer (63 = 63 m or worse)."""
    return None if code == 0 else code


def degrees(e7):
    """For display only: one division, as the legacy gps_data path does."""
    return e7 / 1e7


# ---------------------------------------------------------------- input

def _check_int(name, value, lo, hi):
    if type(value) is not int:          # rejects bool, float, str, None
        raise TypeError("%s must be int, got %r" % (name, value))
    if value < lo or value > hi:
        raise ValueError("%s=%d outside [%d, %d]" % (name, value, lo, hi))


def _normalise(fix, i):
    """Validate one input fix and return a plain dict with h_acc_dm and
    ttff_s filled (absent or None -> 0, section 4)."""
    try:
        lat, lon, t = fix["lat_e7"], fix["lon_e7"], fix["t"]
        h, ttff = fix.get("h_acc_dm"), fix.get("ttff_s")
    except (KeyError, TypeError, AttributeError):
        raise ValueError("fix %d: needs lat_e7, lon_e7 and t" % i)
    if h is None:
        h = 0
    if ttff is None:
        ttff = 0
    _check_int("fix %d lat_e7" % i, lat, INT32_MIN, INT32_MAX)
    _check_int("fix %d lon_e7" % i, lon, INT32_MIN, INT32_MAX)
    _check_int("fix %d t" % i, t, 0, UINT32_MAX)
    _check_int("fix %d h_acc_dm" % i, h, 0, UINT32_MAX)
    _check_int("fix %d ttff_s" % i, ttff, 0, UINT32_MAX)
    return {"lat_e7": lat, "lon_e7": lon, "t": t, "h_acc_dm": h, "ttff_s": ttff}


def is_excluded(fix):
    """Section 4: True for a fix the encoder drops; the caller MUST then
    remove it from its accumulator, since it can never be sent. The C API
    exports the same predicate as gps_block_fix_excluded. Validates the fix
    as the encoder does (raises on bad input). The null island test is on
    the QUANTIZED position: any fix within 50 (1e-7 degree) of (0, 0) on
    both axes is excluded."""
    return _excluded(_normalise(fix, 0))


def _excluded(f):
    lat, lon = f["lat_e7"], f["lon_e7"]
    return (lat < -LAT_E7_LIMIT or lat > LAT_E7_LIMIT or
            lon < -LON_E7_LIMIT or lon > LON_E7_LIMIT or
            (q(lat) == 0 and q(lon) == 0) or
            f["t"] < CLOCK_GATE_EPOCH)


def wire_order(fixes):
    """Validate, exclude, and order newest first (reverse of a stable
    ascending sort by t). Raises on invalid input. Returns the list of kept
    fixes in wire order; it may be empty or longer than MAX_FIXES."""
    if isinstance(fixes, (str, bytes)) or not hasattr(fixes, "__iter__"):
        raise TypeError("fixes must be a sequence of mappings")
    norm = [_normalise(f, i) for i, f in enumerate(fixes)]
    kept = [f for f in norm if not _excluded(f)]
    ascending = sorted(range(len(kept)), key=lambda i: kept[i]["t"])   # stable
    return [kept[i] for i in reversed(ascending)]


# ---------------------------------------------------------------- layout

def layout(fixes, header_epoch):
    """The fields of the block in wire order as (name, width, value), or None
    when N (after exclusion) is outside 1..32. Pure; raises on bad input."""
    _check_int("header_epoch", header_epoch, 0, UINT32_MAX)
    f = wire_order(fixes)
    n = len(f)
    if n < 1 or n > MAX_FIXES:
        return None

    out = []
    qlat = [q(x["lat_e7"]) for x in f]
    qlon = [q(x["lon_e7"]) for x in f]
    age = header_epoch - f[0]["t"]
    age_zz = zz(age)

    out.append(("version", 3, VERSION))
    out.append(("n_minus_1", 5, n - 1))
    out.append(("lat0", 25, zz(qlat[0])))
    out.append(("lon0", 26, zz(qlon[0])))
    out.append(("age_w", 6, W(age_zz)))
    out.append(("age", W(age_zz), age_zz))

    ttff = [x["ttff_s"] for x in f]
    if n == 1:
        out.append(("ttff0", 10, min(TTFF_SAT, ttff[0])))
    else:
        kmax = 0
        for k in range(1, n):           # RAW uint32 values, before saturating
            if ttff[k] > ttff[kmax]:    # strict: lowest index wins a tie
                kmax = k
        m = n - 1
        s = sum(ttff) - ttff[kmax]
        rest = (2 * s + m) // (2 * m)   # round-half-up mean
        out.append(("ttff_kmax", W(n - 1), kmax))
        out.append(("ttff_max", 10, min(TTFF_SAT, ttff[kmax])))
        out.append(("ttff_rest", 10, min(TTFF_SAT, rest)))

    for k in range(n):
        out.append(("acc[%d]" % k, 6, acc_code(f[k]["h_acc_dm"])))

    if n >= 2:
        dlat = [zz(qlat[k] - qlat[k - 1]) for k in range(1, n)]
        dlon = [zz(qlon[k] - qlon[k - 1]) for k in range(1, n)]
        dt = [f[k - 1]["t"] - f[k]["t"] for k in range(1, n)]
        dt_min = min(dt)
        ddt = [d - dt_min for d in dt]
        lat_w, lon_w, dt_w = W(max(dlat)), W(max(dlon)), W(max(ddt))
        out.append(("lat_w", 5, lat_w))
        out.append(("lon_w", 5, lon_w))
        out.append(("dtmin_w", 6, W(dt_min)))
        out.append(("dt_min", W(dt_min), dt_min))
        out.append(("dt_w", 6, dt_w))
        for k in range(1, n):
            out.append(("dlat[%d]" % k, lat_w, dlat[k - 1]))
            out.append(("dlon[%d]" % k, lon_w, dlon[k - 1]))
            out.append(("ddt[%d]" % k, dt_w, ddt[k - 1]))
    return out


def pack(fields):
    """Write (name, width, value) fields MSB first, zero-pad the last byte.
    Also used by the vector generator to build deliberately bad blocks."""
    acc = 0
    nbits = 0
    for name, width, value in fields:
        if width < 0 or value < 0 or value >> width:
            raise ValueError("%s=%d does not fit in %d bits" % (name, value, width))
        acc = (acc << width) | value
        nbits += width
    pad = -nbits % 8
    return (acc << pad).to_bytes((nbits + pad) // 8, "big")


# ---------------------------------------------------------------- encoder

def gps_block_bits(fixes, header_epoch):
    """Exact number of bits the layout needs for these fixes, or 0 when N
    (after exclusion) is outside 1..32. Independent of any cap."""
    fields = layout(fixes, header_epoch)
    return 0 if fields is None else sum(w for _, w, _ in fields)


def gps_block_encode(fixes, header_epoch, cap):
    """The block, ceil(bits / 8) bytes long; b"" (the C API's 0, nothing
    written) when N (after exclusion) is outside 1..32 or the block would be
    longer than cap. Refuses, never truncates."""
    _check_int("cap", cap, 0, 1 << 62)
    fields = layout(fixes, header_epoch)
    if fields is None:
        return b""
    nbytes = (sum(w for _, w, _ in fields) + 7) // 8
    if nbytes > cap:
        return b""
    return pack(fields)


bits = gps_block_bits
encode = gps_block_encode


# ---------------------------------------------------------------- decoder

class _Corrupt(Exception):
    pass


class _Reader:
    def __init__(self, data):
        self.value = int.from_bytes(data, "big")
        self.total = 8 * len(data)
        self.pos = 0

    def read(self, width, name):
        if self.pos + width > self.total:
            raise _Corrupt("read past end: %s needs %d bits at bit %d of %d"
                           % (name, width, self.pos, self.total))
        shift = self.total - self.pos - width
        self.pos += width
        return (self.value >> shift) & ((1 << width) - 1)

    def width(self, bitsize, maximum, name):
        w = self.read(bitsize, name)
        if w > maximum:
            raise _Corrupt("%s=%d above its maximum %d" % (name, w, maximum))
        return w


def _decode_v1(r, nbytes, header_epoch):
    n = r.read(5, "n_minus_1") + 1
    qlat = [unzz(r.read(25, "lat0"))]
    qlon = [unzz(r.read(26, "lon0"))]
    age_w = r.width(6, AGE_W_MAX, "age_w")
    age = unzz(r.read(age_w, "age"))

    if n == 1:
        ttff_out = [r.read(10, "ttff0")]
    else:
        kmax = r.read(W(n - 1), "ttff_kmax")
        if kmax >= n:
            raise _Corrupt("ttff_kmax=%d >= N=%d" % (kmax, n))
        ttff_max = r.read(10, "ttff_max")
        ttff_rest = r.read(10, "ttff_rest")
        ttff_out = [ttff_max if k == kmax else ttff_rest for k in range(n)]

    codes = [r.read(6, "acc") for _ in range(n)]

    t = [header_epoch - age]
    if n >= 2:
        lat_w = r.width(5, LAT_W_MAX, "lat_w")
        lon_w = r.width(5, LON_W_MAX, "lon_w")
        dtmin_w = r.width(6, DTMIN_W_MAX, "dtmin_w")
        dt_min = r.read(dtmin_w, "dt_min")
        dt_w = r.width(6, DT_W_MAX, "dt_w")
        for k in range(1, n):
            qlat.append(qlat[-1] + unzz(r.read(lat_w, "dlat")))
            qlon.append(qlon[-1] + unzz(r.read(lon_w, "dlon")))
            t.append(t[-1] - (dt_min + r.read(dt_w, "ddt")))

    walked = r.pos
    expected = (walked + 7) // 8
    if nbytes != expected:
        raise _Corrupt("length %d B, layout needs %d B" % (nbytes, expected))
    if r.read(r.total - r.pos, "pad") != 0:
        raise _Corrupt("non-zero pad bits")

    for k in range(n):
        if not -Q_LAT_LIMIT <= qlat[k] <= Q_LAT_LIMIT:
            raise _Corrupt("fix %d: q_lat %d out of range" % (k, qlat[k]))
        if not -Q_LON_LIMIT <= qlon[k] <= Q_LON_LIMIT:
            raise _Corrupt("fix %d: q_lon %d out of range" % (k, qlon[k]))
        if qlat[k] == 0 and qlon[k] == 0:
            # The encoder excludes every fix that quantizes to (0, 0), so a
            # block holding one is corrupt as a whole (never skip the fix).
            raise _Corrupt("fix %d: q = (0, 0), which the encoder never emits" % k)
        if not CLOCK_GATE_EPOCH <= t[k] <= UINT32_MAX:
            raise _Corrupt("fix %d: t %d out of range" % (k, t[k]))

    out = []
    for k in reversed(range(n)):        # oldest first
        lat_e7, lon_e7 = 100 * qlat[k], 100 * qlon[k]
        out.append({"lat_e7": lat_e7, "lon_e7": lon_e7, "t": t[k],
                    "h_acc_m": acc_code_to_m(codes[k]),
                    "gps_fix_time_s": ttff_out[k]})
    return out, walked


def decode(block, header_epoch):
    """Decode one gps_block. header_epoch is the raw on-air
    MessagePacket.header.epoch of the same frame (0 is valid).

    Never raises on block content: a bad block comes back as
    ('ignored', reason) and the caller decodes the rest of the frame.
    No size limit: any length that walks the layout exactly is accepted
    (the 180 B nanopb cap binds the encoder, not the decoder).
    Raises TypeError / ValueError only for a caller bug (block not bytes,
    header_epoch not a uint32)."""
    if not isinstance(block, (bytes, bytearray, memoryview)):
        raise TypeError("block must be bytes")
    _check_int("header_epoch", header_epoch, 0, UINT32_MAX)
    data = bytes(block)
    if len(data) == 0:
        return ("empty", [])
    r = _Reader(data)
    version = r.read(3, "version")
    if version != VERSION:
        return ("ignored", "version %d not implemented" % version)
    try:
        return ("ok", _decode_v1(r, len(data), header_epoch)[0])
    except _Corrupt as e:
        return ("ignored", "corrupt: %s" % e)


def walked_bits(block, header_epoch):
    """For tests: the number of layout bits the decoder walked (padding
    excluded) for a block that decodes as ok, else None."""
    _check_int("header_epoch", header_epoch, 0, UINT32_MAX)
    data = bytes(block)
    if not data:
        return None
    r = _Reader(data)
    if r.read(3, "version") != VERSION:
        return None
    try:
        return _decode_v1(r, len(data), header_epoch)[1]
    except _Corrupt:
        return None
