"""What's on the card, v1: reference codec (Python 3, standard library only).

The normative description is CARD_SUMMARY_V1.md next to this file; this
module is its executable form. The collar firmware (collarID_thread
Core/Src/card_days.c), the server and the clients are checked against the
vectors it generates (test_vectors/card_summary_v1.json,
make_card_summary_vectors.py). Added 2026-11-16 (collarID_thread
docs/CONTRACT_files_and_spotter_gaps.md Part 3).

A day record is 10 bytes, little-endian:
    [0..2] sound hours     u24, bit h = UTC hour h of that day holds sound
    [3..4] sound MiB       u16, rounded up, 65535 = that much or more
    [5..7] movement hours  u24, as sound
    [8..9] movement MiB    u16, as sound

API:
    encode_day(sound_hours, sound_mib, movement_hours, movement_mib) -> bytes
    decode_day(b) -> dict(sound_hours=[...], sound_mib, movement_hours=[...], movement_mib)
    decode_days(b) -> [dict, ...]                 b is a whole number of records
    mib_from_bytes(n) -> int                      bytes to MiB, rounded up, saturating
    mib_from_kib(k) -> int                        the collar keeps KiB per day
    span_hours(day, start, end) -> int            the u24 hours of UTC day `day`
                                                  (its midnight, epoch s) that a
                                                  recording from start to end covers
    window(from_epoch, days, now) -> (first_day, n)
    split(n) -> [(offset, count), ...]            the frames of an n-day answer
    encode_summary(...) / decode_summary(b)       the CardSummary message
"""

DAY_LEN = 10
DAY_S = 86400
HOUR_S = 3600
HOURS_MASK = (1 << 24) - 1
MIB_SAT = 65535
DAYS_DEFAULT = 30
DAYS_MAX = 62
DAYS_PER_FRAME = 16
FRAMES_MAX = 4
# A recording longer than this (a clock that jumped while a file was open)
# is held to it: no collar file runs past a day plus an hour.
SPAN_MAX_S = DAY_S + HOUR_S

# CardSummary field numbers (message.proto).
F_FIRST_DAY, F_DAYS, F_PART, F_PARTS, F_LOG_KIB, F_AS_OF = 1, 2, 3, 4, 5, 6
MESSAGE_PACKET_FIELD = 12   # MessagePacket.card_summary


def hours_mask(hours):
    """A list of hours 0..23 (or an int mask) as the u24 mask."""
    if isinstance(hours, int):
        if not 0 <= hours <= HOURS_MASK:
            raise ValueError("hours mask out of range: %r" % hours)
        return hours
    m = 0
    for h in hours:
        if not 0 <= h <= 23:
            raise ValueError("hour out of range: %r" % h)
        m |= 1 << h
    return m


def hours_list(mask):
    return [h for h in range(24) if mask & (1 << h)]


def _u16(v):
    if not 0 <= v <= MIB_SAT:
        raise ValueError("MiB out of range: %r" % v)
    return v.to_bytes(2, "little")


def encode_day(sound_hours=0, sound_mib=0, movement_hours=0, movement_mib=0):
    return (hours_mask(sound_hours).to_bytes(3, "little") + _u16(sound_mib) +
            hours_mask(movement_hours).to_bytes(3, "little") + _u16(movement_mib))


def decode_day(b):
    if len(b) != DAY_LEN:
        raise ValueError("a day record is %d bytes, not %d" % (DAY_LEN, len(b)))
    return {
        "sound_hours": hours_list(int.from_bytes(b[0:3], "little")),
        "sound_mib": int.from_bytes(b[3:5], "little"),
        "movement_hours": hours_list(int.from_bytes(b[5:8], "little")),
        "movement_mib": int.from_bytes(b[8:10], "little"),
    }


def decode_days(b):
    if len(b) % DAY_LEN:
        raise ValueError("days is %d bytes, not a whole number of records" % len(b))
    return [decode_day(b[i:i + DAY_LEN]) for i in range(0, len(b), DAY_LEN)]


def mib_from_kib(kib):
    if kib <= 0:
        return 0
    return min(MIB_SAT, (kib + 1023) // 1024)


def mib_from_bytes(n):
    if n <= 0:
        return 0
    return min(MIB_SAT, (n + (1 << 20) - 1) >> 20)


def kib_from_bytes(n):
    """What the collar adds to a day for one file: KiB rounded up."""
    return 0 if n <= 0 else (n + 1023) // 1024


def span_hours(day, start, end):
    """The hours of UTC day `day` (its midnight) that [start, end] covers.
    end before start reads as start; a span over SPAN_MAX_S is held to it."""
    if day % DAY_S:
        raise ValueError("day must be a UTC midnight")
    if end < start:
        end = start
    if end - start > SPAN_MAX_S:
        end = start + SPAN_MAX_S
    s = max(start, day)
    e = min(end, day + DAY_S - 1)
    if s > e:
        return 0
    m = 0
    for h in range((s - day) // HOUR_S, (e - day) // HOUR_S + 1):
        m |= 1 << h
    return m


def window(from_epoch, days, now):
    """The answer's first day (UTC midnight) and day count for a request.
    days 0 = 30, held to 1..62; from_epoch 0 = the days that end today."""
    n = DAYS_DEFAULT if days == 0 else max(1, min(DAYS_MAX, days))
    if from_epoch == 0:
        today = now // DAY_S
        first = max(0, today - (n - 1))
    else:
        first = from_epoch // DAY_S
    return first * DAY_S, n


def split(n):
    """(offset, count) of each frame of an n-day answer: DAYS_PER_FRAME days
    a frame, at most FRAMES_MAX frames."""
    if not 1 <= n <= DAYS_MAX:
        raise ValueError("an answer holds 1..%d days" % DAYS_MAX)
    out, at = [], 0
    while at < n:
        c = min(DAYS_PER_FRAME, n - at)
        out.append((at, c))
        at += c
    assert len(out) <= FRAMES_MAX
    return out


# ---- the CardSummary message (proto3, minimal encoder) ----------------------

def _varint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _field_varint(num, v):
    return b"" if v == 0 else _varint(num << 3) + _varint(v)


def _field_bytes(num, b):
    return b"" if not b else _varint(num << 3 | 2) + _varint(len(b)) + bytes(b)


def encode_summary(first_day, days, part, parts, log_kib=0, as_of=0):
    """CardSummary bytes, fields in number order, zeros left out (proto3)."""
    if len(days) % DAY_LEN or len(days) > DAYS_PER_FRAME * DAY_LEN:
        raise ValueError("days: a whole number of records, at most %d" % DAYS_PER_FRAME)
    for v in (first_day, part, parts, log_kib, as_of):
        if not 0 <= v <= 0xFFFFFFFF:
            raise ValueError("uint32 out of range: %r" % v)
    return (_field_varint(F_FIRST_DAY, first_day) + _field_bytes(F_DAYS, days) +
            _field_varint(F_PART, part) + _field_varint(F_PARTS, parts) +
            _field_varint(F_LOG_KIB, log_kib) + _field_varint(F_AS_OF, as_of))


def _read_varint(b, i):
    v, shift = 0, 0
    while True:
        if i >= len(b):
            raise ValueError("truncated varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def decode_summary(b):
    out = {"first_day": 0, "days": b"", "part": 0, "parts": 0, "log_kib": 0, "as_of": 0}
    names = {F_FIRST_DAY: "first_day", F_PART: "part", F_PARTS: "parts",
             F_LOG_KIB: "log_kib", F_AS_OF: "as_of"}
    i = 0
    while i < len(b):
        key, i = _read_varint(b, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _read_varint(b, i)
            if num in names:
                out[names[num]] = v & 0xFFFFFFFF
        elif wt == 2:
            n, i = _read_varint(b, i)
            if i + n > len(b):
                raise ValueError("truncated field")
            if num == F_DAYS:
                out["days"] = bytes(b[i:i + n])
            i += n
        else:
            raise ValueError("unexpected wire type %d" % wt)
    return out


def message_packet_field(summary):
    """MessagePacket.card_summary (field 12) wrapped around CardSummary bytes:
    what follows the header in a reply frame."""
    return _varint(MESSAGE_PACKET_FIELD << 3 | 2) + _varint(len(summary)) + summary
