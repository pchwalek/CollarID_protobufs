#!/usr/bin/env python3
"""Make test_vectors/card_summary_v1.json from the reference codec.

    python3 make_card_summary_vectors.py           write the vectors
    python3 make_card_summary_vectors.py --check   exit 1 if the checked-in JSON is stale

Synthetic (times in 2027). The collar firmware vendors the JSON
(collarID_thread test/host/data/card_summary_v1.json) and replays it; the
server and the clients decode against it. Deterministic.
"""

import json
import os
import sys

import card_summary as cs

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, os.pardir, "test_vectors", "card_summary_v1.json")

D0 = 1798761600            # 2027-01-01 00:00:00 UTC
DAY = cs.DAY_S
H = cs.HOUR_S


def day_vectors():
    cases = [
        ("an empty day", [], 0, [], 0),
        ("one take at 05:00, 3 MiB", [5], 3, [], 0),
        ("movement all day", [], 0, list(range(24)), 41),
        ("sound evenings, movement all day", [18, 19, 20, 21, 22], 1200, list(range(24)), 40),
        ("hour 0 and hour 23 only", [0, 23], 1, [0, 23], 1),
        ("saturated sizes", list(range(24)), cs.MIB_SAT, list(range(24)), cs.MIB_SAT),
        ("byte order: 0x0102 MiB, hours 1 and 9 and 17", [1, 9, 17], 0x0102, [2, 10, 18], 0x0201),
    ]
    out = []
    for name, sh, sm, mh, mm in cases:
        b = cs.encode_day(sh, sm, mh, mm)
        out.append({"name": name, "sound_hours": sh, "sound_mib": sm, "movement_hours": mh,
                    "movement_mib": mm, "hex": b.hex()})
    return out


def mib_vectors():
    out = []
    for n in (0, 1, 1023, 1024, (1 << 20) - 1, 1 << 20, (1 << 20) + 1, 5 * (1 << 20),
              cs.MIB_SAT << 20, (cs.MIB_SAT << 20) + 1, 1 << 40):
        out.append({"bytes": n, "kib": cs.kib_from_bytes(n), "mib": cs.mib_from_bytes(n),
                    "mib_of_kib": cs.mib_from_kib(cs.kib_from_bytes(n))})
    return out


def span_vectors():
    cases = [
        ("a take inside one hour", D0, D0 + 5 * H + 60, D0 + 5 * H + 1800),
        ("an hourly take from 19:30", D0, D0 + 19 * H + 1800, D0 + 20 * H + 1800),
        ("ends exactly on the hour: that hour's first second", D0, D0 + 7 * H, D0 + 8 * H),
        ("ends a second before the hour", D0, D0 + 7 * H, D0 + 8 * H - 1),
        ("a day-long movement file", D0, D0, D0 + DAY - 1),
        ("a movement file to the midnight rollover", D0, D0, D0 + DAY),
        ("over midnight: the first day", D0, D0 + 23 * H + 1800, D0 + DAY + 1800),
        ("over midnight: the second day", D0 + DAY, D0 + 23 * H + 1800, D0 + DAY + 1800),
        ("a span on another day", D0 + 2 * DAY, D0 + 3600, D0 + 7200),
        ("end before start reads as start", D0, D0 + 10 * H + 5, D0 + 9 * H),
        ("a clock jump: held to a day and an hour (the first day)", D0, D0 + 22 * H, D0 + 9 * DAY),
        ("a clock jump: held to a day and an hour (the next day)", D0 + DAY, D0 + 22 * H, D0 + 9 * DAY),
        ("a clock jump: nothing two days on", D0 + 2 * DAY, D0 + 22 * H, D0 + 9 * DAY),
    ]
    out = []
    for name, day, start, end in cases:
        m = cs.span_hours(day, start, end)
        out.append({"name": name, "day": day, "start": start, "end": end, "hours": cs.hours_list(m)})
    return out


def window_vectors():
    now = D0 + 40 * DAY + 13 * H        # 2027-02-10 13:00
    cases = [
        ("defaults: the 30 days that end today", 0, 0),
        ("7 days that end today", 0, 7),
        ("one day", 0, 1),
        ("62 days", 0, 62),
        ("more than 62 is held to 62", 0, 100),
        ("from a time on a day", D0 + 3 * DAY + 17 * H + 5, 10),
        ("from a midnight", D0 + 5 * DAY, 0),
        ("from the future: days with nothing yet", now + 3 * DAY, 2),
    ]
    out = []
    for name, f, d in cases:
        first, n = cs.window(f, d, now)
        out.append({"name": name, "from_epoch": f, "days": d, "now": now, "first_day": first, "n": n})
    return out


def split_vectors():
    return [{"days": n, "frames": [list(p) for p in cs.split(n)]} for n in (1, 15, 16, 17, 30, 32, 33, 48, 49, 62)]


def summary_vectors():
    days = [cs.encode_day([18, 19, 20], 900, list(range(24)), 38),
            cs.encode_day([], 0, list(range(24)), 40),
            cs.encode_day([4, 5], 120, list(range(12)), 21)]
    full = b"".join(cs.encode_day([h % 24], h, list(range(24)), 40 + h) for h in range(16))
    cases = [
        ("three days, part 1 of 1 with the log", D0 + 7 * DAY, b"".join(days), 1, 1, 2048, D0 + 10 * DAY + 600),
        ("a full frame of 16 days, part 2 of 4 (no log)", D0, full, 2, 4, 0, D0 + 70 * DAY),
        ("one empty day", D0 + 3 * DAY, cs.encode_day(), 1, 1, 1, D0 + 3 * DAY + 5),
        ("every uint32 at its largest", 0xFFFFFFFF - 0xFFFFFFFF % DAY, full, 4, 4, 0xFFFFFFFF, 0xFFFFFFFF),
    ]
    out = []
    for name, first, d, part, parts, log_kib, as_of in cases:
        b = cs.encode_summary(first, d, part, parts, log_kib, as_of)
        out.append({"name": name, "first_day": first, "days_hex": d.hex(), "part": part,
                    "parts": parts, "log_kib": log_kib, "as_of": as_of, "hex": b.hex(),
                    "field12_hex": cs.message_packet_field(b).hex()})
    return out


def build():
    return {
        "about": ("What's on the card v1 (reference/CARD_SUMMARY_V1.md): CMD_CARD_SUMMARY's answer. "
                  "Generated by reference/make_card_summary_vectors.py from reference/card_summary.py; "
                  "do not edit. Synthetic: times in 2027."),
        "version": 1,
        "day_len": cs.DAY_LEN,
        "days_per_frame": cs.DAYS_PER_FRAME,
        "frames_max": cs.FRAMES_MAX,
        "days_default": cs.DAYS_DEFAULT,
        "days_max": cs.DAYS_MAX,
        "mib_saturated": cs.MIB_SAT,
        "span_max_s": cs.SPAN_MAX_S,
        "message_packet_field": cs.MESSAGE_PACKET_FIELD,
        "days": day_vectors(),
        "sizes": mib_vectors(),
        "spans": span_vectors(),
        "windows": window_vectors(),
        "splits": split_vectors(),
        "summaries": summary_vectors(),
    }


def render():
    doc = build()
    lines = ["{"]
    keys = list(doc.keys())
    for i, k in enumerate(keys):
        v = doc[k]
        comma = "," if i < len(keys) - 1 else ""
        if isinstance(v, list):
            lines.append("  %s: [" % json.dumps(k))
            for j, e in enumerate(v):
                lines.append("    %s%s" % (json.dumps(e, separators=(", ", ": ")), "," if j < len(v) - 1 else ""))
            lines.append("  ]%s" % comma)
        else:
            lines.append("  %s: %s%s" % (json.dumps(k), json.dumps(v), comma))
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv):
    text = render()
    if "--check" in argv:
        try:
            with open(OUT, encoding="utf-8") as fh:
                same = fh.read() == text
        except FileNotFoundError:
            same = False
        print("up to date" if same else "STALE: run make_card_summary_vectors.py")
        return 0 if same else 1
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote %s" % os.path.normpath(OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
