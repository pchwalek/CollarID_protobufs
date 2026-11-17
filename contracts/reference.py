"""Reference implementation of the CollarID contracts (contracts/collarid_contracts.json).

The vectors (test_vectors/contracts_v1.json) are made from this file by
make_vectors.py, and every repo that implements one of these contracts runs
its own code over the same vectors. This file is the arbiter: when two
implementations disagree, the one that disagrees with this is wrong, or this
is, and then the vectors change first.

Standard library only. Ported from the implementations in use on 2026-10-16:
the website's js/u5-ota.js and js/wb-ota.js, the flash station's
ble_update.py, the radio firmware's custom_stm.c, the server's decoder.py.
"""

import json
import os
import re
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_PATH = os.path.join(HERE, "collarid_contracts.json")


def load_spec(path=SPEC_PATH):
    with open(path) as fh:
        return json.load(fh)


def _load_spec_or_generated():
    """The spec beside this file; a repo that vendors this file without the
    spec but with the generated Python module (collarid_contracts.py) reads
    that instead: the same data."""
    try:
        return load_spec()
    except FileNotFoundError:  # pragma: no cover - vendored copies only
        from collarid_contracts import CONTRACTS
        return CONTRACTS


SPEC = _load_spec_or_generated()
DFU = SPEC["dfu"]
CAPS = SPEC["caps"]


# ── CRC-32 (reflected 0xEDB88320, init and final 0xFFFFFFFF) ──────────────
def crc32(data):
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


# ── protobuf: the two fields the Bluetooth contracts need ─────────────────
def _varint(buf, i):
    val = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return val & 0xFFFFFFFF, i


def _enc_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _skip(buf, i, wire):
    if wire == 0:
        _, i = _varint(buf, i)
    elif wire == 2:
        n, i = _varint(buf, i)
        i += n
    elif wire == 5:
        i += 4
    elif wire == 1:
        i += 8
    else:
        i = len(buf)
    return i


def encode_special_mode(code):
    """BlePacket{ schedule_config_packet (field 2) { special_mode (field 3) = code } }."""
    inner = b"\x18" + _enc_varint(code)
    return b"\x12" + _enc_varint(len(inner)) + inner


def decode_special_mode(data):
    """special_mode out of a BlePacket, or None when absent."""
    data, i = bytes(data), 0
    while i < len(data):
        tag, i = _varint(data, i)
        field, wire = tag >> 3, tag & 7
        if field == 2 and wire == 2:
            length, i = _varint(data, i)
            end = i + length
            while i < end:
                t2, i = _varint(data, i)
                if t2 >> 3 == 3 and t2 & 7 == 0:
                    return _varint(data, i)[0]
                i = _skip(data, i, t2 & 7)
            return None
        i = _skip(data, i, wire)
    return None


def mtu_of_publish(code):
    """The MTU a radio publishes on entering DFU (0x4D54xxxx), or None."""
    if code is None or (code >> 16) != DFU["mtu_publish_tag"]:
        return None
    return code & 0xFFFF


def payload_for_mtu(mtu, cap):
    """Frame payload for a published MTU: one ATT write is MTU-3, a frame adds 11."""
    return max(20, min(cap, mtu - 3 - DFU["frame_overhead"]))


def encode_status_version(version):
    """BlePacket{ system_state_packet (field 3) { firmware_version (field 6) } }."""
    v = version.encode()
    inner = b"\x32" + _enc_varint(len(v)) + v
    return b"\x1a" + _enc_varint(len(inner)) + inner


def parse_status_version(data):
    data, i = bytes(data), 0
    while i < len(data):
        tag, i = _varint(data, i)
        field, wire = tag >> 3, tag & 7
        if field == 3 and wire == 2:
            length, i = _varint(data, i)
            end = i + length
            while i < end:
                t2, i = _varint(data, i)
                if t2 >> 3 == 6 and t2 & 7 == 2:
                    n, i = _varint(data, i)
                    return data[i:i + n].decode("utf-8", "replace")
                i = _skip(data, i, t2 & 7)
            return None
        i = _skip(data, i, wire)
    return None


def build_of_version(version):
    """Collars report 'b<build> <hash>'."""
    m = re.match(SPEC["version_report"]["pattern"], (version or "").strip())
    return int(m.group(1)) if m else None


def build_of_image(image, tag):
    """The single '<tag>:<n>:' stamp in an image (FWBUILD, RADIOBUILD), or None."""
    found = {int(m.group(1)) for m in re.finditer(re.escape(tag).encode() + rb":(\d+):", bytes(image))}
    return found.pop() if len(found) == 1 else None


# ── the capability characteristic ─────────────────────────────────────────
def parse_caps(raw):
    """-> {present, fmt, bits, family, build, kind}.

    raw None: no characteristic, the older radio. Formats 1-2 are the MkII
    Mesh radio (no family byte); format 3 adds the family at byte 4, format
    4 the build (u32 LE) at bytes 5-8."""
    fam_names = {v: k for k, v in CAPS["families"].items()}
    out = {"present": False, "fmt": 0, "bits": 0, "family": None, "build": None, "kind": "older"}
    if raw is None:
        return out
    raw = bytes(raw)
    out["present"] = True
    if len(raw) < 4 or raw[0:2] != CAPS["magic"].encode():
        out["kind"] = "unknown"
        return out
    out["fmt"], out["bits"] = raw[2], raw[3]
    if raw[2] >= CAPS["format_family"]:
        fam = raw[CAPS["family_offset"]] if len(raw) > CAPS["family_offset"] else None
        out["family"] = fam if fam in fam_names else None
    else:
        out["family"] = CAPS["families"]["wb5m"]
    if raw[2] >= CAPS["format_build"] and len(raw) >= CAPS["build_offset"] + 4:
        out["build"] = int.from_bytes(raw[CAPS["build_offset"]:CAPS["build_offset"] + 4], "little")
    out["kind"] = fam_names.get(out["family"], "unknown")
    return out


def caps_bytes(fmt, bits, family=None, build=None):
    """What a radio answers (the radio firmware's side)."""
    b = CAPS["magic"].encode() + bytes([fmt, bits])
    if fmt >= CAPS["format_family"]:
        b += bytes([family])
    if fmt >= CAPS["format_build"]:
        b += (build or 0).to_bytes(4, "little")
    return b


# ── the main chip's update stream (relayed by the radio) ──────────────────
def u5_stream(image, git_hash=""):
    """32-byte 'U5FW' header + image (js/u5-ota.js buildStream)."""
    h = bytearray(DFU["u5_header_len"])
    h[0:4] = DFU["u5_magic"].encode()
    h[4] = DFU["u5_header_version"]
    h[5] = SPEC["dfu"]["targets"]["u5"]
    h[8:12] = len(image).to_bytes(4, "little")
    h[12:16] = crc32(image).to_bytes(4, "little")
    gh = (git_hash or "")[:8].encode("ascii", "ignore")
    h[16:16 + len(gh)] = gh
    h[28:32] = crc32(bytes(h[:28])).to_bytes(4, "little")
    return bytes(h) + bytes(image)


def pad_to_batches(image, payload):
    """0xFF so header + image is a whole number of batches (js/u5-ota.js padToBatches)."""
    batch = payload * DFU["batch_frames"]
    pad = (batch - ((DFU["u5_header_len"] + len(image)) % batch)) % batch
    return bytes(image) + b"\xff" * pad


def data_frame(seq, chunk):
    """[0x11][seq u32 LE][len u16 LE][payload][crc32 of everything before]."""
    f = bytes([DFU["frame_data"]]) + seq.to_bytes(4, "little") + len(chunk).to_bytes(2, "little") + bytes(chunk)
    return f + crc32(f).to_bytes(4, "little")


def frames(stream, payload):
    return [data_frame(i, stream[off:off + payload]) for i, off in enumerate(range(0, len(stream), payload))]


def radio_start_frame(target, image):
    """[0x10][target][len u32 LE][image crc u32 LE][crc32 of the first 10 bytes] (js/wb-ota.js)."""
    h = bytes([DFU["frame_start"], target]) + len(image).to_bytes(4, "little") + crc32(image).to_bytes(4, "little")
    return h + crc32(h).to_bytes(4, "little")


# ── ErrorFlags.flag ───────────────────────────────────────────────────────
def error_flag_keys(word):
    """The keys of the bits set in an ErrorFlags.flag word, low bit first.
    A set bit no allocation names comes back as 'bit<n>'."""
    names = {b["bit"]: b["key"] for b in SPEC["error_flags"]["bits"]}
    return [names.get(i, f"bit{i}") for i in range(32) if word >> i & 1]


# ── Low-battery hibernation thresholds (2026-11-12) ───────────────────────
BATT = SPEC["battery_thresholds"]


def _strtol(text):
    """What C strtol(text, &end, 10) reads: leading whitespace, an optional
    sign, then digits. None when it reads nothing (end == text)."""
    if text is None:
        return None
    m = re.match(r"\s*([+-]?\d+)", str(text))
    return int(m.group(1)) if m else None


def battery_thresholds_valid(hibernate, resume):
    """The rails: a pair a push, the Bluetooth tunnel or a configurator may
    set. Anything else is refused whole (SCHED_RAIL_BAD_BATTERY_THRESHOLDS)."""
    try:
        h, r = int(hibernate), int(resume)
    except (TypeError, ValueError):
        return False
    if isinstance(hibernate, bool) or isinstance(resume, bool):
        return False
    return (BATT["hibernate_min"] <= h <= BATT["hibernate_max"]
            and BATT["resume_min"] <= r <= BATT["resume_max"]
            and r >= h + BATT["min_gap"])


def battery_thresholds_from_csv(hibernate_text, resume_text):
    """The pair a CONFIG.CSV gives (battery_hibernate_pct, battery_resume_pct
    rows; None = the row is missing). A row that reads as no number is the
    default; each value is held to its range; then resume is raised to
    hibernate + min_gap when below it. Always a valid pair."""
    h = _strtol(hibernate_text)
    r = _strtol(resume_text)
    h = BATT["hibernate_default"] if h is None else min(BATT["hibernate_max"], max(BATT["hibernate_min"], h))
    r = BATT["resume_default"] if r is None else min(BATT["resume_max"], max(BATT["resume_min"], r))
    if r < h + BATT["min_gap"]:
        r = h + BATT["min_gap"]
    return [h, r]


# ── Direct-radio regions (2026-11-17) ─────────────────────────────────────
#
# collarID_thread docs/CONTRACT_direct_regions.md. A rule set is a
# DirectRegion value; its bands, the countries that map to it, the devices
# and the constants are SPEC["direct_regions"]. Every function takes a rule
# set as its id (1..15), its key ("US915") or the rule-set dict itself (the
# vectors' synthetic rule set); 0, None and an unknown id are "no region",
# which passes every check and changes nothing (as before regions existed).
# Integers throughout: kHz, cdBm, cdBi, microseconds, milliseconds, seconds.
# beacon/c/direct_rules.c is the C port; both are held to the vectors.

DR = SPEC.get("direct_regions", {})
DR_CONST = DR.get("constants", {})
DR_REASONS = tuple(DR.get("reasons", ()))          # dr_check's answers, in the order they are judged
DR_BANDWIDTHS = tuple(DR_CONST.get("bandwidths_khz", ()))
DR_SLOTS = DR_CONST.get("buckets", 60) + 1         # 60 whole minutes + the current one


def dr_rule_set(rs):
    """The rule set for an id, a key or a rule-set dict; None = no region."""
    if rs is None or isinstance(rs, bool):
        return None
    if isinstance(rs, dict):
        return rs
    for r in DR["rule_sets"]:
        if (isinstance(rs, str) and r["key"] == rs) or (isinstance(rs, int) and r["id"] == rs):
            return r
    return None


def dr_device(dev="generic"):
    """A device: one of the spec's named profiles (collar_wio, collar_mk3,
    spotter, generic) or a dict {gain_cdbi, min_dbm, max_dbm}."""
    if dev is None:
        dev = "generic"
    return dev if isinstance(dev, dict) else DR["devices"][dev]


def dr_half_khz(bw_khz):
    """Half a channel, rounded up to the kHz: 63, 125, 250."""
    return (bw_khz + 1) // 2


def _dr_band(r, band):
    if r is None or not isinstance(band, int) or band < 0 or band >= len(r["bands"]):
        return None
    return r["bands"][band]


def _dr_holds(b, freq_khz, bw_khz):
    h = dr_half_khz(bw_khz)
    return b["lo_khz"] + h <= freq_khz <= b["hi_khz"] - h


def _dr_on_grid(b, freq_khz):
    if b["grid_step_khz"] is None:
        return True
    return (freq_khz - b["grid_base_khz"]) % b["grid_step_khz"] == 0   # mathematical modulo


def dr_band_of(rs, freq_khz, bw_khz):
    """The first band (table order) that holds the whole channel; -1 = none.
    The bandwidth is not judged: an air account counts a send in the band it
    lies in (a LoRaWAN uplink too) whatever the band allows."""
    r = dr_rule_set(rs)
    if r is None:
        return -1
    for i, b in enumerate(r["bands"]):
        if _dr_holds(b, freq_khz, bw_khz):
            return i
    return -1


def dr_power_cap(rs, band, device="generic"):
    """(cap_dbm, usable): min(band conducted, floor((band e.i.r.p. - antenna
    gain) / 100), device max); usable when the cap is at least the device's
    minimum. No rule set or no band: (device max, True)."""
    d = dr_device(device)
    b = _dr_band(dr_rule_set(rs), band)
    if b is None:
        return d["max_dbm"], True
    cap = min(b["conducted_dbm"], (b["eirp_cdbm"] - d["gain_cdbi"]) // 100, d["max_dbm"])
    return cap, cap >= d["min_dbm"]


def dr_toa_us(sf, bw_khz, n, preamble=None):
    """Time on air of an n-byte frame in microseconds: coding rate 4/5,
    explicit header, CRC on, low data rate optimisation when the symbol is
    longer than 16 ms, preamble 8 unless given. beacon/c/wake_frame.c
    wake_toa_us, bit for bit. 0 outside SF7..12 / 125, 250, 500 kHz /
    0..255 bytes / preamble 0..1024."""
    if preamble is None:
        preamble = DR_CONST["preamble_symbols"]
    if not (7 <= sf <= 12 and bw_khz in (125, 250, 500) and 0 <= n <= 255 and 0 <= preamble <= 1024):
        return 0
    ts = (1 << sf) * 1000 // bw_khz
    num, den = 8 * n - 4 * sf + 44, 4 * (sf - (2 if ts > 16000 else 0))
    payload_symbols = (-(-num // den)) * 5 if num > 0 else 0
    return (4 * preamble + 17 + 32 + 4 * payload_symbols) * (ts // 4)


def dr_frame_fits(sf, bw_khz, n, max_send_ms):
    """An n-byte frame is shorter than a send limit (0 = no limit). A
    setting with no time on air (outside SF7..12 / 125, 250, 500 kHz) never
    fits a limit."""
    if not max_send_ms:
        return True
    toa = dr_toa_us(sf, bw_khz, n)
    return toa != 0 and toa < max_send_ms * 1000


def dr_max_len(sf, bw_khz, max_send_ms):
    """The longest payload (0..255) shorter than max_send_ms on air; 255 when
    there is no limit (0); -1 when nothing fits or the setting is not one."""
    if dr_toa_us(sf, bw_khz, 0) == 0:
        return -1
    best = -1
    for n in range(256):
        if not dr_frame_fits(sf, bw_khz, n, max_send_ms):
            break
        best = n
    return best


def dr_lbt(rs, band):
    """(threshold dBm, listen ms) of a band's listen-before-talk, or None."""
    b = _dr_band(dr_rule_set(rs), band)
    return None if b is None or not b["lbt_ms"] else (b["lbt_dbm"], b["lbt_ms"])


def dr_send_limit(rs, band):
    """(max send ms, pause ms) of a band, or None when it has no limit."""
    b = _dr_band(dr_rule_set(rs), band)
    return None if b is None or not b["max_send_ms"] else (b["max_send_ms"], b["pause_ms"])


def dr_band_max_len(rs, band, sf, bw_khz):
    b = _dr_band(dr_rule_set(rs), band)
    return dr_max_len(sf, bw_khz, b["max_send_ms"] if b else 0)


def dr_check(rs, sf, bw_khz, freq_khz, device="generic"):
    """A NEW setting (contract section 4): "OK" or the reason it is refused.
    Each band is judged in this order: it holds the whole channel, allows
    the bandwidth, has the centre on its grid, is usable by the device, and a
    64-byte frame at (sf, bw) is shorter than its send limit. The answer is
    "OK" when one band passes all five, else the reason of the band that got
    furthest (NO_BAND < BANDWIDTH < GRID < POWER_FLOOR < FRAME_TIME). Power
    is never a reason: a send above the cap goes out at the cap."""
    r = dr_rule_set(rs)
    if r is None:
        return DR_REASONS[0]
    d = dr_device(device)
    best = 1
    for i, b in enumerate(r["bands"]):
        if not _dr_holds(b, freq_khz, bw_khz):
            stage = 1
        elif bw_khz not in b["bw_khz"]:
            stage = 2
        elif not _dr_on_grid(b, freq_khz):
            stage = 3
        elif not dr_power_cap(r, i, d)[1]:
            stage = 4
        elif not dr_frame_fits(sf, bw_khz, DR_CONST["base_frame_bytes"], b["max_send_ms"]):
            stage = 5
        else:
            return DR_REASONS[0]
        best = max(best, stage)
    return DR_REASONS[best]


def _dr_bw_index(bw_khz):
    """125 -> 0, 250 -> 1, 500 -> 2; a bandwidth that is not one of them is
    read as the next of them up (62.5 kHz as 125, as the US rule's '125, or
    anything narrower'), at most 500."""
    for i, b in enumerate(DR_BANDWIDTHS):
        if bw_khz <= b:
            return i
    return len(DR_BANDWIDTHS) - 1


def _dr_nearest_on(base, step, a, b, f):
    """The point base + k x step in [a, b] nearest f, ties to the lower; None if none."""
    g0 = base + (-((base - a) // step)) * step          # the first point >= a
    g1 = base + ((b - base) // step) * step              # the last point <= b
    if g0 > g1:
        return None
    if f <= g0:
        return g0
    if f >= g1:
        return g1
    lower = base + ((f - base) // step) * step
    upper = lower if lower == f else lower + step
    return lower if f - lower <= upper - f else upper


def _dr_nearest_centre(b, bw_khz, freq_khz):
    h = dr_half_khz(bw_khz)
    lo, hi = b["lo_khz"] + h, b["hi_khz"] - h
    if lo > hi:
        return None
    if b["grid_step_khz"] is not None:
        return _dr_nearest_on(b["grid_base_khz"], b["grid_step_khz"], lo, hi, freq_khz)
    if freq_khz % 1000 == 0:
        whole = _dr_nearest_on(0, 1000, lo, hi, freq_khz)
        if whole is not None:
            return whole
    return min(max(freq_khz, lo), hi)


def dr_default_channel(rs):
    """(sf, bw_khz, freq_khz) of a rule set's default channel; with no region, today's (US) default."""
    r = dr_rule_set(rs)
    d = r["default"] if r else DR["no_region_default"]
    return d["sf"], d["bw_khz"], d["freq_khz"]


def dr_convert(rs, sf, bw_khz, freq_khz):
    """A SAVED setting (contract section 5): (sf', bw', freq', how), how =
    "kept" (it passes the check with the generic device), "moved" (onto the
    nearest legal channel of a band holding the frequency) or "default" (no
    band holds the frequency, or none has a legal centre for the bandwidth:
    the rule set's default channel). Independent of the device. Coding rate
    and sync word never change."""
    r = dr_rule_set(rs)
    if r is None or dr_check(r, sf, bw_khz, freq_khz, "generic") == DR_REASONS[0]:
        return sf, bw_khz, freq_khz, "kept"
    bi = _dr_bw_index(bw_khz)
    best = None
    for i, b in enumerate(r["bands"]):
        if not b["lo_khz"] <= freq_khz <= b["hi_khz"]:
            continue
        allowed = sorted(b["bw_khz"])
        if DR_BANDWIDTHS[bi] in allowed:
            nb = DR_BANDWIDTHS[bi]
        else:
            wider = [x for x in allowed if x > DR_BANDWIDTHS[bi]]
            nb = min(wider) if wider else max(x for x in allowed if x < DR_BANDWIDTHS[bi])
        nsf = min(max(sf + _dr_bw_index(nb) - bi, DR_CONST["sf_min"]), DR_CONST["sf_max"])
        nf = _dr_nearest_centre(b, nb, freq_khz)
        if nf is None:
            continue
        key = (abs(nf - freq_khz), -b["eirp_cdbm"], b["lo_khz"])
        if best is None or key < best[0]:
            best = (key, i, nsf, nb, nf)
    if best is None:
        dsf, dbw, df = dr_default_channel(r)
        return dsf, dbw, df, "default"
    _, i, nsf, nb, nf = best
    limit = r["bands"][i]["max_send_ms"]
    while nsf > DR_CONST["sf_min"] and not dr_frame_fits(nsf, nb, DR_CONST["base_frame_bytes"], limit):
        nsf -= 1
    return nsf, nb, nf, "moved"


def dr_air_limit_ms(rs, band, cls="normal"):
    """The most a class may have used in the hour: the whole budget for
    "beacon" (lost-mode and find-mode beacons), 75 % of it (rounded down)
    for "normal" (everything else). 0 = the band has no budget."""
    b = _dr_band(dr_rule_set(rs), band)
    if b is None or not b["budget_ms_per_h"]:
        return 0
    budget = b["budget_ms_per_h"]
    return budget if cls == "beacon" else budget * DR_CONST["normal_share_pct"] // 100


class DrAirAccount:
    """The sliding one-hour air account of one device in the bands of one
    rule set (contract section 8): per band, the ms sent in each of the last
    60 whole minutes and in the current one (so it covers up to 61 minutes:
    conservative, never generous). Kept in RAM; empty at start. now_s is
    whole seconds on a clock that does not go back (uptime); a minute is
    now_s // 60. Record a send after it ends, with now_s = its end. Bands
    without a budget are not tracked (used 0, wait 0)."""

    def __init__(self, rs):
        self.r = dr_rule_set(rs)
        n = len(self.r["bands"]) if self.r else 0
        self.minute = None                      # the newest minute held
        self.ms = [[0] * DR_SLOTS for _ in range(n)]

    def _tracked(self, band):
        b = _dr_band(self.r, band)
        return b is not None and b["budget_ms_per_h"] > 0

    def record(self, band, now_s, ms):
        if not self._tracked(band):
            return
        m = now_s // 60
        if self.minute is None:
            self.minute = m
        elif m > self.minute:
            for k in range(1, min(m - self.minute, DR_SLOTS) + 1):
                for row in self.ms:
                    row[(self.minute + k) % DR_SLOTS] = 0
            self.minute = m
        # a clock that went back records into the newest minute
        self.ms[band][self.minute % DR_SLOTS] += ms

    def _window(self, now_s):
        """(first, last) minute of the window ending at now_s: the current
        minute (or the newest held, when the clock went back) and the 60
        before it; data is held up to self.minute."""
        eff = max(now_s // 60, self.minute)
        return max(eff - 60, 0), self.minute

    def used_ms(self, band, now_s):
        if not self._tracked(band) or self.minute is None:
            return 0
        lo, hi = self._window(now_s)
        return sum(self.ms[band][k % DR_SLOTS] for k in range(lo, hi + 1))

    def wait_s(self, band, now_s, ms, cls="normal"):
        """0 when an ms-long send of the class fits now; else the whole
        seconds until enough of the oldest minutes leave the window (a
        minute k leaves at (k + 61) x 60 s); None ("never") when the send
        alone is over the class limit."""
        if not self._tracked(band):
            return 0
        limit = dr_air_limit_ms(self.r, band, cls)
        if ms > limit:
            return None
        used = self.used_ms(band, now_s)
        if used + ms <= limit:
            return 0
        excess, released = used + ms - limit, 0
        lo, hi = self._window(now_s)
        for k in range(lo, hi + 1):
            released += self.ms[band][k % DR_SLOTS]
            if released >= excess:
                return (k + DR_SLOTS) * 60 - now_s
        raise AssertionError("unreachable: the send alone fits the limit")


def dr_schedule_need(rs, sf, bw_khz, freq_khz, reports_per_h, report_bytes,
                     lost_per_h=0, lost_bytes=0, find_per_h=0, find_bytes=0):
    """Schedule fit (contract section 8) for the band of the base channel:
    the air needed per hour at (sf, bw) = reports x toa(report) (the normal
    part) + lost-mode beacons x toa + find-mode beacons x toa (the beacon
    part). Counts are whole sends per hour (a send every I seconds is
    ceil(3600 / I)). Refused when the normal part is over 75 % of the budget
    ("normal_over", judged first) or the whole is over it ("total_over");
    "no_budget" (fits) when the band has none, there is no region or the
    channel is in no band. ms values are rounded up; the verdict is taken
    in microseconds."""
    r = dr_rule_set(rs)
    band = dr_band_of(r, freq_khz, bw_khz) if r else -1
    b = _dr_band(r, band)
    budget = b["budget_ms_per_h"] if b else 0
    normal_limit = dr_air_limit_ms(r, band, "normal")
    normal_us = reports_per_h * dr_toa_us(sf, bw_khz, report_bytes)
    beacon_us = lost_per_h * dr_toa_us(sf, bw_khz, lost_bytes) + find_per_h * dr_toa_us(sf, bw_khz, find_bytes)
    need_us = normal_us + beacon_us
    if budget == 0:
        fits, reason = True, "no_budget"
    elif normal_us > normal_limit * 1000:
        fits, reason = False, "normal_over"
    elif need_us > budget * 1000:
        fits, reason = False, "total_over"
    else:
        fits, reason = True, "fits"
    up = lambda us: -(-us // 1000)  # noqa: E731
    return {"band": band, "budget_ms": budget, "normal_limit_ms": normal_limit, "need_ms": up(need_us),
            "normal_ms": up(normal_us), "beacon_ms": up(beacon_us), "fits": fits, "reason": reason}


def dr_region_resolve(setting, lorawan_region=None, freq_khz=0):
    """The rule set a device runs (contract section 9): a setting of 1..15 is
    that rule set; 0 (AUTO) takes the LoRaWAN region when LoRaWAN is
    configured (lorawan_region, a ble.proto RadioRegion value; None = not
    configured: 0 -> 1, 1 -> 3, 2 -> 2, others none), else the direct radio's
    frequency (863000..870000 kHz EU868, 902000..928000 kHz US915); anything
    else, a setting above 15 included, is 0 (none)."""
    if 1 <= setting <= DR_CONST["region_max"]:
        return setting
    if setting != 0:
        return 0
    if lorawan_region is not None:
        return dict(DR["auto"]["lorawan"]).get(lorawan_region, 0)
    for lo, hi, region in DR["auto"]["frequency_khz"]:
        if lo <= freq_khz <= hi:
            return region
    return 0


def dr_wake_channel(rs, long_range=False):
    """A rule set's wake channel: {freq_hz, bw_khz, sf, max_dbm}, max_dbm the
    cap of its band for the generic device (a device uses dr_power_cap with
    its own profile); None for no region."""
    r = dr_rule_set(rs)
    if r is None:
        return None
    w = r["wake"]
    cap, _ = dr_power_cap(r, dr_band_of(r, w["freq_hz"] // 1000, w["bw_khz"]), "generic")
    return {"freq_hz": w["freq_hz"], "bw_khz": w["bw_khz"], "sf": w["sf_long"] if long_range else w["sf"],
            "max_dbm": cap}


def dr_freq_to_fields(freq_khz):
    """(frequency, frequency_khz) to write (LoRaConfig 6/10, RadioSettings
    6/14, CONFIG.CSV lora_frequency / lora_frequency_khz): a whole MHz is
    (MHz, 0); anything else is (the nearest MHz, a half up; the kHz)."""
    return (freq_khz + 500) // 1000, (0 if freq_khz % 1000 == 0 else freq_khz)


def dr_freq_from_fields(frequency_mhz, frequency_khz=0):
    """The frequency in kHz a reader takes: frequency_khz when it is not 0,
    else the whole MHz."""
    return frequency_khz if frequency_khz else frequency_mhz * 1000


def dr_country(iso):
    for c in DR["countries"]:
        if c["iso"] == iso:
            return c
    return None


def dr_countries_by_name():
    """The list a website or app shows: sorted by English name."""
    return sorted(DR["countries"], key=lambda c: c["name"])


# The US rule of CONTRACT_us_500khz.md, now one row of the table (US915).
def us500_allowed(sf, bw_khz, freq_mhz):
    return dr_check(1, sf, bw_khz, freq_mhz * 1000, "generic") == DR_REASONS[0]


def to_us500(sf, bw_khz, freq_mhz):
    """CONTRACT_us_500khz.md section 3, through dr_convert: (sf', 500, MHz')."""
    s, b, f, _ = dr_convert(1, sf, bw_khz, freq_mhz * 1000)
    return s, b, f // 1000
