# CollarID lost-mode beacon: the wire contract

A collar in lost mode broadcasts a short raw-LoRa frame at a fixed cadence so
that a searcher can find it. This directory is the public specification of
that frame, for anyone building a receiver: the plaintext v1 frame every
collar sends today, the encrypted v2 frame a keyed collar will send, the
sealed report a keyed collar sends in place of its regular plaintext radio
report, the key derivation an owner's receiver needs, a reference
implementation in Python and C, and frozen test vectors. It also holds the
frames a Handheld Receiver sends to a collar: the signed command, and the
wake frame and roll call with which it reaches a collar that is listening
for it.

Where a receiver and this text disagree, one of them has a bug, and the
vectors decide. Everything here is synthetic: no real collar identifier, key or
position appears anywhere in this repository.

## Contents

| File | What it is |
|---|---|
| `beacon_v2.py` | Reference codec and command-line tool (Python 3, standard library only). |
| `c/aead_ccm.[ch]`, `c/beacon_frame.[ch]` | The same codec in C11 over an injected AES block function; byte-identical copies of the collar firmware's files. |
| `c/wake_frame.[ch]` | The wake frame, the wake channel table, the timing and the roll call in C11 (whole microseconds, no float), for the collar firmware and the Handheld Receiver to copy byte for byte. |
| `vectors.json` | Frozen known-answer vectors (below). |
| `make_vectors.py` | Regenerates `vectors.json` from the codec; `--check` fails if the file is stale. |
| `test_beacon_v2.py` | `python3 -m unittest -v` in this directory. |
| `test_wake_frame_c.py`, `c/test/wake_frame_harness.c` | Compiles `c/wake_frame.c` and holds it to the vectors and to `beacon_v2.py` (the same `python3 -m unittest`; skipped without a C compiler). |

## Frames

A receiver dispatches on the first byte and the length. Anything else is not a
beacon (a collar's plaintext radio report, for one: it is a protobuf
`MessagePacket` and always starts `0x0A`).

| Magic | Length | Frame |
|---|---|---|
| `0x4C` (`'L'`) | 18 B | v1, plaintext. What an unkeyed collar sends. Stays decodable forever. |
| `0x4D` (`'M'`) | 30 B | v2, AES-128-CCM. What a keyed collar sends. |
| `0x52` (`'R'`) | 18..255 B | Sealed report: a keyed collar's regular radio report, AES-128-CCM (below). |
| `0x44` (`'D'`) | 30..255 B | Signed handheld command, to a collar (below). Not a beacon: a receiver relays it, never decodes it as one. |
| `0x4B` (`'K'`) | 25 B | A collar's acknowledgement of a command (below). |
| `0x57` (`'W'`) | 5..13 B | Wake frame, to listening collars: cleartext, sent as a train on the wake channel (below). |
| `0x43` (`'C'`) | 29 B | Roll call, to every collar of a group: AES-128-CCM under the group's wake key (below). |

All integers are little-endian.

### v1 (0x4C), 18 bytes

```
[0]      u8   0x4C
[1..4]   u32  uid          the collar's on-air identifier
[5..8]   i32  lat_e7       latitude  x 1e7, WGS-84
[9..12]  i32  lon_e7       longitude x 1e7
[13..16] u32  fix_epoch    UTC seconds the GPS fix was taken; 0 = no position
[17]     u8   batt_pct     battery, 0..100
```

### v2 (0x4D), 30 bytes

```
[0]      u8   0x4D
[1..4]   u32  uid          cleartext: key lookup, searcher identification
[5..8]   u32  ctr          cleartext transmit counter (see "Counter")
[9..21]  13 B ciphertext   the v1 body [5..17] (lat_e7, lon_e7, fix_epoch, batt_pct), encrypted
[22..29] 8 B  tag          authentication tag
```

The body is exactly v1's bytes [5..17]; only its confidentiality and
integrity change.

### No position

`fix_epoch` = 0 means "no position", in either frame: never a place at 0, 0
and never a time in 1970. The collar sends it with `lat_e7` = `lon_e7` = 0,
and a receiver ignores the latitude and longitude of any frame whose
`fix_epoch` is 0.

A collar in lost mode sends its beacon at every interval, whether or not it
has a GPS fix:

- With a fix, the frame carries the collar's most recent accepted fix, and
  `fix_epoch` is the time that fix was taken, not the time the frame was sent.
  A collar that cannot get a new fix (under dense canopy, indoors) keeps
  sending its last one with its original `fix_epoch`, so a position can be
  hours old: show its age with it.
- With none (no fix since the collar started), the frame carries the
  no-position values above. A searcher still homes in on its RSSI, exactly as
  on a v2 frame it cannot open.

One collar's stream can therefore go fix, no position (after a restart), fix.
A no-position frame is not a fix "going backwards" and does not replace the
last fix a receiver has seen: compare the next fix against that one.

### Cipher

AES-128-CCM as in RFC 3610 (NIST SP 800-38C), with

- L = 2 (two-byte length field, so the nonce is 13 bytes),
- M = 8 (eight-byte tag),
- **AAD** = the nine cleartext bytes `[0..8]` (magic, uid, ctr),
- **nonce** (13 bytes) = `uid_le32 || ctr_le32 || dir || 00 00 00 00`, where
  `dir = 0x00` for every collar-originated beacon (`0x01` and `0x02` are
  reserved for a future command channel and never appear in a beacon).

In `cryptography` (Python) that is one call:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
uid = int.from_bytes(frame[1:5], "little"); ctr = int.from_bytes(frame[5:9], "little")
nonce = frame[1:9] + b"\x00" * 5
body = AESCCM(dev_key, tag_length=8).decrypt(nonce, frame[9:30], frame[0:9])
```

For a receiver without a CCM library: B_0 has flag byte `0x59`, the single
AAD block is `00 09 || AAD || zero padding`, the counter blocks A_i have flag
byte `0x01`, and a frame costs five AES-128 block operations in the forward
direction only.

### Counter

`ctr` is split: bits `[31:24]` are the **provision generation** (`gen`,
1..255) and bits `[23:0]` a sequence that the collar never rewinds (it
survives resets and battery removal). The generation is bumped whenever the
collar is (re)provisioned with a key, and it is part of the key derivation, so
a re-provisioned collar transmits under a new key with a sequence that starts
again at zero. A receiver must therefore never treat `ctr` values from
different generations as one sequence.

Replay: a rebroadcast frame is byte-identical, and CCM cannot tell. A receiver
should keep the highest `ctr` seen per `uid` in a session, flag a frame at or
below it as a replay or duplicate, and show the age of the fix from the
authenticated `fix_epoch` (a frame with `fix_epoch` 0 has no fix to age).

### A beacon outside lost mode: the key check

Right after a collar takes a new key over Bluetooth, it sends ONE v2 frame
under that key even when it is not in lost mode, on the radio settings its
lost-mode beacon uses, so that a receiver holding the key (or the key's
owner, through their server) can confirm the collar really has it. It is an
ordinary v2 frame: same layout, same key, and a `ctr` taken from the same
never-rewinding sequence as every other beacon (it is usually the first
frame of the new generation, `seq` 0). Only a key that actually changed sends
one: a retry of the key the collar already holds does not.

Like a lost-mode beacon, a key check from a collar without a GPS fix carries
the no-position values (`fix_epoch` 0, see "No position" above).

### Sealed report (0x52), 18..255 bytes

Besides its lost-mode beacon, a collar with direct radio enabled sends a
regular report over the same raw LoRa settings: a protobuf `MessagePacket`
(`message.proto` in this repository), which an unkeyed collar sends in the
clear. A collar that holds a device key sends that report sealed instead
(added 2026-09-30):

```
[0]          u8    0x52
[1..4]       u32   uid          cleartext, as v2
[5..8]       u32   ctr          cleartext, as v2 (see "Counter")
[9..9+n-1]   n B   ciphertext   the report's protobuf bytes, encrypted; 1 <= n <= 238
[9+n..9+n+7] 8 B   tag          authentication tag
frame length n + 17 = 18..255 bytes (one LoRa packet)
```

It is the v2 construction byte for byte, with a longer body: the same device
key, AAD = the nine cleartext bytes `[0..8]`, the same 13-byte nonce
(`uid_le32 || ctr_le32 || 00 || 00 00 00 00`), AES-128-CCM with L = 2 and
M = 8. Sealing a 13-byte beacon body this way with magic `0x4D` gives exactly
the v2 frame; only the magic and the body length differ. The magic is part of
the AAD, so a report never opens as a beacon or the other way round.

- **One counter for every sealed frame.** `ctr` is the same never-rewinding
  counter the collar's v2 beacons use: each sealed frame the collar sends,
  report or beacon, takes the next value of one sequence. A report and a
  beacon never share a `ctr`, so no nonce is ever used twice under a key.
  Receivers keep the replay rules of v2, with one high-water mark per `uid`
  across beacons and reports (a frame at or below it is a replay or
  duplicate), and never one sequence across generations.
- **Without the key** a receiver still learns which collar it hears (`uid`),
  its counter, RSSI and SNR, nothing of the report: show it as a locked row,
  as for a v2 frame it cannot open.
- **With the key** the opened bytes are the protobuf `MessagePacket` the
  collar would otherwise have sent in the clear; decode them exactly as a
  plaintext report.
- **Size.** A sealed frame carries at most 238 bytes of report (255 on
  air): the collar fits the report to that before sealing (what does not fit
  waits for its next report). A collar without a key still sends plaintext
  reports of up to 255 bytes.

In `cryptography` (Python):

```python
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
nonce = frame[1:9] + b"\x00" * 5
report = AESCCM(dev_key, tag_length=8).decrypt(nonce, frame[9:], frame[0:9])
```

A report costs `2 * ceil(n / 16) + 3` AES-128 block operations
(CBC-MAC over B_0, the AAD block and the payload; CTR over the payload and the
tag): 33 for the largest.

### Signed handheld command (0x44) and its acknowledgement (0x4B)

A Handheld Receiver carries a command the server signed and sends it in the
receive window a collar opens after its own direct-radio frame
(`DESIGN_finder_two_way.md` in the collar firmware repository, sections 6 and
6A). The frame holds a `DownlinkPacket` (downlink.proto), so a command means
exactly what it means over LoRaWAN.

    [0]          0x44
    [1..4]       uid32 (little-endian), cleartext
    [5..8]       cmd_counter, cleartext: [31:24] provision generation, [23:0] sequence
    [9..]        AES-128-CCM ciphertext of
                   echo u32 || valid_from u32 || valid_to u32 || DownlinkPacket (1..226 B)
    last 8       tag
    AAD = bytes [0..8]; nonce = uid_le32 || ctr_le32 || 0x01 || 0x00000000

The key is the device's COMMAND key, `AES-CMAC(command master, "CID-LORA-CMD"
|| uid_le32 || gen)`; the command master never leaves the server, and the
beacon key family can never open one (the test pins it). The collar accepts a
command only with a counter strictly above the last it accepted (persisted
before it acts), and only while fresh: `echo` non-zero must equal the echo of
the frame that opened the window (live signing); `echo` zero means the
command is pre-signed: `valid_to` must be set and `now` must lie in
`[valid_from, valid_to]`. A collar with no valid clock says nothing to a
pre-signed command and does not use its counter up, so the handheld can try
again (its INTENT can carry the time). Pre-signed commands are how a phone
and a receiver work with no signal: they are signed before the trip.

The collar answers with a 25-byte acknowledgement sealed under the same key,
the command's counter and direction byte 0x02:

    [0] 0x4B  [1..4] uid  [5..8] the command's counter
    ciphertext of result u8 || command u8 || detail u32 || rssi i8 || snr_q4 i8
    8-byte tag

`result`: 1 accepted, 2 no release unit, 3 bad echo, 4 expired, 5 unknown
command, 6 queue full, 7 refused on this carrier, 8 reserved (no clock: the
collar answers nothing instead), 9 session open (detail = the SF), 10 session
closed, 11 settings piece not used (detail = the unfinished transaction in
the way, 0 = none; a piece of a newer handheld push replaces an unfinished
transaction that a signed frame opened; one opened over LoRaWAN or Bluetooth
is not replaced until it is past its 10 min limit, after which a piece of any
newer transaction drops it and the collar reports EXPIRED for it), 12
Bluetooth file window refused (`CMD_BLE_WINDOW`; detail = why: 1 no window
key, 2 the radio cannot serve files, 3 no card, 4 battery low, 5 a firmware
update is running, 6 the window asks for audio (`ble_window.kinds` bit 2)
and its range is missing, reversed or over 24 hours (added 2026-11-16); an
opened window answers 1 accepted with detail = the minutes granted;
`../bulk/README.md`). Since 2026-11-16 result 12 is also how
`CMD_CARD_SUMMARY` says the card cannot answer: detail 3 no readable card,
7 the card's day index is still being built (ask again later).
For `CMD_CARD_SUMMARY`, the detail of result 1 is the number of reply frames
that follow (1..4), each a report frame carrying `card_summary`
(`../reference/CARD_SUMMARY_V1.md`).
For `CMD_RESEND`, the detail of result 1 is the number of frames that follow:
the asked-for ones the collar's ring holds, at most 4.
For `CMD_LOCATE_NOW` (downlink.proto), the detail of result 1 is the time the
GPS attempt may take, in seconds; the report with the fix follows on the wake
channel while the collar's call window is open.
`rssi`/`snr_q4` are how the collar
heard the command. Vectors: `commands` and `command_acks` in `vectors.json`.

### Wake frame (0x57), 5..13 bytes

A collar can be set to listen for a Handheld Receiver (added 2026-11-13). In
the hours its schedule says so (`ScheduleConfig.lora_wake_interval_s` in
`ble.proto`: 10, 30 or 60 s; 0, the default, is not listening) it opens its
LoRa receiver for one short window per interval, on the wake channel of its
region (next section), and sleeps in between. To reach it, a receiver sends a
**train**: wake frames back to back for a little longer than that interval,
so that the collar's next window falls on one of them. A frame names up to
four collars. The collars it names stay up for what follows the train; every
other collar is asleep again about a frame later.

```
[0]      u8   0x57
[1]      u8   flags        bit 0 MORE: the tag list continues in the alternating frame
                           bit 1 LONG: sent at the long-range setting (for the record)
                           bit 2 ROLL: a roll call follows the train; the frame has no tags
                           bits 3..7 = 0: a collar ignores a frame with any of them set
[2..3]   u16  time left    10 ms units, from the END of this frame to the END of the
                           train's last frame; 0 in the last frame
[4]      u8   k            number of tags, 1..4 (0 with ROLL, and only then)
[5..]    k x u16  tags     one per collar called
frame length 5 + 2k = 5..13 bytes
```

- **Tags.** `tag(uid) = fmix32(uid ^ 0x57414B45) & 0xFFFF`, where `0x57414B45`
  is ASCII `WAKE` and fmix32 is MurmurHash3's 32-bit finalizer, all in 32
  bits:

  ```
  x ^= x >> 16;  x *= 0x85EBCA6B;  x ^= x >> 13;  x *= 0xC2B2AE35;  x ^= x >> 16
  ```

  Two bytes instead of four per collar keep the frame, and with it every
  collar's listen window, short. Two collars share a tag once in 65,536: the
  other one then stays up for nothing, because what follows names the whole
  uid. A tag of 0 is a tag like any other.
- **Not authenticated.** The frame is cleartext and anyone can send one. All
  it can do is make a collar listen once a second for the next minute; what
  makes a collar act is the signed command or the signed roll call that
  follows.
- **The train.** Frames back to back, at most 5 ms between the end of one and
  the start of the next, for at least `1.03 x I + W + frame`: `I` is the
  listening interval of the collars called, `W` and `frame` are in "Timing"
  below, and the 3 % covers the two clocks. `time left` counts down to 0 in
  the last frame, so a collar that caught any one frame knows `T0`, the end
  of the train: the end of the frame it caught plus that frame's time left.
- **Up to 8 collars a train.** With more than four, the frames alternate
  between two tag lists and every frame carries MORE. A collar that does not
  find its tag in a frame with MORE reads one more frame before it gives up.
- **Refused frames.** A collar acts on nothing but a frame of 5..13 bytes
  that starts `0x57`, has no reserved flag set, at most 4 tags and exactly
  `5 + 2k` bytes; without ROLL at least one tag; with ROLL no tag and no
  MORE. The `wake_frames` vectors hold one frame for each of these.
- **After the train.** A called collar receives from `T0 - 10 ms`. The
  receiver sends its INTENT, the frame that opens a command window
  (`DESIGN_finder_two_way.md` in the collar firmware repository), at
  `T0 + 30 ms` with echo 0, and the collar waits `intent_wait` for it. Echo 0
  means the commands that follow are pre-signed ones (`0x44` above, with a
  validity window). A collar that was called and hears no INTENT listens
  once a second (every 2 s at long range) for 60 s, so the receiver can reach
  it again with a train of a second or two; after the first signed command it
  accepts, it keeps that pace for 5 minutes after the last accepted command,
  15 minutes at most. After a train with ROLL every collar that caught it
  waits for the roll call instead, from `T0 - 10 ms` for
  `2 x toa(29, 8) + 150 ms`.

Vectors: `wake_tags` and `wake_frames` in `vectors.json`.

### The wake channel

A wake does not use the direct radio's own frequency and spreading factor.
Each region has one wake channel, held in the firmware of the collar and of
the receiver, and picked by the direct radio's region setting
(`LoRaConfig.region`, a `DirectRegion` in `ble.proto`):

| Region | `DirectRegion` | Frequency | Bandwidth | SF standard | SF long range | Power cap |
|---|---|---|---|---|---|---|
| US915 (US and Canada) | 1 | 919.000 MHz | 500 kHz | 9 | 12 | 22 dBm |
| EU868 (EU) | 2 | 869.525 MHz | 125 kHz | 7 | 10 | 22 dBm |
| AU915 (Australia) | 3 | 919.000 MHz | 500 kHz | 9 | 12 | 22 dBm |

`DirectRegion` 0 is AUTO: the LoRaWAN region when LoRaWAN is configured,
otherwise from the direct radio's frequency (863 to 870 MHz is EU868, 902 to
928 MHz is US915, never AU915). Anything else is no region, and a collar with
no region does not listen. The numbers are not those of the LoRaWAN
region enum (`RadioRegion`: US915 0, AU915 1, EU868 2). "Long range" is a
setting of its own (`LoRaConfig.wake_long_range`), the same at both ends.

Every frame on the wake channel is LoRa at coding rate 4/5 with an explicit
header, CRC on, IQ normal and **sync word 0x57**. Wake frames have a
**12-symbol preamble**, every other frame 8 (a receiver configured for 12
takes both). Transmit power is the device's direct-radio power, held to the
cap. Everything of a call happens there, at the wake spreading factor: the
trains, the INTENT, the signed commands and their acknowledgements, the
reports a command asks for, the roll call and the beacons that answer it.

### Timing

Both ends compute these from the wake channel's spreading factor and
bandwidth, the same way:

```
Ts          = 2^SF / BW                                  one symbol
toa(n, p)   = (p + 4.25 + 8 + max(ceil((8n - 4 SF + 44) / (4 (SF - 2 DE))) x 5, 0)) x Ts
              an n-byte frame with a p-symbol preamble; DE = 1 when Ts > 16 ms, else 0
frame       = toa(13, 12)                                one full wake frame
tail        = toa(13, 8) - 8 Ts                          a wake frame after its preamble
W           = tail + 16 Ts + 7 ms                        the collar's listen window
cap         = 1.5 x frame + 20 ms                        how long one detection may hold the collar
train       >= 1.03 x I + W + frame
intent_wait = 2 x toa(14, 8) + 150 ms                    from T0 - 10 ms
cmd_window  = toa(255, 8) + 300 ms                       the command window after a frame
```

`W` is what guarantees the catch. A detection needs 8 symbols of one frame's
12-symbol preamble. A window that opens when the frame on air has just under
8 of them left waits out the rest of that frame (those symbols and its
tail), the gap (5 ms at most) and 8 symbols of the next preamble:
`tail + 16 Ts + 5 ms`, and 2 ms are kept over. `cap` bounds what anything
that looks like a preamble can cost a collar: no whole wake frame within it,
and the collar is listening again.

| Setting | Ts | frame | W | cap | intent_wait | A roll-call slot, least / default |
|---|---|---|---|---|---|---|
| US915, AU915 standard: SF9 at 500 kHz | 1.024 ms | 45.3 ms | 56.4 ms | 88 ms | 232.4 ms | 62 / 67 ms |
| EU868 standard: SF7 at 125 kHz | 1.024 ms | 50.4 ms | 61.5 ms | 96 ms | 242.7 ms | 77 / 82 ms |
| US915, AU915 long range: SF12 at 500 kHz | 8.192 ms | 321.5 ms | 361.3 ms | 502 ms | 727.5 ms | 376 / 381 ms |
| EU868 long range: SF10 at 125 kHz | 8.192 ms | 321.5 ms | 361.3 ms | 502 ms | 727.5 ms | 458 / 463 ms |

| Constant | Value |
|---|---|
| Listening interval `I` | 0 = not listening; configurators offer 10, 30 and 60 s; a collar holds any other non-zero value to 5..120 s |
| Slow-down | a collar whose false wakes used up its budget for the clock hour listens at 2 x, at most 4 x, its interval until the hour ends; it never stops |
| Interval while called | 1 s at the standard setting, 2 s at long range |
| Called, no signed command yet | the collar keeps that pace for 60 s |
| Call window | 300 s after the last accepted signed command, 900 s after the first at most |
| The receiver's first INTENT, or its roll call | `T0 + 30 ms` |
| A train for a collar that is called or in its call window | `1.03 x 1 s` (2 s at long range) `+ W + frame` |
| No answer | the same train once more, then one of four times the length |

The reference codec works in whole microseconds (every value above is one),
so an integer implementation gets the vectors' numbers exactly. Vectors:
`wake_timing` in `vectors.json`, with the trains for 1, 2, 5, 10, 30, 60 and
120 s.

### Roll call (0x43), 29 bytes

A train reaches the collars a receiver has named. To find the collars it has
no name for, every collar in range has to answer, and that cannot be open to
anyone: "everybody answer" would be a locator for whoever sends it. So the
roll call is sealed under a key that comes from the owner's command master,
which never leaves the server: one **wake key** for all the collars of a
**group**. A group is the owner's account; its number is the account's
number on the server.

```
[0]       u8   0x43
[1..4]    u32  group        cleartext: key lookup
[5..8]    u32  counter      cleartext: [31:24] the wake key's generation,
                            [23:0] a sequence that only rises, per group
[9..20]   12 B ciphertext   of valid_from u32 || valid_to u32 || slots u8 ||
                            slot_ms u16 || flags u8 (0)
[21..28]  8 B  tag
```

AES-128-CCM as for the v2 frame (L = 2, M = 8), with **AAD** = the nine
cleartext bytes `[0..8]` and **nonce** = `group_le32 || ctr_le32 || 0x03 ||
00 00 00 00`: the group stands where a beacon has the uid, and `0x03` is the
roll call's direction byte (`0x00` beacon and report, `0x01` command, `0x02`
its acknowledgement).

A receiver sends the roll call once, at `T0 + 30 ms` of a train whose frames
carry ROLL, and then listens for `300 ms + slots x slot_ms + 200 ms` after
sending it. It does not sign it: the server signs roll calls ahead (a
two-week window, 32 slots), the receiver carries them, and it sends at most
one a minute.

A collar answers when all of this holds, checked in this order:

1. the frame is 29 bytes and starts `0x43`;
2. the collar holds a wake key;
3. `group` is that key's group;
4. the counter's generation is that key's;
5. the counter is above the last one the collar accepted (it keeps that
   across resets, next to its command counter);
6. the tag verifies;
7. `flags` is 0;
8. the collar's clock is valid,
9. and inside `[valid_from, valid_to]`;
10. `slots` is 1..64;
11. `slot_ms` is at least `toa(30, 8) + 5 ms` at the collar's wake setting;
12. it has not answered a roll call in the last 60 s.

Then it sends **one v2 beacon (`0x4D`)** under its beacon key, starting

```
300 ms + (fmix32(uid ^ 0x57414B45 ^ counter) % slots) x slot_ms
```

after the end of the roll call, and goes back to listening. The 300 ms are
the collar's time to work: it seals its beacon after it has accepted the
roll call, not before (checking the roll call and sealing take it about
0.2 s), so a train with ROLL that brings no valid roll call spends none of
its beacon counter. A collar with a wake key and no beacon key sends
nothing. The slots spread the group's collars so their answers do not all
collide, and a new counter deals them again; `slot_ms` is the answer's
airtime with a margin, by default `ceil(toa(30, 8)) + 10 ms`. A roll call
that is refused changes nothing and does not use its counter up. Whoever is
nearby learns from a roll call only that collars of the group answered: the
answers are sealed.

Vectors: `roll_calls` in `vectors.json`: `keys` (the derivation), `frames`
(seal and open), `slots` (who answers where) and `checks` (the collar's rule,
one refusal for each of the twelve points).

## Keys

Each collar holds one 16-byte **device key**. Owners hold a 16-byte **beacon
master** from which every device key of their fleet derives:

```
dev_key = AES-CMAC(master, label || uid_le32 || gen)      RFC 4493; a 17-byte input
label   = "CID-LORA-BCN"                                   12 ASCII bytes, no terminator
uid     = the frame's cleartext uid, little-endian
gen     = the frame's cleartext ctr >> 24
```

So a receiver holding only the master can open any frame of the fleet from
the cleartext header alone: read `uid` and `gen`, derive, decrypt. A receiver
given a single device key (a recovery team) opens that collar's frames of that
generation only. Capturing a collar yields that one device key and nothing
else.

A second label, `"CID-LORA-CMD"`, derives a separate key family from a
separate master for the reserved command channel. A beacon key never
authenticates a command frame, and a command key is never given out.

A third label, `"CID-LORA-WAK"`, derives the **wake key** of a roll call,
from the owner's command master. It is one key per group and generation, not
per collar, so the group stands where the uid does:

```
wake_key = AES-CMAC(command master, "CID-LORA-WAK" || group_le32 || gen)      a 17-byte input
group    = the roll call's cleartext group, little-endian
gen      = the roll call's cleartext counter >> 24
```

Every collar of the group holds the same wake key (installed over Bluetooth,
`BEACON_KEY_SLOT_WAKE` in `downlink.proto`), so a collar that is opened gives
away the means to make its owner's other collars answer a roll call once
with a sealed beacon, and nothing more: it opens no beacon and signs no
command. A new generation replaces the key on every collar of the group.

**Key check value**: `kcv = AES-128(key, sixteen zero bytes)[0..2]`, three
bytes that identify a key without revealing it. It is what provisioning tools
display and log.

## Vectors (`vectors.json`)

Frozen at `"version": 1`; a change is a new format version, never a rewrite.
A new frame kind adds a section and leaves every earlier entry as it was:
`reports` was added that way (2026-09-30), then `commands` and
`command_acks` (2026-11-11) and the four wake sections (2026-11-13). Hex is
lower-case. Sections:

| Key | Count | Contents |
|---|---|---|
| `aes128` | 1 | FIPS-197 appendix C.1 |
| `cmac` | 4 | RFC 4493 examples 1-4 |
| `ccm` | 24 | RFC 3610 packet vectors 1-24 (1-6 and 13-18 are M=8 like the beacon; 7-12 and 19-24 are M=10) |
| `kdf` | 8 | master, purpose, uid, gen, the 17-byte input, `dev_key`, `kcv` |
| `frames` | 14 | master, uid, gen, seq, ctr, body fields, `dev_key`, `kcv`, nonce, AAD, body, ciphertext, tag, the 30-byte frame |
| `v1` | 3 | uid, body fields, the 18-byte frame |
| `reports` | 3 | sealed reports (0x52): master, uid, gen, seq, ctr, `dev_key`, `kcv`, nonce, AAD, payload, ciphertext, tag, the frame and its length: a short report (49 B), a one-byte payload (18 B, the shortest frame) and a 238-byte payload (255 B, the longest, at seq 0xFFFFFE of gen 255) |
| `commands` | 3 | signed handheld commands (0x44): uid, gen, seq, ctr, `cmd_key`, nonce, AAD, echo, validity, the `DownlinkPacket` bytes, the frame |
| `command_acks` | 2 | acknowledgements (0x4B): the command's uid and counter, result, command, detail, rssi, snr, the 25-byte frame |
| `wake_tags` | 15 | uid, the mixed 32 bits, the tag: the edges (uid 0, 0xFFFFFFFF, a tag of 0), the eight collars of the train vectors, and two collars with one tag |
| `wake_frames` | 25 | 12 wake frames (0x57) with `ok` true: collars called, tags, flags, time left, the frame, and what the frame means to five collars (`called`, `more`, `not_called`, `roll`); 13 with `ok` false and the reason a collar ignores them (`refusal`) |
| `wake_timing` | 6 parts | `constants`; `regions` (the wake table); `region_resolve` (19 cases of setting, LoRaWAN region and frequency); `settings` (the four wake settings: every time above in microseconds and to 0.1 ms, airtimes, and the trains for seven intervals); `interval_clamp`; `time_left` |
| `roll_calls` | 4 parts | `keys` (6 wake keys: master, group, gen, input, key, `kcv`); `frames` (5 roll calls: every field, nonce, AAD, body, ciphertext, tag, frame); `slots` (30 slot choices); `checks` (26 runs of the collar's rule: 7 answered, 19 refused, with the reason) |

A conforming implementation opens every `frames` entry to its fields with
`dev_key`, derives the same `dev_key` from `master`, and, when re-sealing the
same fields under the same uid and ctr, produces the same 30 bytes; likewise
every `reports` entry to its payload, and back to the same frame. Every
single-bit change to a frame must fail to open. The report payloads are
synthetic bytes, not real reports.

For a wake, a conforming implementation gives every `wake_tags` tag, builds
and parses every `ok` entry of `wake_frames` to the same bytes and fields
with the same verdict for each collar listed, refuses every other entry,
computes the microsecond values of `wake_timing.settings` exactly, resolves
every `region_resolve` case, seals and opens every `roll_calls.frames` entry
byte for byte, picks the slot of every `roll_calls.slots` entry and answers
or refuses every `roll_calls.checks` entry as stated (the order of the
checks only shows when two of them fail at once, which no vector does).

## Command line

```
python3 beacon_v2.py open   --key    <dev_key hex> <30 bytes hex>
python3 beacon_v2.py open   --master <master hex>  <30 bytes hex>
python3 beacon_v2.py derive --master <master hex> --uid 0x7E57C0DE --gen 1
python3 beacon_v2.py kcv    --key <hex>
python3 beacon_v2.py v1     <18 bytes hex>
python3 beacon_v2.py report-peek <frame hex>
python3 beacon_v2.py report-open --key    <dev_key hex> <frame hex>
python3 beacon_v2.py report-open --master <master hex>  <frame hex>
python3 beacon_v2.py report-seal --key <dev_key hex> --uid 0x7E570001 --ctr 0x01000001 <payload hex>
python3 beacon_v2.py wake-tag 0x7E570021 0x7E570022
python3 beacon_v2.py wake-parse <frame hex> [--uid 0x7E570021]
python3 beacon_v2.py wake-timing --region US915 [--long] [--interval 30]
python3 beacon_v2.py roll-open --key    <wake key hex>       <29 bytes hex>
python3 beacon_v2.py roll-open --master <command master hex> <29 bytes hex>
python3 beacon_v2.py derive --master <command master hex> --purpose wake --uid <group> --gen 1
```

Output is one JSON object; a frame that does not authenticate prints
`{"error": "authentication failed", ...}` and exits 1, revealing nothing.
`report-open` prints the payload as hex: the report's protobuf bytes.

## Notes for receiver authors

- A receiver without a key still gets `uid`, `ctr`, RSSI and SNR from a v2
  frame: identification and RSSI homing work; only the position is withheld.
- The 30-byte frame is about 20 ms longer on air than v1 at SF7/BW125
  (71.9 ms against 51.5 ms) and about 120 ms longer at SF10 (453 ms against
  330 ms).
- A sealed report is 17 bytes longer on air than the same report in the
  clear.
- The reference code is written for clarity, not speed or side-channel
  resistance. Use a maintained CCM library where one exists.
