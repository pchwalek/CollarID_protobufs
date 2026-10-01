# CollarID lost-mode beacon: the wire contract

A collar in lost mode broadcasts a short raw-LoRa frame at a fixed cadence so
that a searcher can find it. This directory is the public specification of
that frame, for anyone building a receiver: the plaintext v1 frame every
collar sends today, the encrypted v2 frame a keyed collar will send, the
sealed report a keyed collar sends in place of its regular plaintext radio
report, the key derivation an owner's receiver needs, a reference
implementation in Python and C, and frozen test vectors.

Where a receiver and this text disagree, one of them has a bug, and the
vectors decide. Everything here is synthetic: no real collar identifier, key or
position appears anywhere in this repository.

## Contents

| File | What it is |
|---|---|
| `beacon_v2.py` | Reference codec and command-line tool (Python 3, standard library only). |
| `c/aead_ccm.[ch]`, `c/beacon_frame.[ch]` | The same codec in C11 over an injected AES block function; byte-identical copies of the collar firmware's files. |
| `vectors.json` | Frozen known-answer vectors (below). |
| `make_vectors.py` | Regenerates `vectors.json` from the codec; `--check` fails if the file is stale. |
| `test_beacon_v2.py` | `python3 -m unittest -v` in this directory. |

## Frames

A receiver dispatches on the first byte and the length. Anything else is not a
beacon (a collar's plaintext radio report, for one: it is a protobuf
`MessagePacket` and always starts `0x0A`).

| Magic | Length | Frame |
|---|---|---|
| `0x4C` (`'L'`) | 18 B | v1, plaintext. What an unkeyed collar sends. Stays decodable forever. |
| `0x4D` (`'M'`) | 30 B | v2, AES-128-CCM. What a keyed collar sends. |
| `0x52` (`'R'`) | 18..255 B | Sealed report: a keyed collar's regular radio report, AES-128-CCM (below). |

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

**Key check value**: `kcv = AES-128(key, sixteen zero bytes)[0..2]`, three
bytes that identify a key without revealing it. It is what provisioning tools
display and log.

## Vectors (`vectors.json`)

Frozen at `"version": 1`; a change is a new format version, never a rewrite.
A new frame kind adds a section and leaves every earlier entry as it was:
`reports` was added that way (2026-09-30). Hex is lower-case. Sections:

| Key | Count | Contents |
|---|---|---|
| `aes128` | 1 | FIPS-197 appendix C.1 |
| `cmac` | 4 | RFC 4493 examples 1-4 |
| `ccm` | 24 | RFC 3610 packet vectors 1-24 (1-6 and 13-18 are M=8 like the beacon; 7-12 and 19-24 are M=10) |
| `kdf` | 8 | master, purpose, uid, gen, the 17-byte input, `dev_key`, `kcv` |
| `frames` | 14 | master, uid, gen, seq, ctr, body fields, `dev_key`, `kcv`, nonce, AAD, body, ciphertext, tag, the 30-byte frame |
| `v1` | 3 | uid, body fields, the 18-byte frame |
| `reports` | 3 | sealed reports (0x52): master, uid, gen, seq, ctr, `dev_key`, `kcv`, nonce, AAD, payload, ciphertext, tag, the frame and its length: a short report (49 B), a one-byte payload (18 B, the shortest frame) and a 238-byte payload (255 B, the longest, at seq 0xFFFFFE of gen 255) |

A conforming implementation opens every `frames` entry to its fields with
`dev_key`, derives the same `dev_key` from `master`, and, when re-sealing the
same fields under the same uid and ctr, produces the same 30 bytes; likewise
every `reports` entry to its payload, and back to the same frame. Every
single-bit change to a frame must fail to open. The report payloads are
synthetic bytes, not real reports.

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
