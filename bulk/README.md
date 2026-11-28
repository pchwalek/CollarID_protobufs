# Bluetooth file transfer, protocol v1 ("CIDB")

A collar serves the files on its card, read-only, to a phone (later the
Handheld Receiver) over Bluetooth. The window opens two ways: a magnet swipe
(the collar's usual Bluetooth session, no key), or the radio command
`CMD_BLE_WINDOW` (`downlink.proto`, signed over the direct radio or sent over
LoRaWAN), which carries the window's key. Design, power, throughput and
failure cases: `collarID_thread/docs/DESIGN_ble_bulk_transfer.md`.

This file is normative. `bulk_v1.py` is the reference codec (with a model of
the collar, `CollarModel`, and a phone, `Client`); `vectors.json`, generated
from it by `make_vectors.py`, is frozen: the collar firmware replays it byte
for byte. Standard library only (AES and CMAC from `../beacon/beacon_v2.py`).

```bash
cd bulk && python3 -m unittest            # reference tests and vectors current
python3 make_vectors.py --check
```

## Transport

- Characteristic **BulkChar** `1a17b2cd-7314-493d-a4b5-32a2d53e6fdc` on the
  CollarID service (`...6fd7`). Write (with response) and notify. Absent on
  older radios and on the first-generation collar: a client that does not find
  it offers no files.
- **Requests**: one request per ATT write, at most 244 bytes, never a long
  (prepared) write: negotiate an MTU of at least the request plus 3. One
  request at a time from one connection (the first to write BulkChar owns it
  until it disconnects).
- **Answers**: a byte stream of frames, carried by notifications on BulkChar.
  The radio cuts the stream anywhere; reassemble by the frame header. Turn
  notifications on before the first request.
- A refused write answers an ATT error:

| ATT error | Meaning |
|---|---|
| 0x03 | no file service now (the window is closed, or this session has none) |
| 0x0D | length 0 or over 244 |
| 0x80 | the collar has not taken the previous request yet: retry shortly |
| 0x81 | another phone holds the file service |

## Frames

Both directions:

    [0]      op     u8
    [1]      seq    u8      the client's choice; every frame of the answer carries it back
    [2..3]   len    u16 LE  payload bytes
    [4..]    payload

In a keyed window, after AUTH, every request except HELLO and AUTH carries 8
more bytes:

    mac = CMAC(K_s, "CIDB-Q" || ctr_le32 || bytes [0 .. 4+len))[0:8]

`ctr` counts the MAC'd requests the collar has accepted since AUTH, from 0. A
request whose MAC is wrong is answered `BAD_MAC` and does not move the
counter, so a retry of a request that got no answer uses the same counter.

An answer's op is the request's op | 0x80. Its payload starts with a result
byte. Errors found before the op is looked at (length, MAC, authentication,
busy, unknown op, a payload too short for its fixed fields) answer with the
result byte alone (`len` 1). Otherwise the op's own answer comes at its full
length, with its own result (a missing file, a bad path).

## Ops

| op | request payload | answer payload |
|---|---|---|
| 0x01 HELLO | client nonce, 8 B | result, version 1, flags (bit 0 auth required, bit 1 authenticated), uid u32, challenge 16 B, window seconds left u16, data bytes per DATA frame u16 (27 B) |
| 0x02 AUTH | tag 16 B | result, proof 8 B (zeros unless OK) (9 B) |
| 0x03 LIST | cookie u32, path | result, next cookie u32 (0 = the listing ended), count u8, entries (at most 1024 B in all) |
| 0x04 STAT | path | result, attr u8, size u64, mtime u32 (14 B) |
| 0x05 READ | offset u64, length u32 (0 = to the end), path | 0..n DATA frames, then result, offset u64, count u32, crc32 u32 (17 B) |
| 0x06 CANCEL | none | result |
| 0x07 BYE | none | result; a window opened by radio command closes about 1.5 s later (a magnet session goes on) |
| 0x08 INFO | none | result, battery_pct u8, battery_mv u16, floor_pct u8, window_left_s u32 (9 B; added 2026-11-16, below) |
| 0x09 IMG_BEGIN | image length u32, flags u8 (bit 0 restart) | result, next u32 (5 B; added 2026-11-26, "An image towards the collar") |
| 0x0A IMG_DATA | offset u32, 1..228 image bytes | result, next u32 (5 B) |
| 0x0B IMG_END | none | result, next u32 (5 B) |

- **DATA** (op 0xC5, the READ's seq): offset u64, then the bytes (at most the
  HELLO's "data bytes per frame": 2048, or 512 while the collar is busy).
  Offsets run without gaps from the READ's offset. A DATA frame for a range
  already received may come again (the collar resends a blob whose arrival
  at its radio it could not confirm): ignore it.
- **READ's answer** ends every READ: `count` bytes were sent, `crc32` (IEEE,
  zlib's) is over exactly those bytes. A READ is bounded by the file's size
  when it started (a file still growing is read as it was). A READ past the
  end answers OK with count 0. To resume, READ again from the first byte you
  do not have. A whole file is complete when its ranges are each checked and
  their sum is the size STAT gave.
- **CANCEL** during a READ: the READ ends with `CANCELLED` (its count and CRC
  are right for what was sent), then CANCEL's own answer. Without a READ
  running: OK.
- While a READ runs, LIST, STAT and READ answer `BUSY`; HELLO ends the READ
  (no answer for it) and starts over.
- **INFO** (2026-11-16, additive): the collar's battery and how long the
  window stays open, for a phone to show while it downloads. Authenticated
  like the other requests (in a keyed window: after AUTH, with a MAC). No
  card work, so it is answered at once, even while a READ runs (its answer
  then comes between the READ's frames, with its own seq; the READ goes on).
  `battery_pct` 0..100 and `battery_mv` are the collar's own average of
  readings taken every 15 s between frames (a reading under the transfer's
  load sags and recovers; the average moves a quarter of the way to each new
  reading), 0 and 0 before the first reading. `floor_pct` is the level at
  which the window closes by itself (the collar's resume level, default 20).
  `window_left_s` is the seconds until the window closes by its own rules
  now (below); in a magnet session, the session's 300 s. A non-empty payload
  answers `BAD_REQUEST` alone. A collar that predates INFO answers
  `UNKNOWN_OP` (12) alone: hide the indicator. Clients ask about every 30 s
  and between files. Vectors: the `info` transcript (`keyed` and `open` are
  unchanged).
- **Window time** (a window opened by radio command): the minutes asked
  (0 = 10, held to 1..30) from the open, or 2 min past the last request or
  frame when that is later, never more than **2 hours** from the open (since
  2026-11-16; was 1 hour); and when the phone leaves without BYE and no
  phone connects within 2 min, it closes 2 min after the phone left (never
  later than it would have anyway). A window no phone has connected to yet
  keeps its full time. BYE closes it about 1.5 s after its answer. Below the
  collar's resume battery level it closes at the next minute's check.
  `bulk_v1.window_close_s` and the `windows` vectors are the rule.
- **Entries**: attr u8 (FAT bits: 0x10 directory, 0x01 read-only, 0x02
  hidden, 0x04 system, 0x20 archive), size u64 (0 for a directory), mtime u32
  (UTC seconds, 0 unknown; FAT keeps 2 s), name length u8, name (ASCII). In
  the card's directory order; no "." or "..". Page with the cookie the answer
  gives.
- **Paths**: absolute, 1..127 bytes of printable ASCII without `\`, no empty,
  `.` or `..` element, no trailing `/` except `/` itself.

Results: 0 OK, 1 BAD_REQUEST, 2 AUTH_REQUIRED, 3 BAD_MAC, 4 AUTH_FAILED,
5 NOT_FOUND, 6 IO_ERROR, 7 BUSY, 8 BAD_PATH, 9 CANCELLED, 10 NOT_A_DIR,
11 NO_CARD, 12 UNKNOWN_OP, 13 NOT_NEEDED (AUTH where no key is needed),
14 IS_A_DIR.
The IMG requests add (2026-11-26): 15 IMG_NOT_BEGUN, 16 IMG_OFFSET,
17 IMG_LENGTH, 18 IMG_FLASH, 19 IMG_HASH, 20 IMG_SIGNATURE, 21 IMG_BATTERY,
22 IMG_BUILD, 23 IMG_VECTORS, 24 IMG_TRIES, 25 IMG_DONE.

## An image towards the collar

Added 2026-11-26 (collarID_thread `docs/DESIGN_remote_update.md`). A window
opened by a `CMD_BLE_WINDOW` whose `ble_window.kinds` has bit 3 (8,
`BLE_FILES_KIND_UPDATE`) also takes one image of the collar's main software.
The command names it: `image_len`, `image_sha256`, `image_build`,
`image_sig` (`downlink.proto`). The key holder can deliver that image or
nothing: the collar installs what it stored only if its SHA-256 is the
command's, it starts like an image (a stack pointer in RAM, a reset vector in
flash), its own `FWBUILD:<n>:` stamp is `image_build`, and the release
signature verifies (ECDSA P-256 under the public key compiled into the
collar, over SHA-256(image | image_build as 4 bytes little-endian);
`image_sig` is r|s, 32 bytes each, big-endian).

In any other window (a magnet session, a window without bit 3, an older
collar) the three requests answer `UNKNOWN_OP` (12) alone, as every op the
collar does not know: nothing changes.

Requests and answers are framed, authenticated and counted exactly as the
others (HELLO, AUTH, then the MAC on every request). All three answers are
`result u8, next u32 LE`: `next` is the number of image bytes the collar
holds, which is the offset the next IMG_DATA must carry. Errors found before
the op is looked at (length, MAC, authentication, `BUSY` while a READ runs,
a payload of the wrong size: `BAD_REQUEST`) answer the result alone.

- **IMG_BEGIN** `image_len u32 LE, flags u8` (5 B; flags bits 1..7 zero).
  `image_len` must be the command's (else `IMG_LENGTH`). With no image begun
  the collar erases the spare half of its flash and answers OK, next 0. With
  one begun it answers OK and `next` as it stands (a client that reconnects
  goes on from there; the image survives a disconnection, not the window),
  unless flags bit 0 (restart) is set: then what is stored is discarded and
  the image begins at 0. A window erases at most 3 times; an IMG_BEGIN that
  would need a fourth answers `IMG_TRIES` and changes nothing (what is
  stored stays and may still be completed; a new command opens a new
  window). `IMG_FLASH`: the erase failed.
- **IMG_DATA** `offset u32 LE, bytes` (1..228 bytes: a 244 B request less the
  header 4, the offset 4 and the MAC 8). `offset` must equal `next`, else
  `IMG_OFFSET` and `next` says where the collar is (nothing is written: a
  piece sent twice, or one whose answer was lost, is told apart this way; go
  on from `next`). Bytes past `image_len`: `IMG_LENGTH`, nothing written.
  OK: stored and read back, `next` advanced. `IMG_FLASH`: a write failed, the
  image is discarded (IMG_BEGIN again). One request at a time; the answer to
  each is the go-ahead for the next.
- **IMG_END** (no payload). Before the last byte: `IMG_LENGTH`, the image
  stays and may be completed. Otherwise the collar checks the stored image,
  in this order: `IMG_HASH`, `IMG_VECTORS`, `IMG_BUILD`, `IMG_SIGNATURE`. Any of them discards the image (`next` 0);
  the collar's running software is untouched and the window goes on. OK
  (`next` = `image_len`): the image is verified. About 1.5 s after the
  answer has gone the collar ends its recordings, saves its log, swaps to
  the new image and restarts; the connection drops. The answer takes as long
  as hashing the whole image on the collar: wait **180 s** for it (other
  answers: the usual few seconds).
- `IMG_BATTERY` (21) is reserved and never sent: the battery is judged when
  the command arrives (50 %, refusal 12) and, during the window, only by
  the window's own floor. A level that sags under the transfer does not
  cost a finished image.
- **A begun image does not wait.** It is discarded 60 s after the last
  IMG_BEGIN or IMG_DATA the collar took (a refused request does not count),
  and 30 min after the IMG_BEGIN that erased, whatever arrives; the
  requests then answer `IMG_NOT_BEGUN`, and IMG_BEGIN starts again while
  tries last. Send the pieces without pausing; while an image is begun the
  collar holds off its own sleep.
- **A release command wins.** If the collar is ordered to release
  (drop-off) while an update window is open, the window closes and its
  image, begun or verified, is discarded; the connection drops. Order the
  update again later.
- After a verified image every IMG request answers `IMG_DONE` (25).
- `IMG_NOT_BEGUN` (15): IMG_DATA or IMG_END with no image begun, or after
  one was discarded.
- The window's own rules hold throughout: it stays open while requests keep
  coming (2 min past the last, two hours at most), and closes at the
  collar's resume battery level. A window that closes, or a new command that
  replaces it, discards an unfinished image.
- That the update took is not answered here: the collar's next report
  carries the new build (`fw_build`). A new image is kept only if, on its
  first start, the collar's LoRa radio and its Bluetooth radio both answer;
  otherwise the collar goes back to the software it had, by itself.

Sequence: HELLO, AUTH, IMG_BEGIN, IMG_DATA from `next` in pieces of up to
228 B until `next` = `image_len`, IMG_END. `bulk_v1.Client.send_image` is
the reference; the `image` transcript in `vectors.json` has every answer
above but `IMG_FLASH`, which needs a collar's hardware, with a stand-in
signature its collar accepts.

The command is refused (ACK result 12, no window) with detail 8 `image_len`
outside 1024..2048000, 9 `image_sha256` or `image_sig` absent, 10
`image_build` not above the collar's own build, 11 the collar has no release
public key, 12 battery below 50 %, 13 a window is open already, 14 the
command did not come in a signed direct-radio frame (`../beacon/README.md`).
Detail 14 is checked first: an update is ordered only by a signed
direct-radio command, never over LoRaWAN, whose network server could
otherwise open an update window with a key of its own choosing.

## What a window serves

Added 2026-11-16 (collarID_thread `docs/CONTRACT_files_and_spotter_gaps.md`
Part 1; the collar's rule is `Core/Src/ble_bulk_scope.c`, host-tested). A
magnet session, and a window whose `ble_window.kinds` is 0 or absent, serve
the whole card, as before. A window opened with `kinds` != 0 serves only:

| kind | `kinds` bit | what |
|---|---|---|
| card log | 0 (1) | `/METADATA.CSV`. The collar keeps one log file and does not rotate it. |
| movement data | 1 (2) | everything under `/accelerometer/` (`YYYY/MM/DD/<take>.wav` and each one's time-anchor sidecar `<take>.anc.csv`) and under `/accelerometer_recovery/`, where a card that cannot make the dated folders records |
| sound | 2 (4) | the takes that overlap `[audio_from, audio_to]`: `/audio/YYYY/MM/DD/<take>.flac` or `.wav` whose start time lies in `[audio_from - 3600, audio_to]`; `mic.anc.csv` (the microphone's time anchors) in the day folders of the UTC days that window touches; in `/audio_recovery/`, the takes in it and its `mic.anc.csv`; in the root, `<take>.flac` in it |
| sound log | 4 (16) | added 2026-11-27 (collarID_thread `docs/DESIGN_sound_log.md`): the sound logs of those same takes and no sound: `<take>.lvl` whose `<take>` starts in `[audio_from - 3600, audio_to]`, in `/audio/YYYY/MM/DD/`, in `/audio_recovery/` and in the root. Never a `.flac`, `.wav` or `mic.anc.csv`: ask for bit 2 as well for those |

`<take>` is the take's first sample in UTC, `YYYYYMMMDDDHHHMMMSSS`, with an
optional `_N` the collar adds on a name clash: `2026Y11M16D10H05M00S.flac`,
`2026Y11M16D10H05M00S_2.wav`. A take runs at most 3600 s (continuous
recording starts a new file every hour; a scheduled take is 1 to 60
minutes), so one that starts up to an hour before `audio_from` still holds
sound from the range and is served; one that starts earlier is not. The
day folders follow that widened window: a range starting at 00:30 also
serves the previous day's folder (its 23:30 take) and its `mic.anc.csv`.
Folders on the way: `/` always; `/accelerometer` and
`/accelerometer_recovery` with bit 1; `/audio`, `/audio/YYYY`,
`/audio/YYYY/MM` and `/audio/YYYY/MM/DD` for the years, months and days the
widened window touches, and `/audio_recovery`, with bit 2 or bit 4. Bit 3 is
the update kind (2026-11-26, "An image towards the collar"): it serves no
file. Bits above 4 are reserved (a window with only those, or only bit 3,
serves `/`, empty). (old: "Bits above 3 are reserved", before the sound log.)

A sound log (`<take>.lvl`, the same name as its FLAC take with `.lvl`) is a
48-byte header, then 3 bytes for every FLAC frame of the take in frame
order: the frame's exact size in its low 14 bits (little-endian), a 2-bit
kind (0 coded, 1 shed, 2 zero-filled, 3 short final) above it, and a level
byte `floor(16 log2(1 + sum0)) - 160` from the encoder's order-0 residual
sum. Each frame's byte offset in the FLAC is the running sum of the sizes
from byte 512, so a client reads a moment's bytes with `READ` (offset,
length) in a window with bit 2. The format, its special entries (a run of
frames with no entry, the trailer) and the rules are collarID_thread
`docs/DESIGN_sound_log.md`; a WAV take has no log.

- LIST of a folder shows only what the window serves (the cookie counts
  only those entries, so every page is full but the last).
- LIST, STAT and READ of anything else answer `NOT_FOUND` (5), exactly as
  for a file that is not there. There is no new result: a v1 client needs
  no change, and a client that downloads what LIST offers never meets it.
- In such a window every path element is letters, digits, `_`, `-` and
  `.`, never beginning with `.`: hidden files (a Mac's `._*`) are not
  served, and no spelling FileX would resolve elsewhere (spaces, `~1`
  short names) gets past the rule. An entry whose path would be over 127
  bytes is not listed (it could not be read).
- Not served by any kind: root-level `.wav` and `.anc.csv` files (the
  recording fallback's last rung: the accelerometer, the microphone and the
  magnetometer name their files alike, so their kind cannot be told), and
  everything else on the card (`CONFIG.CSV`, GPS, magnetometer, ...).

The audio range is checked as sent (the hour before `audio_from` does not
count) when the command arrives: `kinds` with bit 2 (or, since 2026-11-27,
bit 4) and `audio_from` or `audio_to` 0, `audio_to <= audio_from`, or
`audio_to - audio_from > 86400` is refused with ACK result 12, detail 6
(`../beacon/README.md`), and no window opens. A command that renews an open
window replaces its key, its minutes and what it serves.

## Authentication

`K_w`, the window key, 16 bytes, is chosen at random by the server for one
`CMD_BLE_WINDOW` and travels inside it (`DownlinkPacket.ble_window.key`,
encrypted in the 0x44 frame or by LoRaWAN). The phone that will connect gets
it from the server with the signed frame. The collar keeps it in RAM for the
window only.

    challenge  the collar's, 16 B, new at every HELLO (never repeats under one K_w)
    cnonce     the client's, 8 B, from HELLO
    in   = uid_le32 || challenge || cnonce
    tag  = CMAC(K_w, "CIDB-AUTH"  || in)          the client sends it in AUTH
    proof= CMAC(K_w, "CIDB-PROOF" || in)[0:8]     the collar answers it: it holds K_w too
    K_s  = CMAC(K_w, "CIDB-SESS"  || in)          the request MACs' key

CMAC is AES-CMAC (RFC 4493); the labels are ASCII without a terminator. A
magnet session has no key: HELLO's flag bit 0 is clear, the challenge is
zeros, AUTH answers `NOT_NEEDED`, and requests carry no MAC.

In v1 the file bytes are not encrypted on the air (see the design document,
"Security"): who may read is decided; what a nearby listener hears is not.
