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
