# What's on the card, v1

Added 2026-11-16 (collarID_thread `docs/CONTRACT_files_and_spotter_gaps.md`
Part 3). A person far from a collar learns which days and hours its card
holds sound and movement data for, and how much, before asking for files over
Bluetooth. The answer is a summary, never a file list. Normative; the
reference codec is `card_summary.py`, the frozen vectors
`../test_vectors/card_summary_v1.json` (`make_card_summary_vectors.py`,
`--check`), the tests `test_card_summary.py`.

## The request

`CMD_CARD_SUMMARY = 30` with `DownlinkPacket.card_summary = 18`:

    message CardSummaryRequest { uint32 from_epoch = 1; uint32 days = 2; }

- `days`: 0 = 30, otherwise held to 1..62.
- `from_epoch`: any time on the first UTC day wanted. 0 = the `days` days
  that end on the collar's UTC today (today and the days before it).
- Over the signed direct radio only. Over LoRaWAN the collar does not run it;
  over the Bluetooth settings tunnel it is refused (`CfgEchoPacket.cmd_result`
  7).

## The acknowledgement

- 1 accepted, detail = the reply frames that follow, 1..4.
- 12 refused (`CMD_ACK_BLE_REFUSED`, the card refusals), detail 3: no
  readable card; detail 7: the card's day index is still being built (a card
  holding data from before this firmware is indexed once, in the
  background): ask again later.

## The reply frames

Up to 4, back to back after the ACK, each a `MessagePacket` with a header
(collar id, the report counter as it stands, the time, the build) and
`card_summary = 12` (`CardSummary`, a sibling field, not a `payload` member),
sealed as a report when the collar holds a beacon key. They take no packet
index and stay out of every ring, as track frames (`CMD_SEND_TRACK`) do.

    message CardSummary {
      uint32 first_day = 1;  // UTC midnight of the first day in `days`
      bytes  days      = 2;  // 10 B per day, consecutive days from first_day
      uint32 part      = 3;  // 1-based frame number of this answer
      uint32 parts     = 4;  // frames in this answer
      uint32 log_kib   = 5;  // /METADATA.CSV, KiB rounded up (part 1 only)
      uint32 as_of     = 6;  // collar UTC when the summary was made
    }

An n-day answer is split into frames of 16 days (the last one shorter):
`ceil(n / 16)` frames, so 62 days take 4. Frame k's `first_day` is the
answer's first day + 16 (k - 1) days. The largest frame is 214 B before the
seal (header 26 B at its largest, field 12 188 B), inside a sealed report's
238 B.

## A day record, 10 bytes, little-endian

| bytes | what |
|---|---|
| 0..2 | sound hours, u24: bit h set = some sound on the card covers part of UTC hour h of that day |
| 3..4 | sound MiB, u16: the takes that start that day, rounded up; 65535 = that much or more |
| 5..7 | movement hours, u24, as sound (accelerometer files) |
| 8..9 | movement MiB, u16, as sound |

A day with nothing is all zeros and is kept, so the days stay consecutive.

**Hours.** A recording covers the hours from its start (its file name) to its
close, both inclusive, cut at each midnight: an hourly take from 19:30 marks
19 and 20; one from 23:30 marks 23 of its day and 0 of the next. A span longer
than a day and an hour (a clock that jumped while a file was open) is held to
that (`span_hours`). Bit h is set for hour h whatever share of it is covered,
so a client shading hours shows where sound is, not how much.

**Sizes.** The bytes of the recordings that start that day (the files in that
day's folder), each counted in KiB rounded up, summed, then shown in MiB
rounded up. Time-anchor sidecars (`*.anc.csv`, `mic.anc.csv`) are left out.
A download of a stretch is about the sum of its days.

**What counts.** Sound: the microphone's takes (`.flac` or `.wav`) under
`/audio/` and the recording fallback folders. Movement: the accelerometer's
`.wav` files under `/accelerometer/` and its fallback folder. The
magnetometer is not summarised in v1.
