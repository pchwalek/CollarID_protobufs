/*
 * wake_frame.h — LoRa wake: the wake frame (0x57 'W'), the wake channel of
 * each region, the timing both ends compute, and the roll call (0x43 'C')
 * with its key.
 *
 * Contract: CollarID_protobufs beacon/README.md ("Wake frame", "Roll call"),
 * the reference codec beacon/beacon_v2.py and the vectors beacon/vectors.json
 * (sections wake_tags, wake_frames, wake_timing, roll_calls). The collar
 * firmware and the Handheld Receiver carry byte-identical copies of this file
 * and of wake_frame.c, so the two ends of a wake cannot drift apart.
 *
 * A Handheld Receiver calls sleeping collars with a TRAIN of wake frames,
 * sent back to back on the wake channel for a little longer than the
 * collars' listening interval. A listening collar opens its receiver for one
 * short window per interval and so catches one frame of the train.
 *
 * Wake frame, 5..13 bytes, cleartext, little-endian:
 *   [0]      0x57            magic ('W')
 *   [1]      flags           bit 0 MORE: the tag list continues in the
 *                                  alternating frame (more than 4 collars)
 *                            bit 1 LONG: sent at the long-range setting
 *                                  (for the record; it changes nothing)
 *                            bit 2 ROLL: a roll call follows the train;
 *                                  the frame carries no tags
 *                            bits 3..7 = 0 (a frame with any set is ignored)
 *   [2..3]   u16 time left   10 ms units, from the END of this frame to the
 *                            END of the train's last frame (0 in the last)
 *   [4]      u8  k           number of tags, 1..4 (0 with ROLL, only then)
 *   [5..]    k x u16 tags    tag(uid) = fmix32(uid ^ 'WAKE') & 0xFFFF
 *
 * The frame is unauthenticated: it only says "collars with these tags, stay
 * up for what follows". What follows is an INTENT and signed 0x44 commands
 * (cmd_frame.h), or a roll call.
 *
 * Roll call, 29 bytes: "every collar of this group in range, answer once",
 * sealed with the beacon's construction (AES-128-CCM, L=2, M=8) under the
 * group's WAKE key, which is one key for every collar of a group (the
 * owner's account) and generation:
 *   [0]      0x43                    magic ('C')
 *   [1..4]   group u32               cleartext (key lookup)
 *   [5..8]   counter u32             cleartext; [31:24] generation, [23:0]
 *                                    strictly increasing per group
 *   [9..20]  ciphertext of valid_from u32 || valid_to u32 || slots u8 ||
 *            slot_ms u16 || flags u8 (0)
 *   [21..28] tag
 *   AAD   = bytes [0..8]
 *   nonce = group_le32 || ctr_le32 || 0x03 || 0x00000000
 * A collar that accepts it sends one sealed beacon (0x4D, beacon_frame.h)
 * starting 300 ms + (fmix32(uid ^ 'WAKE' ^ counter) % slots) x slot_ms after
 * the roll call's end. The collar seals that beacon AFTER it has accepted
 * the roll call (checking and sealing take it about 0.2 s, which is what the
 * 300 ms are for), so a ROLL train that brings no valid roll call spends no
 * beacon counter. The receiver listens 300 ms + slots x slot_ms + 200 ms
 * after sending the roll call.
 *
 * Times are whole microseconds in uint32_t: every value here is one, so no
 * float is needed and a port gets the vectors' numbers exactly.
 *
 * Pure C11 over the injected AES of aead_ccm.h: no HAL, no heap, no
 * endianness assumptions (bytes are assembled explicitly).
 */
#ifndef WAKE_FRAME_H
#define WAKE_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "aead_ccm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- the wake frame ------------------------------------------------------ */

#define WAKE_FRAME_MAGIC         0x57u
#define WAKE_FRAME_HDR_LEN       5u
#define WAKE_FRAME_MAX_TAGS      4u
#define WAKE_FRAME_MAX_LEN       (WAKE_FRAME_HDR_LEN + 2u * WAKE_FRAME_MAX_TAGS)   /* 13 */
#define WAKE_FLAG_MORE           0x01u
#define WAKE_FLAG_LONG           0x02u
#define WAKE_FLAG_ROLL           0x04u
#define WAKE_FLAGS_DEFINED       (WAKE_FLAG_MORE | WAKE_FLAG_LONG | WAKE_FLAG_ROLL)
#define WAKE_SALT                0x57414B45u   /* 'WAKE': the tag's salt, and the roll-call slot's */
#define WAKE_TIME_UNIT_MS        10u           /* the time-left field counts 10 ms */
#define WAKE_TIME_LEFT_MAX       0xFFFFu       /* 655.35 s */
#define WAKE_TRAIN_MAX_COLLARS   (2u * WAKE_FRAME_MAX_TAGS)   /* 8: two alternating lists */

typedef struct {
	uint8_t  flags;                       /* WAKE_FLAG_* */
	uint16_t time_left_10ms;
	uint8_t  k;                           /* tags in use, 0..4 */
	uint16_t tags[WAKE_FRAME_MAX_TAGS];
} wake_frame_t;

/* Why a frame is not one a collar acts on, in the order checked (the
 * `refusal` of the wake_frames vectors, in the same order). */
typedef enum {
	WAKE_FRAME_OK             = 0,
	WAKE_FRAME_LENGTH         = 1,   /* not 5..13 bytes                        */
	WAKE_FRAME_BAD_MAGIC      = 2,   /* byte 0 is not 0x57                     */
	WAKE_FRAME_RESERVED_FLAGS = 3,   /* a flag bit 3..7 is set                 */
	WAKE_FRAME_TAG_COUNT      = 4,   /* k above 4                              */
	WAKE_FRAME_TAG_BYTES      = 5,   /* the length is not 5 + 2k               */
	WAKE_FRAME_NO_TAGS        = 6,   /* k = 0 without ROLL                     */
	WAKE_FRAME_ROLL_WITH_TAGS = 7,   /* ROLL with k above 0                    */
	WAKE_FRAME_ROLL_WITH_MORE = 8    /* ROLL with MORE: no list to continue    */
} wake_frame_result_t;

/* What a parsed frame means to one collar. */
typedef enum {
	WAKE_NOT_CALLED = 0,   /* back to listening, nothing charged                       */
	WAKE_CALLED     = 1,   /* its tag is in the frame: wait for the train's end, then
	                          for the INTENT                                           */
	WAKE_MORE       = 2,   /* its tag is not here but the list continues: read one
	                          more frame before giving up                              */
	WAKE_ROLL       = 3    /* a roll-call train: wait for its end, then the roll call  */
} wake_verdict_t;

/* 32-bit avalanche mix (murmur3 fmix32); the collar firmware's
 * send_phase_mix (send_phase.h), repeated here so this file stands alone. */
static inline uint32_t wake_mix(uint32_t x)
{
	x ^= x >> 16;
	x *= 0x85EBCA6Bu;
	x ^= x >> 13;
	x *= 0xC2B2AE35u;
	x ^= x >> 16;
	return x;
}

/* The 16 bits a wake frame names a collar by. Two collars share a tag once
 * in 65,536: the other then stays up for nothing, because the INTENT that
 * follows carries the whole uid. */
static inline uint16_t wake_tag(uint32_t uid)
{
	return (uint16_t)(wake_mix(uid ^ WAKE_SALT) & 0xFFFFu);
}

/* Build a frame from *f (flags, time left, k tags). Returns its length,
 * 5 + 2k, or 0 with nothing written for a NULL argument or a frame the
 * parser below would refuse (reserved flags, k above 4, no tags without
 * ROLL, ROLL with tags or MORE). */
size_t wake_frame_build(const wake_frame_t *f, uint8_t out[WAKE_FRAME_MAX_LEN]);

/* Decode a received frame as a collar does. On WAKE_FRAME_OK *f is filled
 * (unused tags zero); on anything else *f is zeroed. */
wake_frame_result_t wake_frame_parse(const uint8_t *frame, size_t len, wake_frame_t *f);

wake_verdict_t wake_frame_verdict(const wake_frame_t *f, uint32_t uid);

/* ---- regions and the wake channel ---------------------------------------- */

/* A resolved region: the DirectRegion numbers of ble.proto, with 0 (AUTO as
 * a setting) meaning "none": a device with no region does not listen. 4..15
 * are the other rule sets of direct_rules.h (DR_REGION_*, 2026-11-17). */
#define WAKE_REGION_NONE    0u
#define WAKE_REGION_US915   1u
#define WAKE_REGION_EU868   2u
#define WAKE_REGION_AU915   3u
#define WAKE_REGION_MAX     15u   /* a setting above this is no region */
/* ble.proto RadioRegion, the LoRaWAN region: NOT the numbers above. */
#define WAKE_LORAWAN_US915  0u
#define WAKE_LORAWAN_AU915  1u
#define WAKE_LORAWAN_EU868  2u

/* Every frame on the wake channel: coding rate 4/5, explicit header, CRC on,
 * IQ normal, this sync word; 12 preamble symbols on wake frames, 8 on every
 * other frame (a receiver set for 12 takes both). */
#define WAKE_SYNC_WORD          0x57u
#define WAKE_PREAMBLE_SYMBOLS   12u
#define WAKE_OTHER_PREAMBLE     8u

typedef struct {
	uint32_t frequency_hz;
	uint16_t bw_khz;
	uint8_t  sf;
	int8_t   max_dbm;      /* the band's cap for the generic device (direct_rules.h
	                          dr_wake_channel); a device sends at its direct-radio
	                          power held to dr_power_cap with its own profile */
} wake_channel_t;

/* The region a device runs. setting is the DirectRegion value: 1..15 is that
 * region (old, to 2026-11-17: 1..3); 0 (AUTO) takes the LoRaWAN region when
 * LoRaWAN is configured (lorawan_region, a RadioRegion value), else reads
 * the direct radio's frequency in whole MHz: 863..870 is EU868, 902..928 is
 * US915, never AU915. Everything else, a setting above 15 included, is
 * WAKE_REGION_NONE. direct_rules.h dr_region_resolve takes kHz. */
uint8_t wake_region_resolve(uint32_t setting, bool lorawan_configured,
                            uint32_t lorawan_region, uint32_t frequency_mhz);

/* The wake channel of a resolved region (1..15), standard or long range,
 * from the table of direct_rules_table.c (CONTRACT_direct_regions.md
 * section 9). false (with *out zeroed) for WAKE_REGION_NONE or an unknown
 * region. Needs direct_rules.c and direct_rules_table.c in the build. */
bool wake_channel(uint8_t region, bool long_range, wake_channel_t *out);

/* ---- timing --------------------------------------------------------------- */
/*
 *   Ts          = 2^SF / BW
 *   toa(n, p)   = (p + 4.25 + 8 + max(ceil((8n - 4 SF + 44) / (4 (SF - 2 DE))) x 5, 0)) x Ts
 *                 coding rate 4/5, explicit header, CRC on; DE = 1 when Ts > 16 ms
 *   frame       = toa(13, 12)               one full wake frame
 *   tail        = toa(13, 8) - 8 Ts         a wake frame after its preamble
 *   W           = tail + 16 Ts + 7 ms       the collar's listen window
 *   cap         = 1.5 x frame + 20 ms       how long a detection may hold the collar
 *   train       >= 1.03 x I + W + frame     I = the called collars' interval
 *   intent_wait = 2 x toa(14, 8) + 150 ms   the collar's wait for the INTENT, from T0 - 10 ms
 *   cmd_window  = toa(255, 8) + 300 ms      the existing command window
 *   T0 = the end of the train: the caught frame's end + its time left.
 * Every function returns 0 for a setting outside SF7..12 at 125, 250 or
 * 500 kHz.
 */
#define WAKE_INTERVAL_MIN_S      5u     /* a non-zero listening interval is held to 5..120 s */
#define WAKE_INTERVAL_MAX_S      120u
#define WAKE_SLOW_FACTOR_MAX     4u     /* over budget: the interval x2, at most x4, to the hour's end */
#define WAKE_GAP_MAX_MS          5u     /* between one frame's end and the next one's start */
#define WAKE_RX_LEAD_MS          10u    /* the collar receives from T0 - 10 ms */
#define WAKE_FIRST_SEND_MS       30u    /* the handheld's INTENT (or roll call) goes out at T0 + 30 ms */
#define WAKE_CALL_SNIFF_S        1u     /* the interval while called, standard setting */
#define WAKE_CALL_SNIFF_LONG_S   2u     /* ... long range */
#define WAKE_CALLED_WAIT_S       60u    /* listening at CALL_SNIFF after a train, before any signed command */
#define WAKE_CALL_IDLE_S         300u   /* the call window ends this long after the last accepted command */
#define WAKE_CALL_MAX_S          900u   /* ... or this long after the first */
#define WAKE_TRAIN_INTERVAL_MAX_S 4000u /* wake_train_us stays inside 32 bits up to here */

uint32_t wake_symbol_us(uint8_t sf, uint16_t bw_khz);
uint32_t wake_toa_us(uint8_t sf, uint16_t bw_khz, uint16_t n, uint16_t preamble);
uint32_t wake_frame_us(uint8_t sf, uint16_t bw_khz);
uint32_t wake_tail_us(uint8_t sf, uint16_t bw_khz);
uint32_t wake_window_us(uint8_t sf, uint16_t bw_khz);        /* W */
uint32_t wake_cap_us(uint8_t sf, uint16_t bw_khz);
uint32_t wake_intent_wait_us(uint8_t sf, uint16_t bw_khz);
uint32_t wake_cmd_window_us(uint8_t sf, uint16_t bw_khz);
/* The shortest train that reaches a collar listening every interval_s
 * (1..WAKE_TRAIN_INTERVAL_MAX_S; 0 outside). */
uint32_t wake_train_us(uint8_t sf, uint16_t bw_khz, uint32_t interval_s);
/* How many frames make that train with gap_us (0..5000) between one frame's
 * end and the next one's start: the fewest whose span, first start to last
 * end, is at least wake_train_us. The sender's arithmetic, not a wire rule. */
uint32_t wake_train_frames(uint8_t sf, uint16_t bw_khz, uint32_t interval_s, uint32_t gap_us);
/* A time to the train's end as the frame's field: 10 ms units, rounded to
 * the nearest (a half up), held to 16 bits. */
uint16_t wake_time_left_10ms(uint32_t us);
/* The interval a collar runs: 0 stays 0 (not listening), anything else is
 * held to 5..120 s. */
uint32_t wake_interval_clamp(uint32_t seconds);

/* ---- roll call (0x43) ----------------------------------------------------- */

#define ROLL_CALL_MAGIC          0x43u
#define ROLL_CALL_HDR_LEN        9u
#define ROLL_CALL_BODY_LEN       12u
#define ROLL_CALL_LEN            (ROLL_CALL_HDR_LEN + ROLL_CALL_BODY_LEN + AEAD_CCM_TAG_LEN)   /* 29 */
#define ROLL_CALL_DIR            0x03u   /* the nonce's direction byte */
#define ROLL_CALL_SLOTS_MAX      64u
#define ROLL_CALL_SLOTS_DEFAULT  32u
#define ROLL_CALL_REPLY_LEN      30u     /* the answer is a v2 beacon (0x4D) */
/* old: #define ROLL_CALL_REPLY_BASE_MS  50u  (to 2026-11-13: slots 0 and 1 could not be met in time) */
#define ROLL_CALL_REPLY_BASE_MS  300u    /* the first slot starts this long after the roll call's end */
#define ROLL_CALL_SLOT_MARGIN_MIN_MS 5u  /* a slot is at least the answer's airtime + 5 ms */
#define ROLL_CALL_SLOT_MARGIN_MS 10u     /* ... and by default its airtime, rounded up, + 10 ms */
#define ROLL_CALL_LISTEN_EXTRA_MS 200u   /* the handheld listens 300 ms + slots x slot_ms + 200 ms */
#define ROLL_CALL_MIN_GAP_S      60u     /* a collar answers at most one roll call a minute */
#define ROLL_CALL_NEVER          0xFFFFFFFFu   /* since_answer_s: it has not answered one yet */

/* KDF label of the wake key family (12 ASCII bytes, no terminator): the
 * owner's COMMAND master, with the group where a device key has the uid. */
#define WAKE_KDF_LABEL           "CID-LORA-WAK"
#define WAKE_KDF_LABEL_LEN       12u
#define WAKE_KDF_INPUT_LEN       (WAKE_KDF_LABEL_LEN + 4u + 1u)   /* 17 */
#define WAKE_KEY_LEN             AEAD_AES_KEY_LEN                  /* 16 */

typedef struct {
	uint32_t valid_from;      /* UTC seconds */
	uint32_t valid_to;
	uint8_t  slots;
	uint16_t slot_ms;
	uint8_t  flags;           /* 0: none is defined */
} roll_call_body_t;

/* Why a collar does not answer, in the order checked (the `reason` of the
 * roll_calls.checks vectors, in the same order). */
typedef enum {
	ROLL_CALL_OK       = 0,    /* answer it */
	ROLL_CALL_FRAME    = 1,    /* not 0x43 and 29 bytes                              */
	ROLL_CALL_NO_KEY   = 2,    /* the collar holds no wake key                       */
	ROLL_CALL_GROUP    = 3,    /* not the group of its key                           */
	ROLL_CALL_GEN      = 4,    /* the counter's generation is not its key's          */
	ROLL_CALL_COUNTER  = 5,    /* not above the last roll call it accepted           */
	ROLL_CALL_TAG      = 6,    /* the tag does not verify                            */
	ROLL_CALL_FLAGS    = 7,    /* a flag bit is set                                  */
	ROLL_CALL_CLOCK    = 8,    /* the collar has no valid clock                      */
	ROLL_CALL_WINDOW   = 9,    /* now is outside [valid_from, valid_to]              */
	ROLL_CALL_SLOTS    = 10,   /* slots is not 1..64                                 */
	ROLL_CALL_SLOT_MS  = 11,   /* a slot is shorter than the answer's airtime + 5 ms */
	ROLL_CALL_RECENT   = 12    /* it answered a roll call less than 60 s ago         */
} roll_call_result_t;

/* group and counter from the cleartext header, no key needed. false unless
 * magic 0x43 and 29 bytes. */
bool roll_call_peek(const uint8_t *frame, size_t len, uint32_t *group, uint32_t *ctr);

/* Seal a roll call under the group's wake key (the server's side; here for
 * the host tests and tooling). false, with out zeroed, on a NULL argument or
 * a CCM refusal. Any field values are sealed; what a collar accepts is
 * roll_call_check. */
bool roll_call_seal(const aead_aes_t *wake_aes, uint32_t group, uint32_t ctr,
                    const roll_call_body_t *b, uint8_t out[ROLL_CALL_LEN]);

/* Open and verify. On any failure returns false with *b zeroed and *group,
 * *ctr untouched. */
bool roll_call_open(const aead_aes_t *wake_aes, const uint8_t *frame, size_t len,
                    uint32_t *group, uint32_t *ctr, roll_call_body_t *b);

/* The collar's rule, whole. wake_aes is the wake key it holds (NULL = none)
 * with that key's group and generation; last_ctr the last roll-call counter
 * it accepted (0 = none yet); clock_valid and now its clock (UTC seconds);
 * sf and bw_khz its wake setting; since_answer_s how long ago it last
 * answered a roll call (ROLL_CALL_NEVER = not yet). ROLL_CALL_OK: *ctr and
 * *b are the roll call's, and the caller persists *ctr as the new last_ctr
 * BEFORE it answers. Anything else: *b is zeroed, *ctr untouched, and
 * last_ctr does not move. */
roll_call_result_t roll_call_check(const aead_aes_t *wake_aes, uint32_t group, uint8_t gen,
                                   uint32_t last_ctr, bool clock_valid, uint32_t now,
                                   uint8_t sf, uint16_t bw_khz, uint32_t since_answer_s,
                                   const uint8_t *frame, size_t len,
                                   uint32_t *ctr, roll_call_body_t *b);

/* The slot this collar answers in (slots 1..255; 0 gives slot 0), and the
 * time from the roll call's end (the collar's RxDone) to the start of its
 * answer: 300 ms + slot x slot_ms. The collar seals the beacon inside those
 * 300 ms, after roll_call_check said ROLL_CALL_OK, never before. */
uint8_t  roll_call_slot(uint32_t uid, uint32_t ctr, uint8_t slots);
uint32_t roll_call_reply_delay_ms(uint32_t uid, uint32_t ctr, uint8_t slots, uint16_t slot_ms);

/* How long a collar that caught a ROLL train waits for the roll call, from
 * T0 - 10 ms: 2 x toa(29, 8) + 150 ms. */
uint32_t roll_call_wait_us(uint8_t sf, uint16_t bw_khz);
/* The shortest slot a collar accepts, toa(30, 8) + 5 ms, and the slot a
 * server signs by default, ceil(toa(30, 8)) + 10 ms. */
uint32_t roll_call_slot_min_us(uint8_t sf, uint16_t bw_khz);
uint16_t roll_call_slot_default_ms(uint8_t sf, uint16_t bw_khz);
/* How long the handheld listens after sending its roll call:
 * 300 ms + slots x slot_ms + 200 ms. */
uint32_t roll_call_listen_ms(uint8_t slots, uint16_t slot_ms);

/* The 17-byte KDF input of a wake key, label || group_le32 || gen, and the
 * key itself, AES-CMAC(command master, input). Off-collar only: a collar
 * is handed its wake key and never derives one. */
void wake_kdf_input(uint32_t group, uint8_t gen, uint8_t out[WAKE_KDF_INPUT_LEN]);
bool wake_kdf(const aead_aes_t *command_master_aes, uint32_t group, uint8_t gen,
              uint8_t out_key[WAKE_KEY_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* WAKE_FRAME_H */
