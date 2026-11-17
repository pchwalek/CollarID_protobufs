/*
 * wake_frame.c — LoRa wake: the wake frame, the wake channel table, the
 * timing and the roll call. See wake_frame.h; contract in
 * CollarID_protobufs beacon/README.md, vectors in beacon/vectors.json.
 *
 * Rules this file keeps:
 *  - bytes are assembled explicitly (little-endian), never by memcpy of a
 *    struct;
 *  - times are whole microseconds in integers, so both ends of a wake get
 *    the same numbers from the same settings;
 *  - a failed open or a refused roll call leaves nothing of the plaintext
 *    behind;
 *  - no heap, no HAL, no float.
 */
#include "wake_frame.h"

#include <string.h>

#include "direct_rules.h"   /* the region table: wake channels and regions (2026-11-17) */

static void put_u16le(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xFFu);
	p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static uint16_t get_u16le(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static void put_u32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xFFu);
	p[1] = (uint8_t)((v >> 8) & 0xFFu);
	p[2] = (uint8_t)((v >> 16) & 0xFFu);
	p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- the wake frame ------------------------------------------------------ */

/* The checks a frame's header fields must pass, shared by build and parse. */
static wake_frame_result_t wake_fields_check(uint8_t flags, uint8_t k)
{
	if ((flags & (uint8_t)~WAKE_FLAGS_DEFINED) != 0u) return WAKE_FRAME_RESERVED_FLAGS;
	if (k > WAKE_FRAME_MAX_TAGS) return WAKE_FRAME_TAG_COUNT;
	return WAKE_FRAME_OK;
}

static wake_frame_result_t wake_roll_check(uint8_t flags, uint8_t k)
{
	const bool roll = (flags & WAKE_FLAG_ROLL) != 0u;
	if (k == 0u && !roll) return WAKE_FRAME_NO_TAGS;
	if (roll && k != 0u) return WAKE_FRAME_ROLL_WITH_TAGS;
	if (roll && (flags & WAKE_FLAG_MORE) != 0u) return WAKE_FRAME_ROLL_WITH_MORE;
	return WAKE_FRAME_OK;
}

size_t wake_frame_build(const wake_frame_t *f, uint8_t out[WAKE_FRAME_MAX_LEN])
{
	if (!f || !out) return 0;
	if (wake_fields_check(f->flags, f->k) != WAKE_FRAME_OK) return 0;
	if (wake_roll_check(f->flags, f->k) != WAKE_FRAME_OK) return 0;
	out[0] = (uint8_t)WAKE_FRAME_MAGIC;
	out[1] = f->flags;
	put_u16le(&out[2], f->time_left_10ms);
	out[4] = f->k;
	for (uint8_t i = 0; i < f->k; i++) {
		put_u16le(&out[WAKE_FRAME_HDR_LEN + 2u * i], f->tags[i]);
	}
	return (size_t)WAKE_FRAME_HDR_LEN + 2u * (size_t)f->k;
}

wake_frame_result_t wake_frame_parse(const uint8_t *frame, size_t len, wake_frame_t *f)
{
	wake_frame_result_t r;

	if (f) memset(f, 0, sizeof(*f));
	if (!frame || !f) return WAKE_FRAME_LENGTH;
	if (len < WAKE_FRAME_HDR_LEN || len > WAKE_FRAME_MAX_LEN) return WAKE_FRAME_LENGTH;
	if (frame[0] != (uint8_t)WAKE_FRAME_MAGIC) return WAKE_FRAME_BAD_MAGIC;
	r = wake_fields_check(frame[1], frame[4]);
	if (r != WAKE_FRAME_OK) return r;
	if (len != (size_t)WAKE_FRAME_HDR_LEN + 2u * (size_t)frame[4]) return WAKE_FRAME_TAG_BYTES;
	r = wake_roll_check(frame[1], frame[4]);
	if (r != WAKE_FRAME_OK) return r;
	f->flags = frame[1];
	f->time_left_10ms = get_u16le(&frame[2]);
	f->k = frame[4];
	for (uint8_t i = 0; i < f->k; i++) {
		f->tags[i] = get_u16le(&frame[WAKE_FRAME_HDR_LEN + 2u * i]);
	}
	return WAKE_FRAME_OK;
}

wake_verdict_t wake_frame_verdict(const wake_frame_t *f, uint32_t uid)
{
	uint16_t tag;

	if (!f) return WAKE_NOT_CALLED;
	if ((f->flags & WAKE_FLAG_ROLL) != 0u) return WAKE_ROLL;
	tag = wake_tag(uid);
	for (uint8_t i = 0; i < f->k && i < WAKE_FRAME_MAX_TAGS; i++) {
		if (f->tags[i] == tag) return WAKE_CALLED;
	}
	return ((f->flags & WAKE_FLAG_MORE) != 0u) ? WAKE_MORE : WAKE_NOT_CALLED;
}

/* ---- regions and the wake channel ---------------------------------------- */

uint8_t wake_region_resolve(uint32_t setting, bool lorawan_configured,
                            uint32_t lorawan_region, uint32_t frequency_mhz)
{
	/* old (to 2026-11-17, CONTRACT_lora_wake.md section 1; a setting above 3 was no region):
	 * if (setting == WAKE_REGION_US915 || setting == WAKE_REGION_EU868 || setting == WAKE_REGION_AU915) {
	 * 	return (uint8_t)setting;
	 * }
	 * if (setting != 0u) return WAKE_REGION_NONE;
	 * if (lorawan_configured) {
	 * 	switch (lorawan_region) {
	 * 	case WAKE_LORAWAN_US915: return WAKE_REGION_US915;
	 * 	case WAKE_LORAWAN_AU915: return WAKE_REGION_AU915;
	 * 	case WAKE_LORAWAN_EU868: return WAKE_REGION_EU868;
	 * 	default:                 return WAKE_REGION_NONE;
	 * 	}
	 * }
	 * if (frequency_mhz >= 863u && frequency_mhz <= 870u) return WAKE_REGION_EU868;
	 * if (frequency_mhz >= 902u && frequency_mhz <= 928u) return WAKE_REGION_US915;
	 * return WAKE_REGION_NONE;
	 */
	/* CONTRACT_direct_regions.md section 9: 1..15 is that region, AUTO as before. A
	 * frequency past 32 bits of kHz is no frequency (0 resolves to none). */
	const uint32_t khz = (frequency_mhz <= 0xFFFFFFFFu / 1000u) ? frequency_mhz * 1000u : 0u;
	return dr_region_resolve(setting, lorawan_configured, lorawan_region, khz);
}

bool wake_channel(uint8_t region, bool long_range, wake_channel_t *out)
{
	dr_wake_t w;

	if (!out) return false;
	memset(out, 0, sizeof(*out));
	/* old (to 2026-11-17): US915 and AU915 919 MHz / 500 kHz / SF9 (12), EU868
	 * 869.525 MHz / 125 kHz / SF7 (10), max_dbm 22 for all three; anything else false.
	 * Now the table of direct_rules_table.c, max_dbm the band's cap for the generic
	 * device (22 for those three, as before). */
	if (!dr_wake_channel(dr_rule_set(region), long_range, &w)) return false;
	out->frequency_hz = w.freq_hz;
	out->bw_khz = w.bw_khz;
	out->sf = w.sf;
	out->max_dbm = w.max_dbm;
	return true;
}

/* ---- timing --------------------------------------------------------------- */

uint32_t wake_symbol_us(uint8_t sf, uint16_t bw_khz)
{
	if (sf < 7u || sf > 12u) return 0;
	if (bw_khz != 125u && bw_khz != 250u && bw_khz != 500u) return 0;
	return ((uint32_t)1u << sf) * 1000u / bw_khz;      /* exact: a multiple of 4 us */
}

uint32_t wake_toa_us(uint8_t sf, uint16_t bw_khz, uint16_t n, uint16_t preamble)
{
	const uint32_t ts = wake_symbol_us(sf, bw_khz);
	int32_t num, den, payload_symbols;
	uint32_t quarter_symbols;

	if (ts == 0u || n > 255u || preamble > 1024u) return 0;
	den = 4 * ((int32_t)sf - ((ts > 16000u) ? 2 : 0));
	num = 8 * (int32_t)n - 4 * (int32_t)sf + 44;
	/* ceil(num / den) x 5, never below 0 (den is positive). */
	payload_symbols = (num > 0) ? ((num + den - 1) / den) * 5 : 0;
	/* (p + 4.25 + 8 + payload) symbols, counted in quarters. */
	quarter_symbols = 4u * preamble + 17u + 32u + 4u * (uint32_t)payload_symbols;
	return quarter_symbols * (ts / 4u);
}

uint32_t wake_frame_us(uint8_t sf, uint16_t bw_khz)
{
	return wake_toa_us(sf, bw_khz, WAKE_FRAME_MAX_LEN, WAKE_PREAMBLE_SYMBOLS);
}

uint32_t wake_tail_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t ts = wake_symbol_us(sf, bw_khz);
	if (ts == 0u) return 0;
	return wake_toa_us(sf, bw_khz, WAKE_FRAME_MAX_LEN, WAKE_OTHER_PREAMBLE) - 8u * ts;
}

uint32_t wake_window_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t ts = wake_symbol_us(sf, bw_khz);
	if (ts == 0u) return 0;
	return wake_tail_us(sf, bw_khz) + 16u * ts + 7000u;
}

uint32_t wake_cap_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t frame = wake_frame_us(sf, bw_khz);
	if (frame == 0u) return 0;
	return frame * 3u / 2u + 20000u;
}

uint32_t wake_intent_wait_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t toa = wake_toa_us(sf, bw_khz, 14u, WAKE_OTHER_PREAMBLE);
	if (toa == 0u) return 0;
	return 2u * toa + 150000u;
}

uint32_t wake_cmd_window_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t toa = wake_toa_us(sf, bw_khz, 255u, WAKE_OTHER_PREAMBLE);
	if (toa == 0u) return 0;
	return toa + 300000u;
}

uint32_t wake_train_us(uint8_t sf, uint16_t bw_khz, uint32_t interval_s)
{
	const uint32_t frame = wake_frame_us(sf, bw_khz);
	if (frame == 0u || interval_s < 1u || interval_s > WAKE_TRAIN_INTERVAL_MAX_S) return 0;
	/* 3 % for the two clocks, one listen window and one frame over. */
	return 1030000u * interval_s + wake_window_us(sf, bw_khz) + frame;
}

uint32_t wake_train_frames(uint8_t sf, uint16_t bw_khz, uint32_t interval_s, uint32_t gap_us)
{
	const uint32_t frame = wake_frame_us(sf, bw_khz);
	const uint32_t train = wake_train_us(sf, bw_khz, interval_s);
	if (train == 0u || gap_us > WAKE_GAP_MAX_MS * 1000u) return 0;
	return (train + gap_us + (frame + gap_us) - 1u) / (frame + gap_us);
}

uint16_t wake_time_left_10ms(uint32_t us)
{
	const uint32_t units = us / 10000u + ((us % 10000u) >= 5000u ? 1u : 0u);
	return (uint16_t)(units > WAKE_TIME_LEFT_MAX ? WAKE_TIME_LEFT_MAX : units);
}

uint32_t wake_interval_clamp(uint32_t seconds)
{
	if (seconds == 0u) return 0;
	if (seconds < WAKE_INTERVAL_MIN_S) return WAKE_INTERVAL_MIN_S;
	if (seconds > WAKE_INTERVAL_MAX_S) return WAKE_INTERVAL_MAX_S;
	return seconds;
}

/* ---- roll call (0x43) ----------------------------------------------------- */

_Static_assert(ROLL_CALL_LEN == 29u, "the public 0x43 layout");
_Static_assert(ROLL_CALL_HDR_LEN <= AEAD_CCM_MAX_AAD && ROLL_CALL_BODY_LEN <= AEAD_CCM_MAX_PT,
               "aead_ccm must seal a roll call");

static void roll_call_nonce(uint32_t group, uint32_t ctr, uint8_t out[AEAD_CCM_NONCE_LEN])
{
	put_u32le(&out[0], group);
	put_u32le(&out[4], ctr);
	out[8] = (uint8_t)ROLL_CALL_DIR;
	memset(&out[9], 0, 4);
}

bool roll_call_peek(const uint8_t *frame, size_t len, uint32_t *group, uint32_t *ctr)
{
	if (!frame || !group || !ctr) return false;
	if (len != ROLL_CALL_LEN || frame[0] != (uint8_t)ROLL_CALL_MAGIC) return false;
	*group = get_u32le(&frame[1]);
	*ctr = get_u32le(&frame[5]);
	return true;
}

bool roll_call_seal(const aead_aes_t *wake_aes, uint32_t group, uint32_t ctr,
                    const roll_call_body_t *b, uint8_t out[ROLL_CALL_LEN])
{
	uint8_t nonce[AEAD_CCM_NONCE_LEN];
	uint8_t body[ROLL_CALL_BODY_LEN];
	bool ok;

	if (!wake_aes || !b || !out) return false;
	out[0] = (uint8_t)ROLL_CALL_MAGIC;
	put_u32le(&out[1], group);
	put_u32le(&out[5], ctr);
	put_u32le(&body[0], b->valid_from);
	put_u32le(&body[4], b->valid_to);
	body[8] = b->slots;
	put_u16le(&body[9], b->slot_ms);
	body[11] = b->flags;
	roll_call_nonce(group, ctr, nonce);
	ok = aead_ccm_seal(wake_aes, nonce, out, ROLL_CALL_HDR_LEN, body, ROLL_CALL_BODY_LEN,
	                   &out[ROLL_CALL_HDR_LEN], &out[ROLL_CALL_HDR_LEN + ROLL_CALL_BODY_LEN]);
	memset(body, 0, sizeof(body));
	if (!ok) memset(out, 0, ROLL_CALL_LEN);
	return ok;
}

bool roll_call_open(const aead_aes_t *wake_aes, const uint8_t *frame, size_t len,
                    uint32_t *group, uint32_t *ctr, roll_call_body_t *b)
{
	uint8_t nonce[AEAD_CCM_NONCE_LEN];
	uint8_t body[ROLL_CALL_BODY_LEN];
	uint32_t g, c;

	if (b) memset(b, 0, sizeof(*b));
	if (!wake_aes || !group || !ctr || !b) return false;
	if (!roll_call_peek(frame, len, &g, &c)) return false;
	roll_call_nonce(g, c, nonce);
	/* aead_ccm zeroes body when the tag does not verify. */
	if (!aead_ccm_open(wake_aes, nonce, frame, ROLL_CALL_HDR_LEN,
	                   &frame[ROLL_CALL_HDR_LEN], ROLL_CALL_BODY_LEN,
	                   &frame[ROLL_CALL_HDR_LEN + ROLL_CALL_BODY_LEN], body)) {
		return false;
	}
	*group = g;
	*ctr = c;
	b->valid_from = get_u32le(&body[0]);
	b->valid_to = get_u32le(&body[4]);
	b->slots = body[8];
	b->slot_ms = get_u16le(&body[9]);
	b->flags = body[11];
	memset(body, 0, sizeof(body));
	return true;
}

roll_call_result_t roll_call_check(const aead_aes_t *wake_aes, uint32_t group, uint8_t gen,
                                   uint32_t last_ctr, bool clock_valid, uint32_t now,
                                   uint8_t sf, uint16_t bw_khz, uint32_t since_answer_s,
                                   const uint8_t *frame, size_t len,
                                   uint32_t *ctr, roll_call_body_t *b)
{
	roll_call_body_t body;
	roll_call_result_t r = ROLL_CALL_OK;
	uint32_t g, c, slot_min_us;

	if (b) memset(b, 0, sizeof(*b));
	if (!ctr || !b) return ROLL_CALL_FRAME;
	if (!roll_call_peek(frame, len, &g, &c)) return ROLL_CALL_FRAME;
	if (!wake_aes) return ROLL_CALL_NO_KEY;
	if (g != group) return ROLL_CALL_GROUP;
	if ((uint8_t)(c >> 24) != gen) return ROLL_CALL_GEN;
	if (c <= last_ctr) return ROLL_CALL_COUNTER;
	if (!roll_call_open(wake_aes, frame, len, &g, &c, &body)) return ROLL_CALL_TAG;
	slot_min_us = roll_call_slot_min_us(sf, bw_khz);
	if (body.flags != 0u) {
		r = ROLL_CALL_FLAGS;
	} else if (!clock_valid) {
		r = ROLL_CALL_CLOCK;
	} else if (now < body.valid_from || now > body.valid_to) {
		r = ROLL_CALL_WINDOW;
	} else if (body.slots < 1u || body.slots > ROLL_CALL_SLOTS_MAX) {
		r = ROLL_CALL_SLOTS;
	} else if (slot_min_us == 0u || (uint32_t)body.slot_ms * 1000u < slot_min_us) {
		r = ROLL_CALL_SLOT_MS;
	} else if (since_answer_s != ROLL_CALL_NEVER && since_answer_s < ROLL_CALL_MIN_GAP_S) {
		r = ROLL_CALL_RECENT;
	}
	if (r == ROLL_CALL_OK) {
		*ctr = c;
		*b = body;
	}
	memset(&body, 0, sizeof(body));
	return r;
}

uint8_t roll_call_slot(uint32_t uid, uint32_t ctr, uint8_t slots)
{
	if (slots == 0u) return 0;
	return (uint8_t)(wake_mix(uid ^ WAKE_SALT ^ ctr) % slots);
}

uint32_t roll_call_reply_delay_ms(uint32_t uid, uint32_t ctr, uint8_t slots, uint16_t slot_ms)
{
	return ROLL_CALL_REPLY_BASE_MS + (uint32_t)roll_call_slot(uid, ctr, slots) * slot_ms;
}

uint32_t roll_call_wait_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t toa = wake_toa_us(sf, bw_khz, ROLL_CALL_LEN, WAKE_OTHER_PREAMBLE);
	if (toa == 0u) return 0;
	return 2u * toa + 150000u;
}

uint32_t roll_call_slot_min_us(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t toa = wake_toa_us(sf, bw_khz, ROLL_CALL_REPLY_LEN, WAKE_OTHER_PREAMBLE);
	if (toa == 0u) return 0;
	return toa + ROLL_CALL_SLOT_MARGIN_MIN_MS * 1000u;
}

uint16_t roll_call_slot_default_ms(uint8_t sf, uint16_t bw_khz)
{
	const uint32_t toa = wake_toa_us(sf, bw_khz, ROLL_CALL_REPLY_LEN, WAKE_OTHER_PREAMBLE);
	if (toa == 0u) return 0;
	return (uint16_t)((toa + 999u) / 1000u + ROLL_CALL_SLOT_MARGIN_MS);
}

uint32_t roll_call_listen_ms(uint8_t slots, uint16_t slot_ms)
{
	/* old: return (uint32_t)slots * slot_ms + ROLL_CALL_LISTEN_EXTRA_MS; */
	return ROLL_CALL_REPLY_BASE_MS + (uint32_t)slots * slot_ms + ROLL_CALL_LISTEN_EXTRA_MS;
}

void wake_kdf_input(uint32_t group, uint8_t gen, uint8_t out[WAKE_KDF_INPUT_LEN])
{
	memcpy(out, WAKE_KDF_LABEL, WAKE_KDF_LABEL_LEN);
	put_u32le(&out[WAKE_KDF_LABEL_LEN], group);
	out[WAKE_KDF_LABEL_LEN + 4u] = gen;
}

bool wake_kdf(const aead_aes_t *command_master_aes, uint32_t group, uint8_t gen,
              uint8_t out_key[WAKE_KEY_LEN])
{
	uint8_t in[WAKE_KDF_INPUT_LEN];
	if (!command_master_aes || !out_key) return false;
	wake_kdf_input(group, gen, in);
	aead_cmac(command_master_aes, in, WAKE_KDF_INPUT_LEN, out_key);
	return true;
}
