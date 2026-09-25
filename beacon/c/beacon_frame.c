/*
 * beacon_frame.c — lost-mode beacon v1/v2 codec, KDF and KCV. See
 * beacon_frame.h; contract in docs/DESIGN_radio_security.md sections 3-4.
 *
 * Rules this file keeps:
 *  - bytes are assembled explicitly (little-endian), never by memcpy of a
 *    struct, so the public copy decodes on any host;
 *  - the v1 layout is exactly sendLostModeBeacon's (test/host pins both);
 *  - a failed open leaves nothing of the plaintext behind;
 *  - no heap, no HAL.
 */
#include "beacon_frame.h"

#include <string.h>

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

/* int32 <-> uint32 two's complement without implementation-defined casts
 * of out-of-range values. */
static uint32_t i32_bits(int32_t v)
{
	return v >= 0 ? (uint32_t)v : (uint32_t)(~(uint32_t)(-(v + 1)));
}

static int32_t bits_i32(uint32_t u)
{
	return (u & 0x80000000u) ? (int32_t)(-(int64_t)(~u) - 1) : (int32_t)u;
}

/* ---- body and v1 ------------------------------------------------------- */

void beacon_body_pack(const beacon_body_t *b, uint8_t out[BEACON_BODY_LEN])
{
	put_u32le(&out[0], i32_bits(b->lat_e7));
	put_u32le(&out[4], i32_bits(b->lon_e7));
	put_u32le(&out[8], b->fix_epoch);
	out[12] = b->batt_pct;
}

void beacon_body_unpack(const uint8_t in[BEACON_BODY_LEN], beacon_body_t *b)
{
	b->lat_e7    = bits_i32(get_u32le(&in[0]));
	b->lon_e7    = bits_i32(get_u32le(&in[4]));
	b->fix_epoch = get_u32le(&in[8]);
	b->batt_pct  = in[12];
}

void beacon_v1_pack(uint32_t uid, const beacon_body_t *b, uint8_t out[BEACON_V1_LEN])
{
	out[0] = (uint8_t)BEACON_V1_MAGIC;
	put_u32le(&out[1], uid);
	beacon_body_pack(b, &out[5]);
}

bool beacon_v1_unpack(const uint8_t *frame, size_t len, uint32_t *uid, beacon_body_t *b)
{
	if (!frame || !uid || !b) return false;
	if (len != BEACON_V1_LEN || frame[0] != (uint8_t)BEACON_V1_MAGIC) return false;
	*uid = get_u32le(&frame[1]);
	beacon_body_unpack(&frame[5], b);
	return true;
}

/* ---- v2 ------------------------------------------------------------------ */

void beacon_v2_nonce(uint32_t uid, uint32_t ctr, uint8_t dir, uint8_t out[BEACON_V2_NONCE_LEN])
{
	put_u32le(&out[0], uid);
	put_u32le(&out[4], ctr);
	out[8] = dir;
	memset(&out[9], 0, 4);
}

bool beacon_v2_seal(const aead_aes_t *dev_aes, uint32_t uid, uint32_t ctr,
                    const beacon_body_t *b, uint8_t out[BEACON_V2_LEN])
{
	uint8_t nonce[BEACON_V2_NONCE_LEN];
	uint8_t body[BEACON_BODY_LEN];

	if (!dev_aes || !b || !out) return false;
	out[0] = (uint8_t)BEACON_V2_MAGIC;
	put_u32le(&out[1], uid);
	put_u32le(&out[5], ctr);
	beacon_v2_nonce(uid, ctr, BEACON_DIR_BEACON, nonce);
	beacon_body_pack(b, body);
	if (!aead_ccm_seal(dev_aes, nonce, out, BEACON_V2_AAD_LEN, body, BEACON_BODY_LEN,
	                   &out[BEACON_V2_AAD_LEN], &out[BEACON_V2_AAD_LEN + BEACON_BODY_LEN])) {
		memset(out, 0, BEACON_V2_LEN);
		return false;
	}
	return true;
}

bool beacon_v2_peek(const uint8_t *frame, size_t len, uint32_t *uid, uint32_t *ctr)
{
	if (!frame || !uid || !ctr) return false;
	if (len != BEACON_V2_LEN || frame[0] != (uint8_t)BEACON_V2_MAGIC) return false;
	*uid = get_u32le(&frame[1]);
	*ctr = get_u32le(&frame[5]);
	return true;
}

bool beacon_v2_open(const aead_aes_t *dev_aes, const uint8_t *frame, size_t len,
                    uint32_t *uid, uint32_t *ctr, beacon_body_t *b)
{
	uint8_t nonce[BEACON_V2_NONCE_LEN];
	uint8_t body[BEACON_BODY_LEN];
	uint32_t u, c;

	if (b) memset(b, 0, sizeof(*b));
	if (!dev_aes || !uid || !ctr || !b) return false;
	if (!beacon_v2_peek(frame, len, &u, &c)) return false;
	beacon_v2_nonce(u, c, BEACON_DIR_BEACON, nonce);
	if (!aead_ccm_open(dev_aes, nonce, frame, BEACON_V2_AAD_LEN,
	                   &frame[BEACON_V2_AAD_LEN], BEACON_BODY_LEN,
	                   &frame[BEACON_V2_AAD_LEN + BEACON_BODY_LEN], body)) {
		return false;
	}
	*uid = u;
	*ctr = c;
	beacon_body_unpack(body, b);
	memset(body, 0, sizeof(body));
	return true;
}

/* ---- keys ---------------------------------------------------------------- */

bool beacon_kdf_input(beacon_key_purpose_t purpose, uint32_t uid, uint8_t gen,
                      uint8_t out[BEACON_KDF_INPUT_LEN])
{
	const char *label;
	switch (purpose) {
	case BEACON_KEY_BEACON:  label = BEACON_KDF_LABEL_BEACON;  break;
	case BEACON_KEY_COMMAND: label = BEACON_KDF_LABEL_COMMAND; break;
	default: return false;
	}
	memcpy(out, label, BEACON_KDF_LABEL_LEN);
	put_u32le(&out[BEACON_KDF_LABEL_LEN], uid);
	out[BEACON_KDF_LABEL_LEN + 4u] = gen;
	return true;
}

bool beacon_kdf(const aead_aes_t *master_aes, beacon_key_purpose_t purpose,
                uint32_t uid, uint8_t gen, uint8_t out_key[BEACON_KEY_LEN])
{
	uint8_t in[BEACON_KDF_INPUT_LEN];
	if (!master_aes || !out_key) return false;
	if (!beacon_kdf_input(purpose, uid, gen, in)) return false;
	aead_cmac(master_aes, in, BEACON_KDF_INPUT_LEN, out_key);
	return true;
}

void beacon_kcv(const aead_aes_t *dev_aes, uint8_t out[BEACON_KCV_LEN])
{
	uint8_t zero[AEAD_AES_BLOCK_LEN], e[AEAD_AES_BLOCK_LEN];
	memset(zero, 0, sizeof(zero));
	dev_aes->encrypt(dev_aes->ctx, zero, e);
	memcpy(out, e, BEACON_KCV_LEN);
	memset(e, 0, sizeof(e));
}
