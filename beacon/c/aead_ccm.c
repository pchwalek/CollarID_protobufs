/*
 * aead_ccm.c — AES-128-CCM (RFC 3610) and AES-CMAC (RFC 4493) over an
 * injected AES-128 block function. See aead_ccm.h.
 *
 * Rules this file keeps:
 *  - the block callback never sees aliased in/out (RadioLib's encryptECB
 *    memsets out before it copies in);
 *  - no heap, no buffer larger than one block, no early exit in the tag
 *    compare, no plaintext left behind on a failed open;
 *  - every length is checked before anything is written.
 */
#include "aead_ccm.h"

#include <string.h>

#define BLK AEAD_AES_BLOCK_LEN

static void xor_into(uint8_t *dst, const uint8_t *src, size_t n)
{
	for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(dst[i] ^ src[i]);
}

static void aes_block(const aead_aes_t *aes, const uint8_t in[BLK], uint8_t out[BLK])
{
	aes->encrypt(aes->ctx, in, out);
}

/* CBC-MAC step: x = E(x XOR b). Two buffers so the callback never aliases. */
static void mac_step(const aead_aes_t *aes, uint8_t x[BLK], const uint8_t b[BLK])
{
	uint8_t t[BLK];
	memcpy(t, x, BLK);
	xor_into(t, b, BLK);
	aes_block(aes, t, x);
}

/* A_i = (L-1) || nonce || i (2 bytes big-endian); S_i = E(A_i). */
static void keystream(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                      uint16_t i, uint8_t s[BLK])
{
	uint8_t a[BLK];
	a[0] = (uint8_t)(AEAD_CCM_L - 1u);
	memcpy(&a[1], nonce, AEAD_CCM_NONCE_LEN);
	a[14] = (uint8_t)(i >> 8);
	a[15] = (uint8_t)(i & 0xFFu);
	aes_block(aes, a, s);
}

static bool tag_len_ok(size_t m)
{
	return m >= 4u && m <= 16u && (m & 1u) == 0u;
}

static bool lengths_ok(size_t aad_len, size_t pt_len, size_t tag_len)
{
	return tag_len_ok(tag_len) && aad_len <= AEAD_CCM_MAX_AAD && pt_len <= AEAD_CCM_MAX_PT;
}

/* CBC-MAC over B_0, the AAD blocks and the padded payload; x receives X_n+1.
 * (RFC 3610 section 2.2, the l(a) < 2^16 - 2^8 encoding, which the API
 * limits guarantee.) */
static void ccm_mac(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len, size_t tag_len, uint8_t x[BLK])
{
	uint8_t b[BLK];

	/* B_0: flags || nonce || l(m) */
	b[0] = (uint8_t)((aad_len ? 0x40u : 0x00u)
	                 | (((tag_len - 2u) / 2u) << 3)
	                 | (AEAD_CCM_L - 1u));
	memcpy(&b[1], nonce, AEAD_CCM_NONCE_LEN);
	b[14] = (uint8_t)(pt_len >> 8);
	b[15] = (uint8_t)(pt_len & 0xFFu);
	memset(x, 0, BLK);
	mac_step(aes, x, b);

	/* AAD blocks: 2-byte length, then the bytes, zero padded. */
	if (aad_len) {
		size_t done = 0;                /* AAD bytes consumed */
		size_t fill = 2;                /* bytes staged in b */
		memset(b, 0, BLK);
		b[0] = (uint8_t)(aad_len >> 8);
		b[1] = (uint8_t)(aad_len & 0xFFu);
		while (done < aad_len) {
			size_t n = aad_len - done;
			if (n > BLK - fill) n = BLK - fill;
			memcpy(&b[fill], &aad[done], n);
			fill += n;
			done += n;
			if (fill == BLK || done == aad_len) {
				mac_step(aes, x, b);
				memset(b, 0, BLK);
				fill = 0;
			}
		}
	}

	/* Payload blocks, zero padded. */
	for (size_t off = 0; off < pt_len; off += BLK) {
		size_t n = pt_len - off;
		if (n > BLK) n = BLK;
		memset(b, 0, BLK);
		memcpy(b, &pt[off], n);
		mac_step(aes, x, b);
	}
}

/* CTR over the payload with S_1.. ; out may alias in. */
static void ccm_crypt(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                      const uint8_t *in, size_t len, uint8_t *out)
{
	uint8_t s[BLK];
	uint16_t i = 1;
	for (size_t off = 0; off < len; off += BLK, i++) {
		size_t n = len - off;
		if (n > BLK) n = BLK;
		keystream(aes, nonce, i, s);
		for (size_t j = 0; j < n; j++) out[off + j] = (uint8_t)(in[off + j] ^ s[j]);
	}
}

bool aead_ccm_seal_tag(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, uint8_t *tag, size_t tag_len)
{
	uint8_t x[BLK], s0[BLK];

	if (!aes || !aes->encrypt || !nonce || !tag) return false;
	if (!lengths_ok(aad_len, pt_len, tag_len)) return false;
	if ((aad_len && !aad) || (pt_len && (!pt || !ct))) return false;

	ccm_mac(aes, nonce, aad, aad_len, pt, pt_len, tag_len, x);
	ccm_crypt(aes, nonce, pt, pt_len, ct);      /* after the MAC: ct may alias pt */
	keystream(aes, nonce, 0, s0);
	for (size_t j = 0; j < tag_len; j++) tag[j] = (uint8_t)(x[j] ^ s0[j]);
	return true;
}

bool aead_ccm_open_tag(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       uint8_t *pt)
{
	uint8_t x[BLK], s0[BLK], t[BLK];

	if (!aes || !aes->encrypt || !nonce || !tag) return false;
	if (!lengths_ok(aad_len, ct_len, tag_len)) return false;
	if ((aad_len && !aad) || (ct_len && (!ct || !pt))) return false;

	ccm_crypt(aes, nonce, ct, ct_len, pt);
	ccm_mac(aes, nonce, aad, aad_len, pt, ct_len, tag_len, x);
	keystream(aes, nonce, 0, s0);
	for (size_t j = 0; j < tag_len; j++) t[j] = (uint8_t)(x[j] ^ s0[j]);
	if (!aead_ct_equal(t, tag, tag_len)) {
		if (ct_len) memset(pt, 0, ct_len);
		return false;
	}
	return true;
}

/* RFC 4493 subkeys: L = E(0); K1 = L<<1 (^ 0x87 on carry); K2 = K1<<1 (same). */
static void shift_left_block(uint8_t out[BLK], const uint8_t in[BLK])
{
	uint8_t carry = 0;
	for (size_t i = BLK; i-- > 0;) {
		out[i] = (uint8_t)((uint8_t)(in[i] << 1) | carry);
		carry = (uint8_t)(in[i] >> 7);
	}
	if (in[0] & 0x80u) out[BLK - 1] = (uint8_t)(out[BLK - 1] ^ 0x87u);
}

void aead_cmac(const aead_aes_t *aes, const uint8_t *msg, size_t len, uint8_t mac[BLK])
{
	uint8_t zero[BLK], l[BLK], k1[BLK], k2[BLK], x[BLK], last[BLK];
	size_t n = (len + BLK - 1u) / BLK;
	bool complete = (len != 0) && (len % BLK == 0);

	memset(zero, 0, BLK);
	aes_block(aes, zero, l);
	shift_left_block(k1, l);
	shift_left_block(k2, k1);
	if (n == 0) n = 1;

	memset(x, 0, BLK);
	for (size_t i = 0; i + 1 < n; i++) mac_step(aes, x, &msg[i * BLK]);

	memset(last, 0, BLK);
	if (complete) {
		memcpy(last, &msg[(n - 1u) * BLK], BLK);
		xor_into(last, k1, BLK);
	} else {
		size_t rem = len - (n - 1u) * BLK;     /* 0 only when len == 0 */
		if (rem) memcpy(last, &msg[(n - 1u) * BLK], rem);
		last[rem] = 0x80u;
		xor_into(last, k2, BLK);
	}
	mac_step(aes, x, last);
	memcpy(mac, x, BLK);
}

bool aead_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++) acc = (uint8_t)(acc | (uint8_t)(a[i] ^ b[i]));
	return acc == 0;
}
