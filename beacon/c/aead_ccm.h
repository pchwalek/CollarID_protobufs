/*
 * aead_ccm.h — AES-128-CCM (RFC 3610) and AES-CMAC (RFC 4493) over an
 * injected AES-128 forward block function.
 *
 * The lost-mode beacon v2 frame (beacon_frame.h, docs/DESIGN_radio_security.md
 * section 3) is sealed with CCM at L=2 (13-byte nonce, 2-byte length) and
 * M=8 (8-byte tag). Both sealing and opening need only the AES forward
 * direction, so the STM32U595, which has no AES hardware, runs RadioLib's
 * software AES (Radiolib/utils/Cryptography.cpp) through the aead_aes_t
 * callback and never links the inverse cipher for this path.
 *
 * Pure C11: no HAL, no ThreadX, no heap, no libc beyond <string.h>. Every
 * buffer is a fixed 16-byte block on the caller's stack (about 80 B for a
 * seal), so it can run on the 4 KB LoRaWAN thread stack. The block callback
 * is ALWAYS called with distinct in/out buffers: RadioLibAES128::encryptECB
 * clears its output before copying the input (Cryptography.cpp:20-21), so an
 * aliased call would silently encrypt zeros. This module never aliases them;
 * a port that binds another AES may rely on that.
 *
 * The tag compare in aead_ccm_open_tag is constant-time (XOR accumulate).
 * The block cipher itself is whatever the caller injects; RadioLib's
 * mixColumns is not constant-time, which is accepted because the collar
 * only ever seals its own data (docs/DESIGN_radio_security.md section 6).
 *
 * Fixed-parameter wrappers (aead_ccm_seal / aead_ccm_open) are what the
 * frame codec uses; the *_tag variants take the tag length so the host tests
 * can run every RFC 3610 packet vector (1-24: M=8 and M=10, all L=2).
 */
#ifndef AEAD_CCM_H
#define AEAD_CCM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AEAD_AES_BLOCK_LEN   16u
#define AEAD_AES_KEY_LEN     16u

/* AES-128 forward block: out = E_K(in), in != out. ctx is the keyed cipher. */
typedef void (*aead_aes_block_fn)(void *ctx, const uint8_t in[AEAD_AES_BLOCK_LEN],
                                  uint8_t out[AEAD_AES_BLOCK_LEN]);

typedef struct {
	aead_aes_block_fn encrypt;
	void             *ctx;
} aead_aes_t;

#define AEAD_CCM_L           2u                      /* length-field bytes */
#define AEAD_CCM_NONCE_LEN   (15u - AEAD_CCM_L)      /* 13 */
#define AEAD_CCM_TAG_LEN     8u                      /* M for the beacon frame */
/* API limits, not RFC limits: bounded stack and no surprises on the collar.
 * A beacon has 9 B of AAD and a 13 B body. */
#define AEAD_CCM_MAX_AAD     32u
#define AEAD_CCM_MAX_PT      64u

/* Encrypt-and-tag. ct receives pt_len bytes, tag receives tag_len bytes
 * (4, 6, 8, 10, 12, 14 or 16). ct may alias pt. Returns false (writing
 * nothing) on a bad tag length or a length over the API limits. */
bool aead_ccm_seal_tag(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, uint8_t *tag, size_t tag_len);

/* Decrypt-and-verify. pt receives ct_len bytes only when the tag verifies;
 * on failure pt is zeroed and false is returned. pt may alias ct. */
bool aead_ccm_open_tag(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t *tag, size_t tag_len,
                       uint8_t *pt);

static inline bool aead_ccm_seal(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct, uint8_t tag[AEAD_CCM_TAG_LEN])
{
	return aead_ccm_seal_tag(aes, nonce, aad, aad_len, pt, pt_len, ct, tag, AEAD_CCM_TAG_LEN);
}

static inline bool aead_ccm_open(const aead_aes_t *aes, const uint8_t nonce[AEAD_CCM_NONCE_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct, size_t ct_len,
                                 const uint8_t tag[AEAD_CCM_TAG_LEN], uint8_t *pt)
{
	return aead_ccm_open_tag(aes, nonce, aad, aad_len, ct, ct_len, tag, AEAD_CCM_TAG_LEN, pt);
}

/* AES-CMAC (RFC 4493): 16-byte MAC of msg[0..len) under the injected key.
 * Used off-collar for the key derivation (beacon_frame.h); the collar itself
 * never derives keys. No heap (RadioLib's generateCMAC allocates). */
void aead_cmac(const aead_aes_t *aes, const uint8_t *msg, size_t len,
               uint8_t mac[AEAD_AES_BLOCK_LEN]);

/* Constant-time equality of n bytes (no early exit, no data-dependent branch). */
bool aead_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* AEAD_CCM_H */
