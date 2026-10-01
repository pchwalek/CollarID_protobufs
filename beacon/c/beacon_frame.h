/*
 * beacon_frame.h — the lost-mode beacon frames: v1 (0x4C, plaintext, what
 * every collar sends today) and v2 (0x4D, AES-128-CCM), plus the key
 * derivation and key check value a receiver or the server needs.
 *
 * Contract: docs/DESIGN_radio_security.md section 3 (frame) and 4 (keys),
 * published for outside implementers as CollarID_protobufs beacon/README.md
 * with the reference codec beacon/beacon_v2.py and the frozen vectors
 * beacon/vectors.json (vendored under test/host/data/). This file is the C
 * reference decoder that repository carries a copy of.
 *
 * v2 frame, 30 bytes, little-endian:
 *   [0]      0x4D                       magic ('M'; 0x4C 'L' stays v1)
 *   [1..4]   uid32                       HAL_GetUIDw0, cleartext (key lookup)
 *   [5..8]   tx_counter                  cleartext; [31:24] provision
 *                                        generation, [23:0] sequence
 *   [9..21]  ciphertext (13 B)           of the body below
 *   [22..29] tag (8 B)
 *   AAD    = bytes [0..8]
 *   nonce  = uid_le32 || ctr_le32 || dir || 0x00000000 (13 B), dir 0x00 here
 * body (13 B, = v1 bytes [5..17]):
 *   lat_e7 i32 || lon_e7 i32 || fix_epoch u32 || batt_pct u8
 *
 * Sealed report (0x52, 2026-09-30): a keyed collar's regular direct-radio
 * report, the same construction with a variable-length body (the protobuf
 * report it would otherwise send in the clear), under the same device key
 * and the same never-rewinding counter as its 0x4D beacons:
 *   [0]          0x52                    magic ('R')
 *   [1..4]       uid32                   cleartext
 *   [5..8]       tx_counter              cleartext, the beacon's sequence
 *   [9..9+n-1]   ciphertext (n B, 1..238)
 *   [9+n..9+n+7] tag (8 B)
 *   AAD and nonce exactly as v2 (dir 0x00); frame length n + 17 = 18..255,
 *   one LoRa packet. A plaintext report always starts 0x0A (its protobuf
 *   header field), so it never reads as 0x52.
 *
 * Keys: dev_key = AES-CMAC(master, label || uid_le32 || gen), one label per
 * purpose. The collar holds only dev_key (delivered over the BLE config
 * tunnel into the flash secure store, E2/E4); the KDF runs on the server and
 * on receivers that hold a master, and here only for the host tests.
 *
 * Pure C11 over the injected AES of aead_ccm.h: no HAL, no heap, no
 * endianness assumptions (bytes are assembled explicitly).
 * old: "Nothing in the firmware calls this yet (E6 flips the beacon builder);
 * old:  --gc-sections drops it from the image until then." (the collar has
 * sealed its 0x4D beacon since E3, and its reports since 2026-09-30)
 */
#ifndef BEACON_FRAME_H
#define BEACON_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "aead_ccm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BEACON_V1_MAGIC       0x4Cu
#define BEACON_V1_LEN         18u
#define BEACON_V2_MAGIC       0x4Du
#define BEACON_V2_LEN         30u
#define BEACON_BODY_LEN       13u
#define BEACON_V2_AAD_LEN     9u
#define BEACON_V2_NONCE_LEN   AEAD_CCM_NONCE_LEN   /* 13 */
#define BEACON_V2_TAG_LEN     AEAD_CCM_TAG_LEN     /* 8 */
#define BEACON_KEY_LEN        AEAD_AES_KEY_LEN     /* 16 */
#define BEACON_KCV_LEN        3u

/* Nonce direction byte: separates the collar's beacons from the finder
 * command channel (DESIGN_finder_two_way.md section 6) under one nonce
 * space. Only BEACON is used by this file. */
#define BEACON_DIR_BEACON     0x00u
#define BEACON_DIR_COMMAND    0x01u
#define BEACON_DIR_COMMAND_ACK 0x02u

/* tx_counter split: the provision generation (server-assigned, bumped on
 * every re-provision, 1..255 once keyed) over a 24-bit never-rewinding
 * sequence (the E2 secure store). */
#define BEACON_CTR_GEN(ctr)        ((uint8_t)((ctr) >> 24))
#define BEACON_CTR_SEQ(ctr)        ((uint32_t)((ctr) & 0x00FFFFFFu))
#define BEACON_CTR_MAKE(gen, seq)  ((uint32_t)(((uint32_t)(gen) << 24) | ((uint32_t)(seq) & 0x00FFFFFFu)))
#define BEACON_SEQ_MAX             0x00FFFFFFu

typedef struct {
	int32_t  lat_e7;
	int32_t  lon_e7;
	uint32_t fix_epoch;
	uint8_t  batt_pct;
} beacon_body_t;

/* KDF labels (12 ASCII bytes each, no terminator on the wire). */
#define BEACON_KDF_LABEL_BEACON   "CID-LORA-BCN"
#define BEACON_KDF_LABEL_COMMAND  "CID-LORA-CMD"
#define BEACON_KDF_LABEL_LEN      12u
#define BEACON_KDF_INPUT_LEN      (BEACON_KDF_LABEL_LEN + 4u + 1u)   /* 17 */

typedef enum {
	BEACON_KEY_BEACON  = 0,   /* confidentiality of beacons; exportable to owners */
	BEACON_KEY_COMMAND = 1    /* authentication of commands; never leaves the server */
} beacon_key_purpose_t;

/* ---- body and v1 ------------------------------------------------------- */

void beacon_body_pack(const beacon_body_t *b, uint8_t out[BEACON_BODY_LEN]);
void beacon_body_unpack(const uint8_t in[BEACON_BODY_LEN], beacon_body_t *b);

/* The legacy plaintext frame, byte-identical to sendLostModeBeacon's. */
void beacon_v1_pack(uint32_t uid, const beacon_body_t *b, uint8_t out[BEACON_V1_LEN]);
bool beacon_v1_unpack(const uint8_t *frame, size_t len, uint32_t *uid, beacon_body_t *b);

/* ---- v2 ------------------------------------------------------------------ */

void beacon_v2_nonce(uint32_t uid, uint32_t ctr, uint8_t dir, uint8_t out[BEACON_V2_NONCE_LEN]);

/* Seal a frame under the device's beacon key (dev_aes keyed with dev_key).
 * Returns false only on a NULL argument or a CCM refusal. */
bool beacon_v2_seal(const aead_aes_t *dev_aes, uint32_t uid, uint32_t ctr,
                    const beacon_body_t *b, uint8_t out[BEACON_V2_LEN]);

/* uid and counter from the cleartext header, no key needed (a receiver
 * without the key can identify and RSSI-home, never locate). */
bool beacon_v2_peek(const uint8_t *frame, size_t len, uint32_t *uid, uint32_t *ctr);

/* Open and verify. On any failure returns false with *b zeroed. */
bool beacon_v2_open(const aead_aes_t *dev_aes, const uint8_t *frame, size_t len,
                    uint32_t *uid, uint32_t *ctr, beacon_body_t *b);

/* ---- sealed report (0x52) ------------------------------------------------ */

#define BEACON_REPORT_MAGIC     0x52u
#define BEACON_REPORT_OVERHEAD  (BEACON_V2_AAD_LEN + BEACON_V2_TAG_LEN)            /* 17: header + tag */
#define BEACON_REPORT_MAX_LEN   255u                                               /* one LoRa packet */
#define BEACON_REPORT_MIN_BODY  1u
#define BEACON_REPORT_MAX_BODY  (BEACON_REPORT_MAX_LEN - BEACON_REPORT_OVERHEAD)   /* 238 */
#define BEACON_REPORT_MIN_LEN   (BEACON_REPORT_MIN_BODY + BEACON_REPORT_OVERHEAD)  /* 18 */

/* Seal body[0..body_len) (1..BEACON_REPORT_MAX_BODY bytes) into a report
 * frame of body_len + BEACON_REPORT_OVERHEAD bytes at out (out_cap at least
 * that). body is either out + BEACON_V2_AAD_LEN (sealed in place: encode the
 * payload there, nothing is copied) or a buffer that does not overlap out.
 * Returns the frame length, or 0 with nothing written for a NULL argument, a
 * body length out of range or a short out (with out zeroed for a CCM
 * refusal, which those checks rule out). Heap-free: the stack is the
 * nonce plus aead_ccm's 16-byte blocks, whatever the length. */
size_t beacon_report_seal(const aead_aes_t *dev_aes, uint32_t uid, uint32_t ctr,
                          const uint8_t *body, size_t body_len,
                          uint8_t *out, size_t out_cap);

/* uid and counter from the cleartext header, no key needed: a receiver
 * without the key still learns which collar and its counter (a "locked"
 * row), never the report. false unless magic 0x52 and length 18..255. */
bool beacon_report_peek(const uint8_t *frame, size_t len, uint32_t *uid, uint32_t *ctr);

/* Open and verify a report frame into body (body_cap at least
 * len - BEACON_REPORT_OVERHEAD). body may be frame + BEACON_V2_AAD_LEN
 * (opened in place) or must not overlap the frame. Returns the body length
 * (1..238), *uid and *ctr set; or 0, *uid and *ctr untouched, for a NULL
 * argument, a frame that is not a report, a short body buffer (nothing
 * written) or a frame that does not authenticate (body[0..len-17) zeroed:
 * nothing of the plaintext is left behind). */
size_t beacon_report_open(const aead_aes_t *dev_aes, const uint8_t *frame, size_t len,
                          uint32_t *uid, uint32_t *ctr, uint8_t *body, size_t body_cap);

/* ---- keys ---------------------------------------------------------------- */

/* The 17-byte KDF input for a purpose: label || uid_le32 || gen. */
bool beacon_kdf_input(beacon_key_purpose_t purpose, uint32_t uid, uint8_t gen,
                      uint8_t out[BEACON_KDF_INPUT_LEN]);

/* dev_key = AES-CMAC(master, kdf_input); master_aes is keyed with the master
 * of that purpose (beacon master or command master: two independent keys). */
bool beacon_kdf(const aead_aes_t *master_aes, beacon_key_purpose_t purpose,
                uint32_t uid, uint8_t gen, uint8_t out_key[BEACON_KEY_LEN]);

/* Key check value: AES(key, 0^16)[0..2]. Loggable; proves a key landed. */
void beacon_kcv(const aead_aes_t *dev_aes, uint8_t out[BEACON_KCV_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* BEACON_FRAME_H */
