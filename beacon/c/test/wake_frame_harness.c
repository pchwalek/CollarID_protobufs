/*
 * wake_frame_harness.c — runs beacon/c/wake_frame.c for the host test
 * (beacon/test_wake_frame_c.py), which feeds it the vectors of
 * beacon/vectors.json one line at a time and compares every answer with the
 * Python reference. Test code only: nothing here goes into a firmware.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -I.. wake_frame_harness.c \
 *      ../wake_frame.c ../aead_ccm.c ../direct_rules.c ../direct_rules_table.c \
 *      -o wake_frame_harness
 *
 * One command per line on stdin, one answer per line on stdout; numbers are
 * decimal, bytes lower-case hex, "-" stands for "none".
 *
 *   tag UID                                  -> tag
 *   parse HEX                                -> ok FLAGS LEFT K T0 T1 T2 T3 | err CODE
 *   build FLAGS LEFT K T0 T1 T2 T3           -> HEX | err
 *   verdict HEX UID                          -> 0..3 | err CODE
 *   resolve SETTING LORAWAN|- MHZ            -> region
 *   channel REGION LONG                      -> HZ KHZ SF DBM | none
 *   timing SF KHZ                            -> ts frame tail w cap intent cmd rollwait slotmin slotdefault
 *   toa SF KHZ N PREAMBLE                    -> us
 *   train SF KHZ INTERVAL GAP_US             -> us frames
 *   clamp S                                  -> s
 *   left US                                  -> units
 *   kdfin GROUP GEN                          -> HEX (17 B)
 *   kdf MASTER GROUP GEN                     -> HEX (16 B)
 *   seal KEY GROUP CTR FROM TO SLOTS MS FLAGS -> HEX (29 B)
 *   open KEY HEX                             -> ok GROUP CTR FROM TO SLOTS MS FLAGS | fail
 *   check KEY|- GROUP GEN LAST NOW|- SF KHZ SINCE|- HEX -> CODE [CTR SLOTS MS]
 *   slot UID CTR SLOTS MS                    -> slot delay_ms listen_ms
 *
 * The AES-128 forward cipher below is for this harness only (its S-box is
 * computed from the definition, so there is no table to mistype); the Python
 * test checks it against FIPS-197 C.1 through the "aes" command.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead_ccm.h"
#include "wake_frame.h"

/* ---- AES-128, forward direction only (test only) -------------------------- */

static uint8_t g_sbox[256];

static uint8_t xtime(uint8_t a)
{
	return (uint8_t)((a << 1) ^ ((a & 0x80u) ? 0x1Bu : 0u));
}

static uint8_t rotl8(uint8_t v, unsigned n)
{
	return (uint8_t)((v << n) | (v >> (8u - n)));
}

static void sbox_init(void)
{
	uint8_t p = 1, q = 1;
	do {
		p = (uint8_t)(p ^ (uint8_t)(p << 1) ^ ((p & 0x80u) ? 0x1Bu : 0u));   /* p *= 3 */
		q ^= (uint8_t)(q << 1);                                               /* q /= 3 */
		q ^= (uint8_t)(q << 2);
		q ^= (uint8_t)(q << 4);
		if (q & 0x80u) q ^= 0x09u;
		g_sbox[p] = (uint8_t)(q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63u);
	} while (p != 1);
	g_sbox[0] = 0x63u;
}

typedef struct {
	uint8_t rk[176];
} aes128_t;

static void aes128_key(aes128_t *a, const uint8_t key[16])
{
	uint8_t rcon = 1;
	memcpy(a->rk, key, 16);
	for (unsigned i = 16; i < 176; i += 4) {
		uint8_t t[4];
		memcpy(t, &a->rk[i - 4], 4);
		if (i % 16 == 0) {
			const uint8_t t0 = t[0];
			t[0] = (uint8_t)(g_sbox[t[1]] ^ rcon);
			t[1] = g_sbox[t[2]];
			t[2] = g_sbox[t[3]];
			t[3] = g_sbox[t0];
			rcon = xtime(rcon);
		}
		for (unsigned j = 0; j < 4; j++) a->rk[i + j] = (uint8_t)(a->rk[i - 16 + j] ^ t[j]);
	}
}

static void aes128_block(void *ctx, const uint8_t in[16], uint8_t out[16])
{
	const aes128_t *a = (const aes128_t *)ctx;
	uint8_t s[16], t[16];

	for (unsigned i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ a->rk[i]);
	for (unsigned rnd = 1; rnd <= 10; rnd++) {
		/* SubBytes and ShiftRows: byte i is row i % 4 of column i / 4. */
		for (unsigned i = 0; i < 16; i++) t[i] = g_sbox[s[(i % 4) + 4 * ((i / 4 + i % 4) % 4)]];
		if (rnd != 10) {
			for (unsigned c = 0; c < 4; c++) {
				const uint8_t *x = &t[4 * c];
				s[4 * c + 0] = (uint8_t)(xtime(x[0]) ^ xtime(x[1]) ^ x[1] ^ x[2] ^ x[3]);
				s[4 * c + 1] = (uint8_t)(x[0] ^ xtime(x[1]) ^ xtime(x[2]) ^ x[2] ^ x[3]);
				s[4 * c + 2] = (uint8_t)(x[0] ^ x[1] ^ xtime(x[2]) ^ xtime(x[3]) ^ x[3]);
				s[4 * c + 3] = (uint8_t)(xtime(x[0]) ^ x[0] ^ x[1] ^ x[2] ^ xtime(x[3]));
			}
		} else {
			memcpy(s, t, 16);
		}
		for (unsigned i = 0; i < 16; i++) s[i] ^= a->rk[16 * rnd + i];
	}
	memcpy(out, s, 16);
}

/* ---- line parsing --------------------------------------------------------- */

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Hex into buf; returns the byte count, or -1 for a bad string. "-" is 0 bytes. */
static int unhex(const char *s, uint8_t *buf, size_t cap)
{
	size_t n = strlen(s);
	if (strcmp(s, "-") == 0) return 0;
	if (n % 2 != 0 || n / 2 > cap) return -1;
	for (size_t i = 0; i < n / 2; i++) {
		const int hi = hex_nibble(s[2 * i]), lo = hex_nibble(s[2 * i + 1]);
		if (hi < 0 || lo < 0) return -1;
		buf[i] = (uint8_t)((hi << 4) | lo);
	}
	return (int)(n / 2);
}

static void put_hex(const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
	printf("\n");
}

static uint32_t u32(const char *s)
{
	return (uint32_t)strtoul(s, NULL, 0);
}

#define MAX_ARGS 12

int main(void)
{
	char line[1024];

	sbox_init();
	while (fgets(line, sizeof(line), stdin)) {
		char *argv[MAX_ARGS];
		int argc = 0;
		for (char *tok = strtok(line, " \r\n"); tok && argc < MAX_ARGS; tok = strtok(NULL, " \r\n")) {
			argv[argc++] = tok;
		}
		if (argc == 0) continue;
		const char *cmd = argv[0];

		if (strcmp(cmd, "aes") == 0 && argc == 3) {
			uint8_t key[16], in[16], out[16];
			aes128_t a;
			if (unhex(argv[1], key, 16) != 16 || unhex(argv[2], in, 16) != 16) { printf("err\n"); continue; }
			aes128_key(&a, key);
			aes128_block(&a, in, out);
			put_hex(out, 16);
		} else if (strcmp(cmd, "tag") == 0 && argc == 2) {
			printf("%u\n", (unsigned)wake_tag(u32(argv[1])));
		} else if (strcmp(cmd, "parse") == 0 && argc == 2) {
			uint8_t frame[64];
			wake_frame_t f;
			const int n = unhex(argv[1], frame, sizeof(frame));
			const wake_frame_result_t r = wake_frame_parse(frame, n < 0 ? 0u : (size_t)n, &f);
			if (r != WAKE_FRAME_OK) {
				printf("err %d\n", (int)r);
			} else {
				printf("ok %u %u %u %u %u %u %u\n", (unsigned)f.flags, (unsigned)f.time_left_10ms,
				       (unsigned)f.k, (unsigned)f.tags[0], (unsigned)f.tags[1], (unsigned)f.tags[2],
				       (unsigned)f.tags[3]);
			}
		} else if (strcmp(cmd, "build") == 0 && argc == 8) {
			wake_frame_t f;
			uint8_t out[WAKE_FRAME_MAX_LEN];
			size_t n;
			memset(&f, 0, sizeof(f));
			f.flags = (uint8_t)u32(argv[1]);
			f.time_left_10ms = (uint16_t)u32(argv[2]);
			f.k = (uint8_t)u32(argv[3]);
			for (int i = 0; i < 4; i++) f.tags[i] = (uint16_t)u32(argv[4 + i]);
			n = wake_frame_build(&f, out);
			if (n == 0) printf("err\n"); else put_hex(out, n);
		} else if (strcmp(cmd, "verdict") == 0 && argc == 3) {
			uint8_t frame[64];
			wake_frame_t f;
			const int n = unhex(argv[1], frame, sizeof(frame));
			const wake_frame_result_t r = wake_frame_parse(frame, n < 0 ? 0u : (size_t)n, &f);
			if (r != WAKE_FRAME_OK) printf("err %d\n", (int)r);
			else printf("%d\n", (int)wake_frame_verdict(&f, u32(argv[2])));
		} else if (strcmp(cmd, "resolve") == 0 && argc == 4) {
			const bool lw = strcmp(argv[2], "-") != 0;
			printf("%u\n", (unsigned)wake_region_resolve(u32(argv[1]), lw, lw ? u32(argv[2]) : 0u, u32(argv[3])));
		} else if (strcmp(cmd, "channel") == 0 && argc == 3) {
			wake_channel_t ch;
			if (!wake_channel((uint8_t)u32(argv[1]), u32(argv[2]) != 0u, &ch)) printf("none\n");
			else printf("%" PRIu32 " %u %u %d\n", ch.frequency_hz, (unsigned)ch.bw_khz, (unsigned)ch.sf, (int)ch.max_dbm);
		} else if (strcmp(cmd, "timing") == 0 && argc == 3) {
			const uint8_t sf = (uint8_t)u32(argv[1]);
			const uint16_t bw = (uint16_t)u32(argv[2]);
			printf("%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32
			       " %" PRIu32 " %" PRIu32 " %u\n",
			       wake_symbol_us(sf, bw), wake_frame_us(sf, bw), wake_tail_us(sf, bw), wake_window_us(sf, bw),
			       wake_cap_us(sf, bw), wake_intent_wait_us(sf, bw), wake_cmd_window_us(sf, bw),
			       roll_call_wait_us(sf, bw), roll_call_slot_min_us(sf, bw),
			       (unsigned)roll_call_slot_default_ms(sf, bw));
		} else if (strcmp(cmd, "toa") == 0 && argc == 5) {
			printf("%" PRIu32 "\n", wake_toa_us((uint8_t)u32(argv[1]), (uint16_t)u32(argv[2]),
			                                    (uint16_t)u32(argv[3]), (uint16_t)u32(argv[4])));
		} else if (strcmp(cmd, "train") == 0 && argc == 5) {
			const uint8_t sf = (uint8_t)u32(argv[1]);
			const uint16_t bw = (uint16_t)u32(argv[2]);
			printf("%" PRIu32 " %" PRIu32 "\n", wake_train_us(sf, bw, u32(argv[3])),
			       wake_train_frames(sf, bw, u32(argv[3]), u32(argv[4])));
		} else if (strcmp(cmd, "clamp") == 0 && argc == 2) {
			printf("%" PRIu32 "\n", wake_interval_clamp(u32(argv[1])));
		} else if (strcmp(cmd, "left") == 0 && argc == 2) {
			printf("%u\n", (unsigned)wake_time_left_10ms(u32(argv[1])));
		} else if (strcmp(cmd, "kdfin") == 0 && argc == 3) {
			uint8_t in[WAKE_KDF_INPUT_LEN];
			wake_kdf_input(u32(argv[1]), (uint8_t)u32(argv[2]), in);
			put_hex(in, sizeof(in));
		} else if (strcmp(cmd, "kdf") == 0 && argc == 4) {
			uint8_t master[16], key[WAKE_KEY_LEN];
			aes128_t a;
			aead_aes_t aes = { aes128_block, &a };
			if (unhex(argv[1], master, 16) != 16) { printf("err\n"); continue; }
			aes128_key(&a, master);
			if (!wake_kdf(&aes, u32(argv[2]), (uint8_t)u32(argv[3]), key)) { printf("err\n"); continue; }
			put_hex(key, sizeof(key));
		} else if (strcmp(cmd, "seal") == 0 && argc == 9) {
			uint8_t key[16], out[ROLL_CALL_LEN];
			aes128_t a;
			aead_aes_t aes = { aes128_block, &a };
			roll_call_body_t b;
			if (unhex(argv[1], key, 16) != 16) { printf("err\n"); continue; }
			aes128_key(&a, key);
			b.valid_from = u32(argv[4]);
			b.valid_to = u32(argv[5]);
			b.slots = (uint8_t)u32(argv[6]);
			b.slot_ms = (uint16_t)u32(argv[7]);
			b.flags = (uint8_t)u32(argv[8]);
			if (!roll_call_seal(&aes, u32(argv[2]), u32(argv[3]), &b, out)) { printf("err\n"); continue; }
			put_hex(out, sizeof(out));
		} else if (strcmp(cmd, "open") == 0 && argc == 3) {
			uint8_t key[16], frame[64];
			aes128_t a;
			aead_aes_t aes = { aes128_block, &a };
			roll_call_body_t b;
			uint32_t group = 0, ctr = 0;
			const int n = unhex(argv[2], frame, sizeof(frame));
			if (unhex(argv[1], key, 16) != 16) { printf("err\n"); continue; }
			aes128_key(&a, key);
			if (!roll_call_open(&aes, frame, n < 0 ? 0u : (size_t)n, &group, &ctr, &b)) {
				printf("fail\n");
			} else {
				printf("ok %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %u %u %u\n", group, ctr,
				       b.valid_from, b.valid_to, (unsigned)b.slots, (unsigned)b.slot_ms, (unsigned)b.flags);
			}
		} else if (strcmp(cmd, "check") == 0 && argc == 10) {
			uint8_t key[16], frame[64];
			aes128_t a;
			aead_aes_t aes = { aes128_block, &a };
			roll_call_body_t b;
			uint32_t ctr = 0;
			const bool keyed = strcmp(argv[1], "-") != 0;
			const bool clock = strcmp(argv[5], "-") != 0;
			const uint32_t since = strcmp(argv[8], "-") != 0 ? u32(argv[8]) : ROLL_CALL_NEVER;
			const int n = unhex(argv[9], frame, sizeof(frame));
			roll_call_result_t r;
			if (keyed) {
				if (unhex(argv[1], key, 16) != 16) { printf("err\n"); continue; }
				aes128_key(&a, key);
			}
			r = roll_call_check(keyed ? &aes : NULL, u32(argv[2]), (uint8_t)u32(argv[3]), u32(argv[4]),
			                    clock, clock ? u32(argv[5]) : 0u, (uint8_t)u32(argv[6]), (uint16_t)u32(argv[7]),
			                    since, frame, n < 0 ? 0u : (size_t)n, &ctr, &b);
			if (r == ROLL_CALL_OK) printf("0 %" PRIu32 " %u %u\n", ctr, (unsigned)b.slots, (unsigned)b.slot_ms);
			else printf("%d\n", (int)r);
		} else if (strcmp(cmd, "slot") == 0 && argc == 5) {
			const uint8_t slots = (uint8_t)u32(argv[3]);
			const uint16_t ms = (uint16_t)u32(argv[4]);
			printf("%u %" PRIu32 " %" PRIu32 "\n", (unsigned)roll_call_slot(u32(argv[1]), u32(argv[2]), slots),
			       roll_call_reply_delay_ms(u32(argv[1]), u32(argv[2]), slots, ms),
			       roll_call_listen_ms(slots, ms));
		} else {
			printf("unknown\n");
		}
	}
	return 0;
}
