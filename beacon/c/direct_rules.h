/*
 * direct_rules.h — direct-radio regions: which channels a collar or a
 * CollarID Spotter may use in a country, at what power, how long one send
 * may last, whether it must listen first, and how much air time it may use
 * in an hour.
 *
 * Contract: collarID_thread docs/CONTRACT_direct_regions.md (2026-11-17).
 * The table is data: CollarID_protobufs contracts/collarid_contracts.json,
 * key direct_regions, generated into direct_rules_table.c (never edit that
 * file; change the spec and run contracts/generate.py). The reference is
 * contracts/reference.py (dr_*), the vectors test_vectors/contracts_v1.json
 * section direct_regions; beacon/test_direct_rules_c.py holds this code to
 * every vector, as C99 and as C++.
 *
 * The collar firmware (Core/Src, Core/Inc) and the Spotter
 * (src/beacon/upstream/) carry byte-identical copies of direct_rules.[ch]
 * and direct_rules_table.c, as they do wake_frame.[ch]; wake_frame.c reads
 * its wake channels and regions from here.
 *
 * Units: frequencies in kHz (the wake channel in Hz), power in centi-dBm
 * (cdBm, 1615 = 16.15 dBm) for limits and whole dBm for radios, antenna
 * gain in centi-dBi (cdBi), time on air in microseconds, air budgets in ms
 * per hour, clocks in whole seconds. Integer arithmetic only; no heap, no
 * float, no HAL. C99, and compiles as C++.
 *
 * A rule set is a DirectRegion value of ble.proto (1..15). A NULL rule set
 * (dr_rule_set(0), or an id the table does not hold) is "no region": every
 * check passes and nothing changes, as before regions existed.
 */
#ifndef DIRECT_RULES_H
#define DIRECT_RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- rule-set ids: ble.proto DirectRegion (the wire numbers) ----------- */

#define DR_REGION_NONE    0u    /* AUTO as a setting; "no region" once resolved */
#define DR_REGION_US915   1u
#define DR_REGION_EU868   2u
#define DR_REGION_AU915   3u
#define DR_REGION_BR915   4u
#define DR_REGION_LA915   5u
#define DR_REGION_IN865   6u
#define DR_REGION_JP920   7u
#define DR_REGION_KR920   8u
#define DR_REGION_SG920   9u
#define DR_REGION_MY919   10u
#define DR_REGION_TH920   11u
#define DR_REGION_VN920   12u
#define DR_REGION_ID920   13u
#define DR_REGION_TW920   14u
#define DR_REGION_RU868   15u
#define DR_REGION_MAX     15u   /* a setting above this is no region */

/* ---- constants (the spec's direct_regions.constants) -------------------- */

#define DR_MAX_BANDS            6u      /* capacity: the most bands of any rule set (EU868: K L M N O Q) */
#define DR_SF_MIN               7u
#define DR_SF_MAX               12u
#define DR_NORMAL_SHARE_PCT     75u     /* everything but beacons may use 75 % of a budget */
#define DR_BASE_FRAME_BYTES     64u     /* the frame a setting must carry inside a send limit */
#define DR_PREAMBLE_SYMBOLS     8u
#define DR_LBT_SAMPLE_MAX_MS    1u      /* listen: RSSI at least every 1 ms for the band's lbt_ms */
#define DR_LBT_BACKOFF_MIN_MS   20u     /* busy: wait a random 20..200 ms and listen again */
#define DR_LBT_BACKOFF_MAX_MS   200u
#define DR_LBT_GIVE_UP_S        20u     /* after 20 s of busy channel the send is delayed, never dropped */
#define DR_BUCKET_S             60u     /* the air account: one-minute buckets ... */
#define DR_AIR_BUCKETS          60u     /* ... 60 whole minutes ... */
#define DR_AIR_SLOTS            (DR_AIR_BUCKETS + 1u)   /* ... plus the current one: 61 */
#define DR_DEFAULT_CODING_RATE  0u      /* ble.proto cr_4_5, on every default channel */
#define DR_DEFAULT_SYNC_WORD    0x12u
#define DR_WAIT_NEVER           0xFFFFFFFFu   /* dr_air_wait_s: the send alone is over its class limit */

/* Bandwidth bits of dr_band_t.bw_mask. */
#define DR_BW_125               0x01u
#define DR_BW_250               0x02u
#define DR_BW_500               0x04u

/* Why a new setting is refused (dr_check), in the order judged; the
 * vectors' reason names, in the same order. */
typedef enum {
	DR_OK          = 0,
	DR_NO_BAND     = 1,   /* no band holds the whole channel                     */
	DR_BANDWIDTH   = 2,   /* a band holds it but allows no such bandwidth         */
	DR_GRID        = 3,   /* ... allows it but the centre is off its grid         */
	DR_POWER_FLOOR = 4,   /* ... on grid but the device cannot go low enough      */
	DR_FRAME_TIME  = 5    /* ... usable but a 64-byte frame is not shorter than
	                         the band's send limit                               */
} dr_reason_t;

/* Who is sending, for the hourly air budget. */
typedef enum {
	DR_CLASS_NORMAL = 0,  /* reports, ACKs, replies, sessions, wake trains ...: 75 % */
	DR_CLASS_BEACON = 1   /* the lost-mode beacon and find-mode beacons: 100 %       */
} dr_class_t;

/* What dr_convert did. */
typedef enum {
	DR_KEPT    = 0,       /* the setting passes the check with the generic device */
	DR_MOVED   = 1,       /* moved onto the nearest legal channel of a band       */
	DR_DEFAULT = 2        /* the rule set's default channel (all three values)    */
} dr_how_t;

/* dr_schedule_need's verdict. */
typedef enum {
	DR_FIT_FITS        = 0,
	DR_FIT_NO_BUDGET   = 1,   /* fits: the band has no budget (or no region / no band) */
	DR_FIT_NORMAL_OVER = 2,   /* refused: the non-beacon part is over 75 %             */
	DR_FIT_TOTAL_OVER  = 3    /* refused: the whole is over the budget                 */
} dr_fit_t;

/* A country's confidence (dr_country_t.confidence). */
typedef enum {
	DR_CONF_PRIMARY = 0,  /* the regulator's text was read                      */
	DR_CONF_CEPT    = 1,  /* follows ERC/REC 70-03; the national text not read  */
	DR_CONF_LOW     = 2   /* rules partly unknown; the safe reading             */
} dr_confidence_t;

/* ---- the table (direct_rules_table.c, generated) ------------------------ */

/* One band of a rule set. A channel is legal in it when it lies wholly
 * inside lo..hi, at a bandwidth of bw_mask, on the grid when there is one. */
typedef struct {
	const char *name;          /* "K", "902-928", ... (for logs) */
	uint32_t lo_khz;
	uint32_t hi_khz;
	uint32_t grid_base_khz;    /* a centre is base + k x step; step 0 = no grid */
	uint32_t grid_step_khz;
	uint32_t budget_ms_per_h;  /* hourly air budget; 0 = none */
	int16_t  eirp_cdbm;        /* most e.i.r.p. */
	int16_t  lbt_dbm;          /* listen-before-talk threshold, when lbt_ms > 0 */
	uint16_t max_send_ms;      /* one send shorter than this; 0 = no limit */
	uint16_t pause_ms;         /* off on the channel after a send, with max_send_ms */
	uint8_t  bw_mask;          /* DR_BW_* */
	int8_t   conducted_dbm;    /* most conducted power at the radio */
	uint8_t  lbt_ms;           /* listen this long first; 0 = no listen-before-talk */
} dr_band_t;

/* A direct-radio setting. */
typedef struct {
	uint32_t freq_khz;
	uint16_t bw_khz;
	uint8_t  sf;
} dr_setting_t;

typedef struct {
	uint8_t            id;           /* DR_REGION_* */
	const char        *key;          /* "US915" */
	const char        *name;         /* "United States, Canada, Mexico" */
	uint8_t            band_count;   /* 1..DR_MAX_BANDS */
	const dr_band_t   *bands;
	dr_setting_t       def;          /* the default channel (contract section 10) */
	uint32_t           wake_freq_hz; /* the wake channel (contract section 9) */
	uint16_t           wake_bw_khz;
	uint8_t            wake_sf;
	uint8_t            wake_sf_long;
} dr_rule_set_t;

/* A sending device: its antenna gain and the lowest and highest conducted
 * power its radio can send. The caller fills one (the Spotter: the gain of
 * its current antenna profile) or uses a named profile below. */
typedef struct {
	int16_t gain_cdbi;
	int8_t  min_dbm;
	int8_t  max_dbm;
} dr_device_t;

typedef struct {
	char        iso[3];        /* ISO 3166 alpha-2, NUL-terminated */
	uint8_t     rule_set;      /* DR_REGION_* */
	uint8_t     confidence;    /* dr_confidence_t */
	const char *name;          /* English */
} dr_country_t;

extern const dr_rule_set_t dr_rule_sets[];     /* in id order */
extern const uint8_t       dr_rule_set_count;
extern const dr_country_t  dr_countries[];     /* the spec's order (grouped by rule set) */
extern const uint8_t       dr_country_count;
extern const dr_device_t   dr_device_collar_wio;   /* gain 90 cdBi, -9..22 dBm */
extern const dr_device_t   dr_device_collar_mk3;   /* gain 90 cdBi, 16..27 dBm (SE2435L) */
extern const dr_device_t   dr_device_spotter;      /* stub antenna 200 cdBi, -9..22 dBm */
extern const dr_device_t   dr_device_generic;      /* website and app; convert() uses it */
extern const dr_setting_t  dr_no_region_default;   /* today's (US) default: 915000 / 500 / 9 */
/* sha256 of the whole contracts spec (CONTRACTS_SHA256 of the generated
 * files) and of its direct_regions section alone, lower-case hex: a repo's
 * test compares them with its vendored spec, so a stale copy fails there. */
extern const char dr_contracts_sha256[65];
extern const char dr_table_sha256[65];

/* ---- lookups -------------------------------------------------------------- */

/* The rule set of an id; NULL for 0 and any id the table does not hold. */
const dr_rule_set_t *dr_rule_set(uint32_t id);
/* ... of a key ("JP920"); NULL when none. */
const dr_rule_set_t *dr_rule_set_by_key(const char *key);
/* A band of a rule set; NULL for a NULL rule set or an index outside it. */
const dr_band_t *dr_band(const dr_rule_set_t *rs, int band);
/* A country by ISO code ("JP"); NULL when it is not offered. */
const dr_country_t *dr_country(const char *iso);

/* DR_BW_* of 125, 250 or 500 kHz; 0 for anything else. */
uint8_t dr_bw_bit(uint16_t bw_khz);
/* Half a channel, rounded up to the kHz: 63, 125, 250. */
uint16_t dr_half_khz(uint16_t bw_khz);

/* The first band (table order) that holds the whole channel
 * (lo + h <= freq <= hi - h), whatever bandwidths it allows; -1 = none.
 * An air account records a send (a LoRaWAN uplink too) in this band. */
int dr_band_of(const dr_rule_set_t *rs, uint32_t freq_khz, uint16_t bw_khz);

/* ---- power ---------------------------------------------------------------- */

/* The most a device may send in a band, whole dBm:
 *   min(band conducted, floor((band e.i.r.p. - gain) / 100), device max).
 * *usable (may be NULL) is false when that is below the device's minimum:
 * the device does not send there at all. A NULL rule set or no band gives
 * the device's maximum, usable. dev NULL = dr_device_generic. Every send
 * goes out at min(its setting, this). */
int8_t dr_power_cap(const dr_rule_set_t *rs, int band, const dr_device_t *dev, bool *usable);

/* ---- checking and converting a setting ------------------------------------ */

/* A NEW setting (contract section 4). Each band is judged in this order: it
 * holds the whole channel, allows the bandwidth, has the centre on its grid,
 * is usable by the device, and a 64-byte frame at (sf, bw) is shorter than
 * its send limit. DR_OK when one band passes all five, else the reason of
 * the band that got furthest. Power is never a reason. A NULL rule set is
 * DR_OK. dev NULL = dr_device_generic. An SF outside 7..12 never fits a
 * band with a send limit and is otherwise not judged. */
dr_reason_t dr_check(const dr_rule_set_t *rs, uint8_t sf, uint16_t bw_khz, uint32_t freq_khz,
                     const dr_device_t *dev);

/* A SAVED setting (contract section 5), independent of the device:
 *  1. it passes dr_check with dr_device_generic: unchanged (DR_KEPT);
 *  2. no band holds the frequency (lo <= freq <= hi): the default channel
 *     (DR_DEFAULT);
 *  3. per holding band: the bandwidth if allowed, else the smallest allowed
 *     wider, else the largest allowed narrower; sf + one step per doubling
 *     (one down per halving), held to 7..12; the nearest legal centre (grid
 *     points; else whole MHz when the input is a whole MHz and one fits;
 *     else every kHz), ties to the lower;
 *  4. the band whose new centre is nearest the old frequency, ties to the
 *     higher e.i.r.p., then the lower lo (DR_MOVED); none with a legal
 *     centre: the default channel (DR_DEFAULT);
 *  5. with a send limit: sf lowered (not below 7) until a 64-byte frame fits.
 * A bandwidth that is not 125, 250 or 500 is read as the next of them up
 * (at most 500). Coding rate and sync word never change. */
dr_how_t dr_convert(const dr_rule_set_t *rs, uint8_t sf, uint16_t bw_khz, uint32_t freq_khz,
                    dr_setting_t *out);

/* The default channel of a rule set (contract section 10); a NULL rule set
 * gives dr_no_region_default. CR 4/5 and sync word 0x12 on all of them. */
void dr_default_channel(const dr_rule_set_t *rs, dr_setting_t *out);

/* ---- time on air, send limit, listen before talk -------------------------- */

/* Microseconds on air of a len-byte frame: coding rate 4/5, explicit header,
 * CRC on, low data rate optimisation when the symbol is longer than 16 ms,
 * preamble 8 (dr_toa_us) or as given. wake_toa_us, bit for bit. 0 outside
 * SF7..12, 125/250/500 kHz, 0..255 bytes, preamble 0..1024. */
uint32_t dr_toa_us(uint8_t sf, uint16_t bw_khz, uint16_t len);
uint32_t dr_toa_preamble_us(uint8_t sf, uint16_t bw_khz, uint16_t len, uint16_t preamble);
/* A len-byte frame is shorter than max_send_ms on air (0 = no limit: true).
 * A setting with no time on air never fits a limit. */
bool dr_frame_fits(uint8_t sf, uint16_t bw_khz, uint16_t len, uint32_t max_send_ms);
/* The longest payload, 0..255, shorter than max_send_ms (255 for 0 = no
 * limit); -1 when none is, or (sf, bw) is not a LoRa setting. */
int16_t dr_max_len(uint8_t sf, uint16_t bw_khz, uint32_t max_send_ms);
/* ... under a band's send limit (255 for a band without one or no band). */
int16_t dr_band_max_len(const dr_rule_set_t *rs, int band, uint8_t sf, uint16_t bw_khz);
/* A band's listen-before-talk: true with the threshold (dBm) and the listen
 * time (ms) when it has one. Pointers may be NULL. */
bool dr_lbt(const dr_rule_set_t *rs, int band, int16_t *dbm, uint8_t *ms);
/* A band's send limit: true with the longest send and the pause after it
 * (ms) when it has one. Pointers may be NULL. */
bool dr_send_limit(const dr_rule_set_t *rs, int band, uint16_t *max_send_ms, uint16_t *pause_ms);

/* ---- the hourly air account (contract section 8) -------------------------- */

/* The caller owns one per device (RAM; empty after a restart), bound to one
 * rule set; re-init it when the rule set changes. Per band, the ms sent in
 * each of the last 60 whole minutes and in the current one (61 slots: up to
 * 61 minutes, conservative). now_s is whole seconds on a clock that never
 * goes back (uptime); its minute is now_s / 60. Bands without a budget are
 * not tracked: used 0, wait 0. ~1.5 KB. */
typedef struct {
	const dr_rule_set_t *rs;
	uint32_t minute;                              /* now_s / 60 of the newest slot */
	bool     started;                             /* false until the first record */
	uint32_t ms[DR_MAX_BANDS][DR_AIR_SLOTS];      /* [band][minute % 61] */
} dr_air_t;

void dr_air_init(dr_air_t *a, const dr_rule_set_t *rs);
/* The most a class may have used in the hour: the budget (beacon), 75 % of
 * it rounded down (normal); 0 for a band without one. */
uint32_t dr_air_limit_ms(const dr_rule_set_t *rs, int band, dr_class_t cls);
/* Count a send of ms in a band (dr_band_of its channel): every send,
 * reports, beacons, ACKs, replies, session frames, wake trains, INTENTs,
 * roll calls; on the collar also LoRaWAN uplinks in the band. Record it
 * when it ends, with now_s = its end. A clock that went back records into
 * the newest minute. */
void dr_air_record(dr_air_t *a, int band, uint32_t now_s, uint32_t ms);
/* The ms used in the window ending at now_s. */
uint32_t dr_air_used_ms(const dr_air_t *a, int band, uint32_t now_s);
/* 0 when an ms-long send of the class fits now; else the whole seconds
 * until enough of the oldest minutes leave the window (minute k leaves at
 * (k + 61) x 60 s); DR_WAIT_NEVER when the send alone is over the class
 * limit (refuse it as a setting). Delay, never drop. */
uint32_t dr_air_wait_s(const dr_air_t *a, int band, uint32_t now_s, uint32_t ms, dr_class_t cls);

/* ---- schedule fit (contract section 8) ------------------------------------ */

typedef struct {
	uint32_t reports_per_h;    /* whole sends an hour: a send every I s is ceil(3600 / I) */
	uint16_t report_bytes;
	uint32_t lost_per_h;       /* lost-mode beacons (when lost mode is on) */
	uint16_t lost_bytes;
	uint32_t find_per_h;       /* find-mode beacons in the hour, when set */
	uint16_t find_bytes;
} dr_need_in_t;

typedef struct {
	int      band;             /* dr_band_of the base channel; -1 = none */
	uint32_t budget_ms;        /* 0 = no budget */
	uint32_t normal_limit_ms;
	uint32_t need_ms;          /* each ms value rounded up from microseconds */
	uint32_t normal_ms;
	uint32_t beacon_ms;
	bool     fits;
	dr_fit_t reason;           /* judged in microseconds: normal first, then the whole */
} dr_need_t;

/* The air a schedule needs per hour in the band of its base channel (sf,
 * bw, freq) and whether it fits. */
void dr_schedule_need(const dr_rule_set_t *rs, uint8_t sf, uint16_t bw_khz, uint32_t freq_khz,
                      const dr_need_in_t *in, dr_need_t *out);

/* ---- regions and the wake channel (contract section 9) -------------------- */

/* The rule set a device runs. setting 1..15 is that rule set; 0 (AUTO)
 * takes the LoRaWAN region when LoRaWAN is configured (lorawan_region, a
 * ble.proto RadioRegion value: 0 US915 -> 1, 1 AU915 -> 3, 2 EU868 -> 2,
 * others none), else the direct radio's frequency: 863000..870000 kHz is
 * EU868, 902000..928000 kHz US915. Anything else, a setting above 15
 * included, is DR_REGION_NONE. */
uint8_t dr_region_resolve(uint32_t setting, bool lorawan_configured, uint32_t lorawan_region,
                          uint32_t freq_khz);

typedef struct {
	uint32_t freq_hz;
	uint16_t bw_khz;
	uint8_t  sf;
	int8_t   max_dbm;          /* the band's cap for dr_device_generic */
} dr_wake_t;

/* A rule set's wake channel, standard or long range. max_dbm is the cap of
 * its band for the generic device; a device caps with dr_power_cap and its
 * own profile. false (with *out zeroed) for a NULL rule set. */
bool dr_wake_channel(const dr_rule_set_t *rs, bool long_range, dr_wake_t *out);

/* ---- the frequency on the wire (contract section 11) ---------------------- */

/* What to write for a frequency: a whole MHz is (MHz, 0); anything else is
 * (the nearest MHz, a half up; the kHz). LoRaConfig frequency /
 * frequency_khz, RadioSettings frequency_mhz / frequency_khz, CONFIG.CSV
 * lora_frequency / lora_frequency_khz. */
void dr_freq_to_fields(uint32_t freq_khz, uint32_t *frequency_mhz, uint32_t *frequency_khz);
/* What a reader takes: frequency_khz when not 0, else the whole MHz (0 for
 * a whole MHz past 32 bits of kHz, which no radio has). */
uint32_t dr_freq_from_fields(uint32_t frequency_mhz, uint32_t frequency_khz);

#ifdef __cplusplus
}
#endif
#endif /* DIRECT_RULES_H */
