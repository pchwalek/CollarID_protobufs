/*
 * direct_rules.c — direct-radio regions: check, convert, power cap, time on
 * air, send limits, the hourly air account, schedule fit, region and wake
 * channel. See direct_rules.h; the table is direct_rules_table.c
 * (generated), the reference contracts/reference.py (dr_*), the vectors
 * test_vectors/contracts_v1.json (direct_regions).
 *
 * Rules this file keeps: integers only (64-bit where a product could pass
 * 32 bits), floor division where the reference floors, no heap, no float,
 * no HAL; C99 that also compiles as C++.
 */
#include "direct_rules.h"

#include <string.h>

static const uint16_t dr_bandwidths[3] = { 125u, 250u, 500u };

/* floor(a / b) for b > 0 (C division truncates toward zero). */
static int64_t dr_floor_div(int64_t a, int64_t b)
{
	int64_t q = a / b;
	if ((a % b) != 0 && a < 0) q--;
	return q;
}

/* ---- lookups -------------------------------------------------------------- */

const dr_rule_set_t *dr_rule_set(uint32_t id)
{
	if (id == 0u) return NULL;
	for (uint8_t i = 0; i < dr_rule_set_count; i++) {
		if (dr_rule_sets[i].id == id) return &dr_rule_sets[i];
	}
	return NULL;
}

const dr_rule_set_t *dr_rule_set_by_key(const char *key)
{
	if (!key) return NULL;
	for (uint8_t i = 0; i < dr_rule_set_count; i++) {
		if (strcmp(dr_rule_sets[i].key, key) == 0) return &dr_rule_sets[i];
	}
	return NULL;
}

const dr_band_t *dr_band(const dr_rule_set_t *rs, int band)
{
	if (!rs || band < 0 || band >= (int)rs->band_count) return NULL;
	return &rs->bands[band];
}

const dr_country_t *dr_country(const char *iso)
{
	if (!iso) return NULL;
	for (uint8_t i = 0; i < dr_country_count; i++) {
		if (strcmp(dr_countries[i].iso, iso) == 0) return &dr_countries[i];
	}
	return NULL;
}

uint8_t dr_bw_bit(uint16_t bw_khz)
{
	switch (bw_khz) {
	case 125u: return (uint8_t)DR_BW_125;
	case 250u: return (uint8_t)DR_BW_250;
	case 500u: return (uint8_t)DR_BW_500;
	default:   return 0u;
	}
}

uint16_t dr_half_khz(uint16_t bw_khz)
{
	return (uint16_t)(((uint32_t)bw_khz + 1u) / 2u);
}

static bool dr_holds(const dr_band_t *b, uint32_t freq_khz, uint16_t bw_khz)
{
	const uint64_t h = dr_half_khz(bw_khz);
	return (uint64_t)b->lo_khz + h <= (uint64_t)freq_khz && (uint64_t)freq_khz + h <= (uint64_t)b->hi_khz;
}

static bool dr_on_grid(const dr_band_t *b, uint32_t freq_khz)
{
	int64_t d;
	if (b->grid_step_khz == 0u) return true;
	d = (int64_t)freq_khz - (int64_t)b->grid_base_khz;
	return d - dr_floor_div(d, (int64_t)b->grid_step_khz) * (int64_t)b->grid_step_khz == 0;
}

int dr_band_of(const dr_rule_set_t *rs, uint32_t freq_khz, uint16_t bw_khz)
{
	if (!rs) return -1;
	for (uint8_t i = 0; i < rs->band_count; i++) {
		if (dr_holds(&rs->bands[i], freq_khz, bw_khz)) return (int)i;
	}
	return -1;
}

/* ---- power ---------------------------------------------------------------- */

/* min(band conducted, floor((e.i.r.p. - gain) / 100)), unclamped. */
static int64_t dr_rule_dbm(const dr_band_t *b, const dr_device_t *dev)
{
	int64_t cap = dr_floor_div((int64_t)b->eirp_cdbm - (int64_t)dev->gain_cdbi, 100);
	if ((int64_t)b->conducted_dbm < cap) cap = b->conducted_dbm;
	return cap;
}

int8_t dr_power_allowed(const dr_rule_set_t *rs, int band, const dr_device_t *dev)
{
	const dr_band_t *b = dr_band(rs, band);
	int64_t cap;

	if (!dev) dev = &dr_device_generic;
	if (!b) return dev->max_dbm;
	cap = dr_rule_dbm(b, dev);
	if (cap < -128) cap = -128;
	if (cap > 127) cap = 127;
	return (int8_t)cap;
}

int8_t dr_power_cap(const dr_rule_set_t *rs, int band, const dr_device_t *dev, bool *usable)
{
	const dr_band_t *b = dr_band(rs, band);
	int64_t cap;

	if (!dev) dev = &dr_device_generic;
	if (!b) {
		if (usable) *usable = true;
		return dev->max_dbm;
	}
	cap = dr_rule_dbm(b, dev);
	if ((int64_t)dev->max_dbm < cap) cap = dev->max_dbm;
	if (cap >= (int64_t)dev->min_dbm) {
		if (usable) *usable = true;
		return (int8_t)cap;
	}
	/* Below the device's floor. old (until 2026-11-17 evening): every
	 * device was unusable here; now a DR_BELOW_FLOOR_SEND device (Mk III)
	 * sends at its minimum. */
	if (dev->below_floor == DR_BELOW_FLOOR_SEND) {
		if (usable) *usable = true;
		return dev->min_dbm;
	}
	if (cap < -128) cap = -128;
	if (usable) *usable = false;
	return (int8_t)cap;
}

/* ---- time on air ----------------------------------------------------------- */

uint32_t dr_toa_preamble_us(uint8_t sf, uint16_t bw_khz, uint16_t len, uint16_t preamble)
{
	uint32_t ts, quarter_symbols;
	int32_t num, den, payload_symbols;

	if (sf < DR_SF_MIN || sf > DR_SF_MAX || dr_bw_bit(bw_khz) == 0u) return 0;
	if (len > 255u || preamble > 1024u) return 0;
	ts = ((uint32_t)1u << sf) * 1000u / bw_khz;          /* exact: a multiple of 4 us */
	den = 4 * ((int32_t)sf - ((ts > 16000u) ? 2 : 0));
	num = 8 * (int32_t)len - 4 * (int32_t)sf + 44;
	payload_symbols = (num > 0) ? ((num + den - 1) / den) * 5 : 0;
	/* (p + 4.25 + 8 + payload) symbols, counted in quarters */
	quarter_symbols = 4u * preamble + 17u + 32u + 4u * (uint32_t)payload_symbols;
	return quarter_symbols * (ts / 4u);
}

uint32_t dr_toa_us(uint8_t sf, uint16_t bw_khz, uint16_t len)
{
	return dr_toa_preamble_us(sf, bw_khz, len, (uint16_t)DR_PREAMBLE_SYMBOLS);
}

bool dr_frame_fits(uint8_t sf, uint16_t bw_khz, uint16_t len, uint32_t max_send_ms)
{
	uint32_t toa;
	if (max_send_ms == 0u) return true;
	toa = dr_toa_us(sf, bw_khz, len);
	return toa != 0u && (uint64_t)toa < (uint64_t)max_send_ms * 1000u;
}

int16_t dr_max_len(uint8_t sf, uint16_t bw_khz, uint32_t max_send_ms)
{
	int16_t best = -1;
	if (dr_toa_us(sf, bw_khz, 0u) == 0u) return -1;
	for (uint16_t n = 0; n <= 255u; n++) {
		if (!dr_frame_fits(sf, bw_khz, n, max_send_ms)) break;
		best = (int16_t)n;
	}
	return best;
}

int16_t dr_band_max_len(const dr_rule_set_t *rs, int band, uint8_t sf, uint16_t bw_khz)
{
	const dr_band_t *b = dr_band(rs, band);
	return dr_max_len(sf, bw_khz, b ? b->max_send_ms : 0u);
}

bool dr_lbt(const dr_rule_set_t *rs, int band, int16_t *dbm, uint8_t *ms)
{
	const dr_band_t *b = dr_band(rs, band);
	if (!b || b->lbt_ms == 0u) return false;
	if (dbm) *dbm = b->lbt_dbm;
	if (ms) *ms = b->lbt_ms;
	return true;
}

bool dr_send_limit(const dr_rule_set_t *rs, int band, uint16_t *max_send_ms, uint16_t *pause_ms)
{
	const dr_band_t *b = dr_band(rs, band);
	if (!b || b->max_send_ms == 0u) return false;
	if (max_send_ms) *max_send_ms = b->max_send_ms;
	if (pause_ms) *pause_ms = b->pause_ms;
	return true;
}

/* ---- check ------------------------------------------------------------------ */

dr_reason_t dr_check(const dr_rule_set_t *rs, uint8_t sf, uint16_t bw_khz, uint32_t freq_khz,
                     const dr_device_t *dev)
{
	int best = (int)DR_NO_BAND;

	if (!rs) return DR_OK;
	if (!dev) dev = &dr_device_generic;
	for (uint8_t i = 0; i < rs->band_count; i++) {
		const dr_band_t *b = &rs->bands[i];
		bool usable = false;
		int stage;

		if (!dr_holds(b, freq_khz, bw_khz)) {
			stage = (int)DR_NO_BAND;
		} else if ((b->bw_mask & dr_bw_bit(bw_khz)) == 0u) {
			stage = (int)DR_BANDWIDTH;
		} else if (!dr_on_grid(b, freq_khz)) {
			stage = (int)DR_GRID;
		} else {
			(void)dr_power_cap(rs, (int)i, dev, &usable);
			if (!usable) {
				stage = (int)DR_POWER_FLOOR;
			} else if (!dr_frame_fits(sf, bw_khz, (uint16_t)DR_BASE_FRAME_BYTES, b->max_send_ms)) {
				stage = (int)DR_FRAME_TIME;
			} else {
				return DR_OK;
			}
		}
		if (stage > best) best = stage;
	}
	return (dr_reason_t)best;
}

/* ---- convert ---------------------------------------------------------------- */

/* 125 -> 0, 250 -> 1, 500 -> 2; anything else the next of them up, at most 2. */
static int dr_bw_index(uint16_t bw_khz)
{
	for (int i = 0; i < 3; i++) {
		if (bw_khz <= dr_bandwidths[i]) return i;
	}
	return 2;
}

/* The point base + k x step in [a, b] nearest f, ties to the lower. */
static bool dr_nearest_on(int64_t base, int64_t step, int64_t a, int64_t b, int64_t f, int64_t *out)
{
	const int64_t g0 = base - dr_floor_div(base - a, step) * step;   /* the first point >= a */
	const int64_t g1 = base + dr_floor_div(b - base, step) * step;   /* the last point <= b */
	int64_t lower, upper;

	if (g0 > g1) return false;
	if (f <= g0) { *out = g0; return true; }
	if (f >= g1) { *out = g1; return true; }
	lower = base + dr_floor_div(f - base, step) * step;
	upper = (lower == f) ? lower : lower + step;
	*out = (f - lower <= upper - f) ? lower : upper;
	return true;
}

static bool dr_nearest_centre(const dr_band_t *b, uint16_t bw_khz, uint32_t freq_khz, uint32_t *out)
{
	const int64_t h = (int64_t)dr_half_khz(bw_khz);
	const int64_t lo = (int64_t)b->lo_khz + h;
	const int64_t hi = (int64_t)b->hi_khz - h;
	const int64_t f = (int64_t)freq_khz;
	int64_t c;

	if (lo > hi) return false;
	if (b->grid_step_khz != 0u) {
		if (!dr_nearest_on((int64_t)b->grid_base_khz, (int64_t)b->grid_step_khz, lo, hi, f, &c)) return false;
	} else if (freq_khz % 1000u == 0u && dr_nearest_on(0, 1000, lo, hi, f, &c)) {
		/* a whole MHz stays a whole MHz when one fits */
	} else {
		c = (f < lo) ? lo : ((f > hi) ? hi : f);
	}
	*out = (uint32_t)c;
	return true;
}

void dr_default_channel(const dr_rule_set_t *rs, dr_setting_t *out)
{
	if (!out) return;
	*out = rs ? rs->def : dr_no_region_default;
}

dr_how_t dr_convert(const dr_rule_set_t *rs, uint8_t sf, uint16_t bw_khz, uint32_t freq_khz,
                    dr_setting_t *out)
{
	const int bi = dr_bw_index(bw_khz);
	bool found = false;
	uint64_t best_dist = 0;
	int16_t best_eirp = 0;
	uint32_t best_lo = 0;
	dr_setting_t best;
	uint16_t limit = 0;
	dr_setting_t keep;

	keep.freq_khz = freq_khz;
	keep.bw_khz = bw_khz;
	keep.sf = sf;
	if (!out) return DR_KEPT;
	if (!rs || dr_check(rs, sf, bw_khz, freq_khz, &dr_device_generic) == DR_OK) {
		*out = keep;
		return DR_KEPT;
	}
	best = keep;
	for (uint8_t i = 0; i < rs->band_count; i++) {
		const dr_band_t *b = &rs->bands[i];
		int nbi = -1, nsf;
		uint32_t centre;
		uint64_t dist;

		if (freq_khz < b->lo_khz || freq_khz > b->hi_khz) continue;
		if ((b->bw_mask & (1u << bi)) != 0u) {
			nbi = bi;
		} else {
			for (int j = bi + 1; j < 3 && nbi < 0; j++) {
				if ((b->bw_mask & (1u << j)) != 0u) nbi = j;
			}
			for (int j = bi - 1; j >= 0 && nbi < 0; j--) {
				if ((b->bw_mask & (1u << j)) != 0u) nbi = j;
			}
		}
		if (nbi < 0) continue;                       /* a band with no bandwidth: none in the table */
		nsf = (int)sf + nbi - bi;
		if (nsf < (int)DR_SF_MIN) nsf = (int)DR_SF_MIN;
		if (nsf > (int)DR_SF_MAX) nsf = (int)DR_SF_MAX;
		if (!dr_nearest_centre(b, dr_bandwidths[nbi], freq_khz, &centre)) continue;
		dist = (centre > freq_khz) ? (uint64_t)(centre - freq_khz) : (uint64_t)(freq_khz - centre);
		if (!found || dist < best_dist || (dist == best_dist && b->eirp_cdbm > best_eirp) ||
		    (dist == best_dist && b->eirp_cdbm == best_eirp && b->lo_khz < best_lo)) {
			found = true;
			best_dist = dist;
			best_eirp = b->eirp_cdbm;
			best_lo = b->lo_khz;
			best.freq_khz = centre;
			best.bw_khz = dr_bandwidths[nbi];
			best.sf = (uint8_t)nsf;
			limit = b->max_send_ms;
		}
	}
	if (!found) {
		dr_default_channel(rs, out);
		return DR_DEFAULT;
	}
	while (best.sf > DR_SF_MIN && !dr_frame_fits(best.sf, best.bw_khz, (uint16_t)DR_BASE_FRAME_BYTES, limit)) {
		best.sf--;
	}
	*out = best;
	return DR_MOVED;
}

/* ---- the hourly air account ------------------------------------------------- */

static bool dr_air_tracked(const dr_air_t *a, int band)
{
	const dr_band_t *b;
	if (!a || band < 0 || band >= (int)DR_MAX_BANDS) return false;
	b = dr_band(a->rs, band);
	return b != NULL && b->budget_ms_per_h > 0u;
}

void dr_air_init(dr_air_t *a, const dr_rule_set_t *rs)
{
	if (!a) return;
	memset(a, 0, sizeof(*a));
	a->rs = rs;
}

uint32_t dr_air_limit_ms(const dr_rule_set_t *rs, int band, dr_class_t cls)
{
	const dr_band_t *b = dr_band(rs, band);
	if (!b || b->budget_ms_per_h == 0u) return 0;
	if (cls == DR_CLASS_BEACON) return b->budget_ms_per_h;
	return (uint32_t)((uint64_t)b->budget_ms_per_h * DR_NORMAL_SHARE_PCT / 100u);
}

void dr_air_record(dr_air_t *a, int band, uint32_t now_s, uint32_t ms)
{
	const uint32_t m = now_s / DR_BUCKET_S;
	uint32_t *slot;

	if (!dr_air_tracked(a, band)) return;
	if (!a->started) {
		a->started = true;
		a->minute = m;
	} else if (m > a->minute) {
		uint32_t d = m - a->minute;
		if (d > DR_AIR_SLOTS) d = DR_AIR_SLOTS;
		for (uint32_t k = 1; k <= d; k++) {
			for (uint32_t bi = 0; bi < DR_MAX_BANDS; bi++) {
				a->ms[bi][(a->minute + k) % DR_AIR_SLOTS] = 0;
			}
		}
		a->minute = m;
	}
	/* a clock that went back records into the newest minute */
	slot = &a->ms[band][a->minute % DR_AIR_SLOTS];
	*slot = (*slot > UINT32_MAX - ms) ? UINT32_MAX : *slot + ms;
}

/* The first minute of the window ending at now_s: the window is the current
 * minute (or the newest held, when the clock went back) and the 60 before
 * it; the slots hold data for minutes up to a->minute. */
static uint32_t dr_air_window_lo(const dr_air_t *a, uint32_t now_s)
{
	const uint32_t m = now_s / DR_BUCKET_S;
	const uint32_t eff = (m > a->minute) ? m : a->minute;
	return (eff >= DR_AIR_BUCKETS) ? eff - DR_AIR_BUCKETS : 0u;
}

static uint64_t dr_air_used(const dr_air_t *a, int band, uint32_t now_s)
{
	uint64_t total = 0;
	if (!dr_air_tracked(a, band) || !a->started) return 0;
	for (uint32_t k = dr_air_window_lo(a, now_s); k <= a->minute; k++) {
		total += a->ms[band][k % DR_AIR_SLOTS];
	}
	return total;
}

uint32_t dr_air_used_ms(const dr_air_t *a, int band, uint32_t now_s)
{
	const uint64_t u = dr_air_used(a, band, now_s);
	return (u > UINT32_MAX) ? UINT32_MAX : (uint32_t)u;
}

uint32_t dr_air_wait_s(const dr_air_t *a, int band, uint32_t now_s, uint32_t ms, dr_class_t cls)
{
	uint32_t limit;
	uint64_t used, excess, released = 0;

	if (!dr_air_tracked(a, band)) return 0;
	limit = dr_air_limit_ms(a->rs, band, cls);
	if (ms > limit) return DR_WAIT_NEVER;
	used = dr_air_used(a, band, now_s);
	if (used + ms <= limit) return 0;
	excess = used + ms - limit;
	for (uint32_t k = dr_air_window_lo(a, now_s); k <= a->minute; k++) {
		released += a->ms[band][k % DR_AIR_SLOTS];
		if (released >= excess) {
			const uint64_t at = ((uint64_t)k + DR_AIR_SLOTS) * DR_BUCKET_S;
			const uint64_t w = at - now_s;                 /* at > now_s: k >= now_s / 60 - 60 */
			return (w >= DR_WAIT_NEVER) ? DR_WAIT_NEVER - 1u : (uint32_t)w;
		}
	}
	return DR_WAIT_NEVER;                                  /* unreachable: ms <= limit */
}

/* ---- schedule fit ------------------------------------------------------------ */

static uint32_t dr_ms_up(uint64_t us)
{
	const uint64_t ms = (us + 999u) / 1000u;
	return (ms > UINT32_MAX) ? UINT32_MAX : (uint32_t)ms;
}

void dr_schedule_need(const dr_rule_set_t *rs, uint8_t sf, uint16_t bw_khz, uint32_t freq_khz,
                      const dr_need_in_t *in, dr_need_t *out)
{
	const dr_band_t *b;
	uint64_t normal_us, beacon_us, need_us;

	if (!out) return;
	memset(out, 0, sizeof(*out));
	out->band = rs ? dr_band_of(rs, freq_khz, bw_khz) : -1;
	b = dr_band(rs, out->band);
	out->budget_ms = b ? b->budget_ms_per_h : 0u;
	out->normal_limit_ms = dr_air_limit_ms(rs, out->band, DR_CLASS_NORMAL);
	normal_us = in ? (uint64_t)in->reports_per_h * dr_toa_us(sf, bw_khz, in->report_bytes) : 0u;
	beacon_us = in ? (uint64_t)in->lost_per_h * dr_toa_us(sf, bw_khz, in->lost_bytes) +
	                 (uint64_t)in->find_per_h * dr_toa_us(sf, bw_khz, in->find_bytes) : 0u;
	need_us = normal_us + beacon_us;
	out->need_ms = dr_ms_up(need_us);
	out->normal_ms = dr_ms_up(normal_us);
	out->beacon_ms = dr_ms_up(beacon_us);
	if (out->budget_ms == 0u) {
		out->fits = true;
		out->reason = DR_FIT_NO_BUDGET;
	} else if (normal_us > (uint64_t)out->normal_limit_ms * 1000u) {
		out->fits = false;
		out->reason = DR_FIT_NORMAL_OVER;
	} else if (need_us > (uint64_t)out->budget_ms * 1000u) {
		out->fits = false;
		out->reason = DR_FIT_TOTAL_OVER;
	} else {
		out->fits = true;
		out->reason = DR_FIT_FITS;
	}
}

/* ---- regions and the wake channel --------------------------------------------- */

uint8_t dr_region_resolve(uint32_t setting, bool lorawan_configured, uint32_t lorawan_region,
                          uint32_t freq_khz)
{
	if (setting >= 1u && setting <= DR_REGION_MAX) return (uint8_t)setting;
	if (setting != 0u) return (uint8_t)DR_REGION_NONE;     /* not AUTO, not a rule set */
	if (lorawan_configured) {
		switch (lorawan_region) {                          /* ble.proto RadioRegion */
		case 0u: return (uint8_t)DR_REGION_US915;
		case 1u: return (uint8_t)DR_REGION_AU915;
		case 2u: return (uint8_t)DR_REGION_EU868;
		default: return (uint8_t)DR_REGION_NONE;
		}
	}
	if (freq_khz >= 863000u && freq_khz <= 870000u) return (uint8_t)DR_REGION_EU868;
	if (freq_khz >= 902000u && freq_khz <= 928000u) return (uint8_t)DR_REGION_US915;
	return (uint8_t)DR_REGION_NONE;
}

bool dr_wake_channel(const dr_rule_set_t *rs, bool long_range, dr_wake_t *out)
{
	if (!out) return false;
	memset(out, 0, sizeof(*out));
	if (!rs) return false;
	out->freq_hz = rs->wake_freq_hz;
	out->bw_khz = rs->wake_bw_khz;
	out->sf = long_range ? rs->wake_sf_long : rs->wake_sf;
	out->max_dbm = dr_power_cap(rs, dr_band_of(rs, rs->wake_freq_hz / 1000u, rs->wake_bw_khz),
	                            &dr_device_generic, NULL);
	return true;
}

/* ---- the frequency on the wire -------------------------------------------------- */

void dr_freq_to_fields(uint32_t freq_khz, uint32_t *frequency_mhz, uint32_t *frequency_khz)
{
	if (frequency_mhz) *frequency_mhz = (uint32_t)(((uint64_t)freq_khz + 500u) / 1000u);
	if (frequency_khz) *frequency_khz = (freq_khz % 1000u == 0u) ? 0u : freq_khz;
}

uint32_t dr_freq_from_fields(uint32_t frequency_mhz, uint32_t frequency_khz)
{
	if (frequency_khz != 0u) return frequency_khz;
	return (frequency_mhz > UINT32_MAX / 1000u) ? 0u : frequency_mhz * 1000u;
}
