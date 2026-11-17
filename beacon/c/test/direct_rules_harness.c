/*
 * direct_rules_harness.c — runs beacon/c/direct_rules.c (with its generated
 * table, and wake_frame.c for the two functions that now read the table)
 * for the host test beacon/test_direct_rules_c.py, which feeds it the
 * direct_regions vectors of test_vectors/contracts_v1.json one line at a
 * time. Test code only: nothing here goes into a firmware. Builds as C99
 * and as C++ (the engine's two homes).
 *
 * One command per line on stdin, one answer per line on stdout; numbers are
 * decimal, "-" stands for "none". RS is a rule-set id; 99 is the synthetic
 * rule set the synth* commands build. DEV is gen, wio, mk3, spot or
 * GAIN:MIN:MAX.
 *
 *   check RS SF BW F DEV            -> reason code
 *   convert RS SF BW F              -> SF BW F HOW
 *   cap RS BAND DEV                 -> DBM USABLE
 *   bandof RS F BW                  -> band | -1
 *   toa SF BW N                     -> us          toap SF BW N P -> us
 *   wtoa SF BW N P                  -> us (wake_toa_us, for the cross-check)
 *   maxlen SF BW MS                 -> len         bandmax RS BAND SF BW -> len
 *   lbt RS BAND                     -> DBM MS | none
 *   limit RS BAND                   -> MAX PAUSE | none
 *   alimit RS BAND CLS              -> ms
 *   ainit RS                        -> ok
 *   arec BAND NOW MS                -> ok
 *   aused BAND NOW                  -> ms
 *   await BAND NOW MS CLS           -> s | never
 *   need RS SF BW F RPH RB LPH LB FPH FB -> BAND BUDGET NLIMIT NEED NORMAL BEACON FITS REASON
 *   resolve SETTING LW|- F          -> region
 *   wresolve SETTING LW|- MHZ       -> region (wake_region_resolve)
 *   wake RS LONG                    -> HZ BW SF DBM | none
 *   wchan REGION LONG               -> HZ BW SF DBM | none (wake_channel)
 *   default RS                      -> SF BW F
 *   f2w F                           -> MHZ KHZ      w2f MHZ KHZ -> F
 *   ruleset RS                      -> ID KEY NBANDS DEF_F DEF_BW DEF_SF WHZ WBW WSF WSFL | none
 *   band RS IDX                     -> NAME LO HI MASK GBASE GSTEP BUDGET EIRP LBTDBM LBTMS MAXSEND PAUSE COND | none
 *   bykey KEY                       -> id | none
 *   country I                       -> ISO RS CONF NAME... | none
 *   iso ISO                         -> RS CONF | none
 *   device NAME                     -> GAIN MIN MAX
 *   sha                             -> CONTRACTS_SHA TABLE_SHA
 *   counts                          -> RULESETS COUNTRIES
 *   synthclear                      -> ok
 *   synthband LO HI MASK GBASE GSTEP BUDGET EIRP LBTDBM LBTMS MAXSEND PAUSE COND -> ok
 *   synthmeta DEF_F DEF_BW DEF_SF WHZ WBW WSF WSFL -> ok
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "direct_rules.h"
#include "wake_frame.h"

#define SYNTH_ID 99u

static dr_band_t g_synth_bands[DR_MAX_BANDS];
static dr_rule_set_t g_synth;
static dr_air_t g_air;
static const char *const g_synth_names[DR_MAX_BANDS] = { "A", "B", "C", "D", "E", "F" };

static char *next_tok(void)
{
	return strtok(NULL, " \t\r\n");
}

static long long num(void)
{
	const char *t = next_tok();
	return t ? strtoll(t, NULL, 10) : 0;
}

static const dr_rule_set_t *rs_arg(void)
{
	const long long id = num();
	if (id == (long long)SYNTH_ID) return &g_synth;
	if (id < 0 || id > 0xFFFFFFFFLL) return NULL;
	return dr_rule_set((uint32_t)id);
}

static dr_device_t g_custom;

static const dr_device_t *dev_arg(void)
{
	const char *t = next_tok();
	int g = 0, lo = 0, hi = 0;
	if (!t || strcmp(t, "gen") == 0) return &dr_device_generic;
	if (strcmp(t, "wio") == 0) return &dr_device_collar_wio;
	if (strcmp(t, "mk3") == 0) return &dr_device_collar_mk3;
	if (strcmp(t, "spot") == 0) return &dr_device_spotter;
	if (sscanf(t, "%d:%d:%d", &g, &lo, &hi) == 3) {
		g_custom.gain_cdbi = (int16_t)g;
		g_custom.min_dbm = (int8_t)lo;
		g_custom.max_dbm = (int8_t)hi;
		return &g_custom;
	}
	return &dr_device_generic;
}

static dr_class_t cls_arg(void)
{
	const char *t = next_tok();
	return (t && strcmp(t, "beacon") == 0) ? DR_CLASS_BEACON : DR_CLASS_NORMAL;
}

static void print_band(const dr_band_t *b)
{
	printf("%s %" PRIu32 " %" PRIu32 " %u %" PRIu32 " %" PRIu32 " %" PRIu32 " %d %d %u %u %u %d\n",
	       b->name, b->lo_khz, b->hi_khz, (unsigned)b->bw_mask, b->grid_base_khz, b->grid_step_khz,
	       b->budget_ms_per_h, (int)b->eirp_cdbm, (int)b->lbt_dbm, (unsigned)b->lbt_ms,
	       (unsigned)b->max_send_ms, (unsigned)b->pause_ms, (int)b->conducted_dbm);
}

static void synth_reset(void)
{
	memset(g_synth_bands, 0, sizeof(g_synth_bands));
	memset(&g_synth, 0, sizeof(g_synth));
	g_synth.id = (uint8_t)SYNTH_ID;
	g_synth.key = "TEST";
	g_synth.name = "synthetic";
	g_synth.bands = g_synth_bands;
}

int main(void)
{
	char line[512];

	synth_reset();
	dr_air_init(&g_air, NULL);
	while (fgets(line, sizeof(line), stdin)) {
		const char *cmd = strtok(line, " \t\r\n");
		if (!cmd) {
			printf("?\n");
		} else if (strcmp(cmd, "check") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const uint8_t sf = (uint8_t)num();
			const uint16_t bw = (uint16_t)num();
			const uint32_t f = (uint32_t)num();
			printf("%d\n", (int)dr_check(rs, sf, bw, f, dev_arg()));
		} else if (strcmp(cmd, "convert") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const uint8_t sf = (uint8_t)num();
			const uint16_t bw = (uint16_t)num();
			const uint32_t f = (uint32_t)num();
			dr_setting_t out;
			const dr_how_t how = dr_convert(rs, sf, bw, f, &out);
			printf("%u %u %" PRIu32 " %d\n", (unsigned)out.sf, (unsigned)out.bw_khz, out.freq_khz, (int)how);
		} else if (strcmp(cmd, "cap") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const int band = (int)num();
			bool usable = false;
			const int8_t cap = dr_power_cap(rs, band, dev_arg(), &usable);
			printf("%d %d\n", (int)cap, usable ? 1 : 0);
		} else if (strcmp(cmd, "bandof") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const uint32_t f = (uint32_t)num();
			printf("%d\n", dr_band_of(rs, f, (uint16_t)num()));
		} else if (strcmp(cmd, "toa") == 0) {
			const uint8_t sf = (uint8_t)num();
			const uint16_t bw = (uint16_t)num();
			printf("%" PRIu32 "\n", dr_toa_us(sf, bw, (uint16_t)num()));
		} else if (strcmp(cmd, "toap") == 0 || strcmp(cmd, "wtoa") == 0) {
			const int wake = strcmp(cmd, "wtoa") == 0;
			const uint8_t sf = (uint8_t)num();
			const uint16_t bw = (uint16_t)num();
			const uint16_t n = (uint16_t)num();
			const uint16_t p = (uint16_t)num();
			printf("%" PRIu32 "\n", wake ? wake_toa_us(sf, bw, n, p) : dr_toa_preamble_us(sf, bw, n, p));
		} else if (strcmp(cmd, "maxlen") == 0) {
			const uint8_t sf = (uint8_t)num();
			const uint16_t bw = (uint16_t)num();
			printf("%d\n", (int)dr_max_len(sf, bw, (uint32_t)num()));
		} else if (strcmp(cmd, "bandmax") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const int band = (int)num();
			const uint8_t sf = (uint8_t)num();
			printf("%d\n", (int)dr_band_max_len(rs, band, sf, (uint16_t)num()));
		} else if (strcmp(cmd, "lbt") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			int16_t dbm = 0;
			uint8_t ms = 0;
			if (dr_lbt(rs, (int)num(), &dbm, &ms)) printf("%d %u\n", (int)dbm, (unsigned)ms);
			else printf("none\n");
		} else if (strcmp(cmd, "limit") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			uint16_t mx = 0, pause = 0;
			if (dr_send_limit(rs, (int)num(), &mx, &pause)) printf("%u %u\n", (unsigned)mx, (unsigned)pause);
			else printf("none\n");
		} else if (strcmp(cmd, "alimit") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const int band = (int)num();
			printf("%" PRIu32 "\n", dr_air_limit_ms(rs, band, cls_arg()));
		} else if (strcmp(cmd, "ainit") == 0) {
			dr_air_init(&g_air, rs_arg());
			printf("ok\n");
		} else if (strcmp(cmd, "arec") == 0) {
			const int band = (int)num();
			const uint32_t now = (uint32_t)num();
			dr_air_record(&g_air, band, now, (uint32_t)num());
			printf("ok\n");
		} else if (strcmp(cmd, "aused") == 0) {
			const int band = (int)num();
			printf("%" PRIu32 "\n", dr_air_used_ms(&g_air, band, (uint32_t)num()));
		} else if (strcmp(cmd, "await") == 0) {
			const int band = (int)num();
			const uint32_t now = (uint32_t)num();
			const uint32_t ms = (uint32_t)num();
			const uint32_t w = dr_air_wait_s(&g_air, band, now, ms, cls_arg());
			if (w == DR_WAIT_NEVER) printf("never\n");
			else printf("%" PRIu32 "\n", w);
		} else if (strcmp(cmd, "need") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const uint8_t sf = (uint8_t)num();
			const uint16_t bw = (uint16_t)num();
			const uint32_t f = (uint32_t)num();
			dr_need_in_t in;
			dr_need_t out;
			in.reports_per_h = (uint32_t)num();
			in.report_bytes = (uint16_t)num();
			in.lost_per_h = (uint32_t)num();
			in.lost_bytes = (uint16_t)num();
			in.find_per_h = (uint32_t)num();
			in.find_bytes = (uint16_t)num();
			dr_schedule_need(rs, sf, bw, f, &in, &out);
			printf("%d %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %d %d\n", out.band,
			       out.budget_ms, out.normal_limit_ms, out.need_ms, out.normal_ms, out.beacon_ms,
			       out.fits ? 1 : 0, (int)out.reason);
		} else if (strcmp(cmd, "resolve") == 0 || strcmp(cmd, "wresolve") == 0) {
			const int wake = strcmp(cmd, "wresolve") == 0;
			const uint32_t setting = (uint32_t)num();
			const char *lw = next_tok();
			const bool configured = lw && strcmp(lw, "-") != 0;
			const uint32_t region = configured ? (uint32_t)strtoul(lw, NULL, 10) : 0u;
			const uint32_t f = (uint32_t)num();
			printf("%u\n", (unsigned)(wake ? wake_region_resolve(setting, configured, region, f)
			                               : dr_region_resolve(setting, configured, region, f)));
		} else if (strcmp(cmd, "wake") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			dr_wake_t w;
			if (dr_wake_channel(rs, num() != 0, &w)) {
				printf("%" PRIu32 " %u %u %d\n", w.freq_hz, (unsigned)w.bw_khz, (unsigned)w.sf, (int)w.max_dbm);
			} else {
				printf("none\n");
			}
		} else if (strcmp(cmd, "wchan") == 0) {
			const uint8_t region = (uint8_t)num();
			wake_channel_t w;
			if (wake_channel(region, num() != 0, &w)) {
				printf("%" PRIu32 " %u %u %d\n", w.frequency_hz, (unsigned)w.bw_khz, (unsigned)w.sf, (int)w.max_dbm);
			} else {
				printf("none\n");
			}
		} else if (strcmp(cmd, "default") == 0) {
			dr_setting_t d;
			dr_default_channel(rs_arg(), &d);
			printf("%u %u %" PRIu32 "\n", (unsigned)d.sf, (unsigned)d.bw_khz, d.freq_khz);
		} else if (strcmp(cmd, "f2w") == 0) {
			uint32_t mhz = 0, khz = 0;
			dr_freq_to_fields((uint32_t)num(), &mhz, &khz);
			printf("%" PRIu32 " %" PRIu32 "\n", mhz, khz);
		} else if (strcmp(cmd, "w2f") == 0) {
			const uint32_t mhz = (uint32_t)num();
			printf("%" PRIu32 "\n", dr_freq_from_fields(mhz, (uint32_t)num()));
		} else if (strcmp(cmd, "ruleset") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			if (!rs) {
				printf("none\n");
			} else {
				printf("%u %s %u %" PRIu32 " %u %u %" PRIu32 " %u %u %u\n", (unsigned)rs->id, rs->key,
				       (unsigned)rs->band_count, rs->def.freq_khz, (unsigned)rs->def.bw_khz, (unsigned)rs->def.sf,
				       rs->wake_freq_hz, (unsigned)rs->wake_bw_khz, (unsigned)rs->wake_sf,
				       (unsigned)rs->wake_sf_long);
			}
		} else if (strcmp(cmd, "band") == 0) {
			const dr_rule_set_t *rs = rs_arg();
			const dr_band_t *b = dr_band(rs, (int)num());
			if (b) print_band(b);
			else printf("none\n");
		} else if (strcmp(cmd, "bykey") == 0) {
			const dr_rule_set_t *rs = dr_rule_set_by_key(next_tok());
			if (rs) printf("%u\n", (unsigned)rs->id);
			else printf("none\n");
		} else if (strcmp(cmd, "country") == 0) {
			const long long i = num();
			if (i < 0 || i >= (long long)dr_country_count) {
				printf("none\n");
			} else {
				const dr_country_t *c = &dr_countries[i];
				printf("%s %u %u %s\n", c->iso, (unsigned)c->rule_set, (unsigned)c->confidence, c->name);
			}
		} else if (strcmp(cmd, "iso") == 0) {
			const dr_country_t *c = dr_country(next_tok());
			if (c) printf("%u %u\n", (unsigned)c->rule_set, (unsigned)c->confidence);
			else printf("none\n");
		} else if (strcmp(cmd, "device") == 0) {
			const dr_device_t *d = dev_arg();
			printf("%d %d %d\n", (int)d->gain_cdbi, (int)d->min_dbm, (int)d->max_dbm);
		} else if (strcmp(cmd, "sha") == 0) {
			printf("%s %s\n", dr_contracts_sha256, dr_table_sha256);
		} else if (strcmp(cmd, "counts") == 0) {
			printf("%u %u\n", (unsigned)dr_rule_set_count, (unsigned)dr_country_count);
		} else if (strcmp(cmd, "synthclear") == 0) {
			synth_reset();
			printf("ok\n");
		} else if (strcmp(cmd, "synthband") == 0) {
			if (g_synth.band_count >= DR_MAX_BANDS) {
				printf("full\n");
			} else {
				dr_band_t *b = &g_synth_bands[g_synth.band_count];
				b->name = g_synth_names[g_synth.band_count];
				b->lo_khz = (uint32_t)num();
				b->hi_khz = (uint32_t)num();
				b->bw_mask = (uint8_t)num();
				b->grid_base_khz = (uint32_t)num();
				b->grid_step_khz = (uint32_t)num();
				b->budget_ms_per_h = (uint32_t)num();
				b->eirp_cdbm = (int16_t)num();
				b->lbt_dbm = (int16_t)num();
				b->lbt_ms = (uint8_t)num();
				b->max_send_ms = (uint16_t)num();
				b->pause_ms = (uint16_t)num();
				b->conducted_dbm = (int8_t)num();
				g_synth.band_count++;
				printf("ok\n");
			}
		} else if (strcmp(cmd, "synthmeta") == 0) {
			g_synth.def.freq_khz = (uint32_t)num();
			g_synth.def.bw_khz = (uint16_t)num();
			g_synth.def.sf = (uint8_t)num();
			g_synth.wake_freq_hz = (uint32_t)num();
			g_synth.wake_bw_khz = (uint16_t)num();
			g_synth.wake_sf = (uint8_t)num();
			g_synth.wake_sf_long = (uint8_t)num();
			printf("ok\n");
		} else {
			printf("?\n");
		}
		fflush(stdout);
	}
	return 0;
}
