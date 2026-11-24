"""Tests for the contracts themselves (the repos' own tests check their code against them).

    cd contracts && python3 -m unittest -v test_contracts

Standard library only.
"""

import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
# old: sys.path.insert(0, os.path.join(ROOT, "reference"))  (to 2026-11-17: reference/ then came
# first, so `import make_vectors` below was reference/make_vectors.py and Fresh compared the
# GPS block vectors, not contracts_v1.json). reference/ is only for test_error_flags_contract.
sys.path.append(os.path.join(ROOT, "reference"))
import generate  # noqa: E402
import make_vectors  # noqa: E402
import reference as R  # noqa: E402

assert os.path.dirname(os.path.abspath(make_vectors.__file__)) == HERE, "contracts/make_vectors.py, not another"


class Fresh(unittest.TestCase):
    def test_generated_files_are_current(self):
        for name, text in generate.render().items():
            with open(os.path.join(generate.OUT, name)) as fh:
                self.assertEqual(fh.read(), text, f"{name} is stale: run contracts/generate.py")

    def test_the_c_table_is_current(self):
        """beacon/c/direct_rules_table.c is generated too (generate.py --check covers it)."""
        all_files = generate.render_all()
        self.assertIn(generate.TABLE_PATH, all_files)
        with open(generate.TABLE_PATH) as fh:
            self.assertEqual(fh.read(), all_files[generate.TABLE_PATH], "run contracts/generate.py")

    def test_vectors_are_current(self):
        with open(make_vectors.OUT) as fh:
            self.assertEqual(fh.read(), make_vectors.render(), "run contracts/make_vectors.py")

    def test_every_generated_file_names_the_spec_hash(self):
        h = generate.sha256(generate.load())
        for name, text in generate.render_all().items():
            self.assertIn(h, text, name)
        d = generate.dr_sha256(generate.load())
        for name, text in generate.render_all().items():
            self.assertIn(d, text, name)            # and the region table's own hash


class Ledger(unittest.TestCase):
    """The ErrorFlags bits here are the ledger in message.proto (reference/test_error_flags_contract.py)."""

    def test_allocated_bits_match_the_proto_ledger(self):
        from test_error_flags_contract import ALLOCATED, FIRST_FREE
        bits = {b["bit"]: b["key"] for b in R.SPEC["error_flags"]["bits"]}
        for bit, name in ALLOCATED.items():
            self.assertEqual(bits.get(bit, "").upper(), name, f"bit {bit}")
        self.assertEqual(R.SPEC["error_flags"]["first_free"], FIRST_FREE)

    def test_bits_0_to_7_are_the_boot_diagnostics(self):
        bits = {b["bit"]: b["key"] for b in R.SPEC["error_flags"]["bits"]}
        self.assertEqual([bits[i] for i in range(8)],
                         ["accelerometer", "magnetometer", "light", "environment", "gps", "particulate",
                          "lora", "diagnostics_ran"])

    def test_one_key_per_bit(self):
        keys = [b["key"] for b in R.SPEC["error_flags"]["bits"]]
        bits = [b["bit"] for b in R.SPEC["error_flags"]["bits"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(bits, list(range(len(bits))))


class Reference(unittest.TestCase):
    def test_special_mode_round_trip(self):
        for c in (1, 2, 5, 127, 128, 300, 0x4D5400B9):
            self.assertEqual(R.decode_special_mode(R.encode_special_mode(c)), c)

    def test_crc_check_value(self):
        self.assertEqual(R.crc32(b"123456789"), 0xCBF43926)

    def test_padding_lands_on_a_batch(self):
        for n in (1, 300, 928, 960, 4096):
            for p in (20, 96, 182):
                self.assertEqual((32 + len(R.pad_to_batches(bytes(n), p))) % (10 * p), 0)

    def test_caps_round_trip(self):
        c = R.parse_caps(R.caps_bytes(4, 7, 1, 157))
        self.assertEqual((c["fmt"], c["family"], c["build"], c["kind"]), (4, 1, 157, "wb5m"))
        self.assertEqual(R.SPEC["caps"]["length"], len(R.caps_bytes(4, 7, 1, 1)))

    def test_the_spec_matches_the_radio_contract_header(self):
        """CollarID_BLE common/collar_bus.h, when it is checked out beside this repo."""
        path = os.path.join(os.path.dirname(ROOT), "CollarID_BLE", "common", "collar_bus.h")
        if not os.path.exists(path):
            self.skipTest("CollarID_BLE not beside this repo")
        text = open(path).read()
        g = R.SPEC["gatt"]
        for define, key in (("CB_UUID_SERVICE", "service"), ("CB_UUID_UPDATE_CHAR", "update_char"),
                            ("CB_UUID_STATUS_CHAR", "status_char"), ("CB_UUID_CAPS_CHAR", "caps_char"),
                            ("CB_UUID_LOCALDEV_CHAR", "localdev_char"), ("CB_UUID_RADIO_CHAR", "radio_char"),
                            ("CB_UUID_OTAREBOOT_CHAR", "ota_reboot_char"),
                            # the file characteristic (CIDB, ../bulk/README.md), 2026-11-16
                            ("CB_UUID_BULK_CHAR", "bulk_char")):
            m = re.search(r"#define %s\s+\"([^\"]+)\"" % define, text)
            self.assertTrue(m and m.group(1) == g[key], define)
        num = lambda name: int(re.search(r"#define %s\s+(0x[0-9A-Fa-f]+|\d+)u" % name, text).group(1), 0)
        self.assertEqual(num("CB_GATT_CAPS_LEN"), R.SPEC["caps"]["length"])
        self.assertEqual(num("CB_GATT_CAPS_FORMAT"), R.SPEC["caps"]["format_build"])
        self.assertEqual(num("CB_GATT_CAPS_BUILD_OFFSET"), R.SPEC["caps"]["build_offset"])
        self.assertEqual(num("CB_GATT_CAPS_FAMILY_WB5M"), R.SPEC["caps"]["families"]["wb5m"])
        self.assertEqual(num("CB_GATT_CAPS_FAMILY_NRF54L15"), R.SPEC["caps"]["families"]["nrf54l15"])


class BatteryThresholds(unittest.TestCase):
    """Low-battery hibernation (2026-11-12): the defaults are what every collar
    ran before the setting, the CSV reading always lands on a valid pair, and
    the bounds leave room for the gap."""

    def test_the_defaults_are_the_old_constants_and_valid(self):
        B = R.SPEC["battery_thresholds"]
        self.assertEqual((B["hibernate_default"], B["resume_default"]), (10, 20))
        self.assertTrue(R.battery_thresholds_valid(B["hibernate_default"], B["resume_default"]))
        self.assertEqual(R.battery_thresholds_from_csv(None, None), [10, 20])

    def test_every_hibernate_level_has_a_valid_resume(self):
        B = R.SPEC["battery_thresholds"]
        self.assertGreaterEqual(B["resume_max"], B["hibernate_max"] + B["min_gap"])
        self.assertLessEqual(B["resume_min"], B["hibernate_min"] + B["min_gap"])

    def test_the_csv_reading_is_always_valid(self):
        texts = [None, "", "x", "-100", "0", "1", "4", "5", "9", "10", "39", "40", "41", "59", "60", "61", "99999"]
        for h in texts:
            for r in texts:
                pair = R.battery_thresholds_from_csv(h, r)
                self.assertTrue(R.battery_thresholds_valid(*pair), (h, r, pair))

    def test_a_valid_pair_reads_back_unchanged(self):
        B = R.SPEC["battery_thresholds"]
        for h in range(B["hibernate_min"], B["hibernate_max"] + 1):
            for r in range(B["resume_min"], B["resume_max"] + 1):
                if R.battery_thresholds_valid(h, r):
                    self.assertEqual(R.battery_thresholds_from_csv(str(h), str(r)), [h, r])

    def test_the_csv_keys_follow_battery_protection(self):
        g = R.SPEC["config_csv"]["keys"]["global"]
        i = g.index("battery_protection_min_temp_c")
        self.assertEqual(g[i + 1:i + 3], ["battery_hibernate_pct", "battery_resume_pct"])



class SavingPower(unittest.TestCase):
    """Saving power before hibernation (2026-11-18): the band sits on the
    hibernate level, never reaches past the resume ceiling, ends a gap above
    where it starts, and a Spotter's hold only ever lowers the sleep level."""

    def test_the_band_and_its_gap_stay_under_the_resume_ceiling(self):
        B = R.SPEC["battery_thresholds"]
        self.assertTrue(R.saving_band_valid(B["saving_band_default"]))
        self.assertEqual(B["saving_band_min"], 0)
        self.assertLessEqual(B["hibernate_max"] + B["saving_band_max"] + B["saving_exit_gap"], B["resume_max"])
        self.assertLess(B["spotter_floor_pct"], B["hibernate_min"])

    def test_the_stage_has_its_gap_and_band_zero_is_off(self):
        B = R.SPEC["battery_thresholds"]
        gap = B["saving_exit_gap"]
        for hib in range(B["hibernate_min"], B["hibernate_max"] + 1):
            for band in range(B["saving_band_min"], B["saving_band_max"] + 1):
                for pct in range(0, 101):
                    start = R.saving_next(hib, band, pct, False)
                    keep = R.saving_next(hib, band, pct, True)
                    if pct <= hib:                       # held by a Spotter: always saving
                        self.assertTrue(start and keep)
                        continue
                    if band == 0:
                        self.assertFalse(start or keep)
                        continue
                    self.assertEqual(start, pct <= hib + band)
                    self.assertEqual(keep, pct <= hib + band + gap)
                    self.assertTrue(keep or not start)   # a reading that starts it keeps it

    def test_a_spotter_hold_only_lowers_the_sleep_level(self):
        for hib in (5, 10, 40):
            for pct in range(0, 101):
                if R.hibernate_now(pct, hib, True):
                    self.assertTrue(R.hibernate_now(pct, hib, False), (pct, hib))

    def test_the_csv_reading_is_always_valid(self):
        for t in [None, "", "x", "-100", "0", "1", "5", "15", "16", "99999", " 3", "7 "]:
            self.assertTrue(R.saving_band_valid(R.saving_band_from_csv(t)), t)
        for b in range(0, 16):
            self.assertEqual(R.saving_band_from_csv(str(b)), b)

    def test_the_refresh_wait_doubles_to_its_cap(self):
        B = R.SPEC["battery_thresholds"]
        waits = [R.saving_gps_refresh_wait_s(n) for n in range(6)]
        self.assertEqual(waits[0], B["saving_gps_refresh_s"])
        self.assertEqual(waits[1], 2 * B["saving_gps_refresh_s"])
        self.assertEqual(waits[-1], B["saving_gps_refresh_max_s"])
        self.assertEqual(waits, sorted(waits))

    def test_the_csv_key_follows_the_resume_level(self):
        g = R.SPEC["config_csv"]["keys"]["global"]
        self.assertEqual(g[g.index("battery_resume_pct") + 1], "battery_saving_band_pct")

class LoRaWake(unittest.TestCase):
    """LoRa wake (2026-11-13): three CONFIG.CSV keys. The region and the
    long-range setting follow the direct radio's other global keys; the
    listening interval closes each schedule's rows, after its direct-radio
    send interval. Unconditional: every writer emits all three."""

    def test_the_global_keys_follow_the_direct_radio(self):
        g = R.SPEC["config_csv"]["keys"]["global"]
        i = g.index("lora_rx_listen")
        self.assertEqual(g[i + 1:i + 3], ["lora_region", "lora_wake_long_range"])
        # old: self.assertEqual(g[i + 3], "lost_mode_enabled")  (to 2026-11-17; lora_frequency_khz
        # follows, DirectRegions.test_the_csv_key below)
        self.assertEqual(g[i + 4], "lost_mode_enabled")
        self.assertEqual(len(g), len(set(g)))

    def test_the_schedule_key_is_the_last_row(self):
        sched = R.SPEC["config_csv"]["keys"]["schedule"]
        self.assertEqual(sched[-2:], ["lora_send_interval_min", "lora_wake_interval_s"])
        self.assertEqual(len(sched), len(set(sched)))

    def test_they_are_unconditional_and_every_writer_s(self):
        cfg = R.SPEC["config_csv"]
        for key in ("lora_region", "lora_wake_long_range", "lora_wake_interval_s"):
            self.assertNotIn(key, cfg["conditional"])
            self.assertNotIn(key, cfg["firmware_only"])

    def test_the_names_are_the_proto_s(self):
        """The schedule key is the proto field's name; the global keys take
        the direct radio's `lora_` prefix as its other keys do."""
        root = os.path.dirname(HERE)
        with open(os.path.join(root, "ble.proto")) as fh:
            ble = fh.read()
        self.assertRegex(ble, r"uint32 lora_wake_interval_s\s+= 13;")
        self.assertRegex(ble, r"DirectRegion region\s+= 8;")
        self.assertRegex(ble, r"bool wake_long_range\s+= 9;")
        # old: "lora_region (0..3)" (to 2026-11-17)
        for key in ("lora_region (0..15)", "lora_wake_long_range (0/1)"):
            self.assertIn("CONFIG.CSV key " + key, re.sub(r"\s*//\s*", " ", ble))

    def test_the_generated_header_lists_them(self):
        with open(os.path.join(generate.OUT, "collarid_contracts.h")) as fh:
            h = fh.read()
        for key in ("lora_region", "lora_wake_long_range", "lora_wake_interval_s"):
            self.assertIn('X("%s")' % key, h)
        g, sched = (R.SPEC["config_csv"]["keys"][k] for k in ("global", "schedule"))
        self.assertIn("#define CID_CONFIG_CSV_GLOBAL_COUNT %du" % len(g), h)
        self.assertIn("#define CID_CONFIG_CSV_SCHEDULE_COUNT %du" % len(sched), h)
        # old: (44, 41) (to 2026-11-17; + lora_frequency_khz)
        # old: self.assertEqual((len(g), len(sched)), (45, 41))   (before battery_saving_band_pct, 2026-11-18)
        # old: self.assertEqual((len(g), len(sched)), (46, 41))   (before the schedule zone, 2026-11-23)
        self.assertEqual((len(g), len(sched)), (48, 41))



class ScheduleZone(unittest.TestCase):
    """The schedule zone (2026-11-23): the reference against the IANA database
    where this Python has it, the rules' shape, the CSV keys and the header."""

    def test_the_reference_is_the_iana_zones(self):
        try:
            import datetime as D
            from zoneinfo import ZoneInfo
            ZoneInfo("America/Denver")
        except Exception:  # pragma: no cover - no tz database here
            self.skipTest("no IANA database")
        for name, std, dst in (("America/Denver", -28, 1), ("America/Phoenix", -28, 0),
                               ("America/New_York", -20, 1), ("America/St_Johns", -14, 1),
                               ("Europe/Berlin", 4, 2), ("Europe/London", 0, 2),
                               ("Australia/Sydney", 40, 3), ("Australia/Adelaide", 38, 3),
                               ("Pacific/Auckland", 48, 4), ("Asia/Kolkata", 22, 0)):
            tz = ZoneInfo(name)
            t = int(D.datetime(2026, 1, 1, tzinfo=D.timezone.utc).timestamp())
            end = int(D.datetime(2031, 1, 1, tzinfo=D.timezone.utc).timestamp())
            while t < end:
                want = int(D.datetime.fromtimestamp(t, tz).utcoffset().total_seconds()) // 900
                self.assertEqual(R.zone_offset_qh(t, std, dst), want, (name, t))
                t += 1800

    def test_the_rules(self):
        Z = R.SPEC["schedule_zone"]
        ids = [r["id"] for r in Z["rules"]]
        self.assertEqual(ids, sorted(set(ids)))
        self.assertEqual(Z["rules"][0], {"id": 0, "key": "none", "name": "No clock change"})
        for r in Z["rules"][1:]:
            self.assertEqual(r["save_qh"] % 4, 0, r["key"])   # whole hours: a local hour starts where a UTC one does
            for k in ("start", "end"):
                e = r[k]
                self.assertIn(e["basis"], ("utc", "local_std"))
                self.assertTrue(1 <= e["month"] <= 12 and 1 <= e["week"] <= 5 and 0 <= e["weekday"] <= 6)

    def test_the_csv_keys_and_header(self):
        g = R.SPEC["config_csv"]["keys"]["global"]
        i = g.index("mortality_transmit_interval_min")
        self.assertEqual(g[i + 1:i + 3], ["schedule_zone_std_qh", "schedule_zone_dst"])
        with open(os.path.join(generate.OUT, "collarid_contracts.h")) as fh:
            h = fh.read()
        self.assertIn("#define CID_ZONE_STD_QH_MIN (-48)", h)
        self.assertIn("#define CID_ZONE_RULES(X)", h)
        self.assertIn("X(1, 4, 3, 2, 0, 120, 0, 11, 1, 0, 60, 0)", h)   # us: basis 0 = local standard


class DirectRegions(unittest.TestCase):
    """Direct-radio regions (collarID_thread docs/CONTRACT_direct_regions.md,
    2026-11-17): the spec is the contract's table, the reference does what
    the contract says, and the beacon reference agrees with it."""

    DR = R.SPEC["direct_regions"]

    # -------------------------------------------------------------- the spec

    def test_rule_sets_are_the_direct_region_values(self):
        ids = [r["id"] for r in self.DR["rule_sets"]]
        self.assertEqual(ids, list(range(1, 16)))
        keys = [r["key"] for r in self.DR["rule_sets"]]
        self.assertEqual(keys, ["US915", "EU868", "AU915", "BR915", "LA915", "IN865", "JP920", "KR920", "SG920",
                                "MY919", "TH920", "VN920", "ID920", "TW920", "RU868"])
        with open(os.path.join(ROOT, "ble.proto")) as fh:
            ble = fh.read()
        for r in self.DR["rule_sets"]:
            self.assertRegex(ble, r"DIRECT_REGION_%s\s*=\s*%d;" % (r["key"], r["id"]))
        self.assertEqual(self.DR["constants"]["region_max"], max(ids))

    def test_bands_are_well_formed(self):
        with open(os.path.join(ROOT, "beacon", "c", "direct_rules.h")) as fh:
            max_bands = int(re.search(r"(?m)^#define DR_MAX_BANDS\s+(\d+)u", fh.read()).group(1))
        for r in self.DR["rule_sets"]:
            self.assertTrue(1 <= len(r["bands"]) <= max_bands, r["key"])
            last_hi = 0
            for b in r["bands"]:
                name = "%s %s" % (r["key"], b["name"])
                self.assertLess(b["lo_khz"], b["hi_khz"], name)
                self.assertGreaterEqual(b["lo_khz"], last_hi, name + ": bands in order, not overlapping")
                last_hi = b["hi_khz"]
                self.assertTrue(b["bw_khz"] and set(b["bw_khz"]) <= {125, 250, 500}, name)
                self.assertEqual(b["bw_khz"], sorted(b["bw_khz"]), name)
                self.assertEqual(b["grid_base_khz"] is None, b["grid_step_khz"] is None, name)
                if b["grid_step_khz"] is not None:
                    self.assertGreater(b["grid_step_khz"], 0, name)
                self.assertEqual(b["lbt_dbm"] is None, b["lbt_ms"] is None, name)
                self.assertEqual(b["max_send_ms"] == 0, b["pause_ms"] == 0, name)
                self.assertGreaterEqual(b["budget_ms_per_h"], 0, name)
                # the website's and app's collar can use every band (convert relies on it)
                self.assertTrue(R.dr_power_cap(r["id"], r["bands"].index(b), "generic")[1], name)
                # every allowed bandwidth has a legal centre in the band
                for bw in b["bw_khz"]:
                    self.assertIsNotNone(R._dr_nearest_centre(b, bw, b["lo_khz"]), (name, bw))

    def test_the_contract_table_of_section_1(self):
        """A few rows of the contract's table, as written there."""
        def band(key, i):
            return R.dr_rule_set(key)["bands"][i]
        self.assertEqual((band("EU868", 4)["lo_khz"], band("EU868", 4)["hi_khz"], band("EU868", 4)["eirp_cdbm"],
                          band("EU868", 4)["budget_ms_per_h"], band("EU868", 4)["grid_base_khz"]),
                         (869400, 869650, 2915, 360000, 869525))
        self.assertEqual((band("JP920", 0)["conducted_dbm"], band("JP920", 0)["lbt_dbm"], band("JP920", 0)["lbt_ms"],
                          band("JP920", 0)["max_send_ms"], band("JP920", 0)["pause_ms"]), (13, -80, 5, 4000, 50))
        self.assertEqual((band("KR920", 0)["lbt_dbm"], band("KR920", 0)["eirp_cdbm"]), (-65, 1400))
        self.assertEqual((band("LA915", 0)["lbt_dbm"], band("LA915", 0)["max_send_ms"]), (-80, 0))
        self.assertEqual(band("US915", 0)["bw_khz"], [500])
        self.assertEqual([(b["lo_khz"], b["hi_khz"]) for b in R.dr_rule_set("BR915")["bands"]],
                         [(902000, 907500), (915000, 928000)])
        self.assertEqual(band("TW920", 0)["conducted_dbm"], 27)

    def test_countries(self):
        cs = self.DR["countries"]
        isos = [c["iso"] for c in cs]
        self.assertEqual(len(isos), len(set(isos)))
        self.assertEqual(len(cs), 54)
        for c in cs:
            self.assertRegex(c["iso"], r"^[A-Z]{2}$")
            self.assertIsNotNone(R.dr_rule_set(c["rule_set"]), c)
            self.assertIn(c["confidence"], self.DR["confidences"])
        by = {c["iso"]: (R.dr_rule_set(c["rule_set"])["key"], c["confidence"]) for c in cs}
        self.assertEqual(by["CH"], ("EU868", "cept"))
        self.assertEqual(by["GB"], ("EU868", "primary"))
        self.assertEqual(by["AR"], ("LA915", "low"))
        self.assertEqual(by["MY"], ("MY919", "low"))
        self.assertEqual(by["RU"], ("RU868", "low"))
        self.assertEqual(by["PR"], ("US915", "primary"))
        self.assertEqual(sum(1 for c in cs if c["rule_set"] == 2), 27 + 4 + 3)
        for c in self.DR["not_offered"]:
            self.assertNotIn(c["iso"], isos)
        self.assertEqual([c["name"] for c in R.dr_countries_by_name()][:3], ["Argentina", "Australia", "Austria"])

    def test_devices_and_constants(self):
        d = self.DR["devices"]
        self.assertEqual({k: (v["gain_cdbi"], v["min_dbm"], v["max_dbm"], v["below_floor"]) for k, v in d.items()},
                         {"collar_wio": (90, -9, 22, "unusable"), "collar_mk3": (100, 9, 28, "send_at_floor"),
                          "spotter": (200, -9, 22, "unusable"), "generic": (100, -9, 22, "unusable")})
        # Mk III and board unknown: the ACR1504I3's 1.0 dBi (Abracon, revised 10-29-24, horizontal
        # placement, 915 MHz; 0.5 at 868). old: 90 for both, the Wio's Linx antenna (until 2026-11-17)
        self.assertEqual(self.DR["below_floor"], ["unusable", "send_at_floor"])   # direct_rules.h DR_BELOW_FLOOR_*
        with open(os.path.join(ROOT, "beacon", "c", "direct_rules.h")) as fh:
            h = fh.read()
        c = self.DR["constants"]
        for name, key in (("DR_REGION_MAX", "region_max"), ("DR_SF_MIN", "sf_min"), ("DR_SF_MAX", "sf_max"),
                          ("DR_NORMAL_SHARE_PCT", "normal_share_pct"), ("DR_BASE_FRAME_BYTES", "base_frame_bytes"),
                          ("DR_PREAMBLE_SYMBOLS", "preamble_symbols"), ("DR_LBT_SAMPLE_MAX_MS", "lbt_sample_max_ms"),
                          ("DR_LBT_BACKOFF_MIN_MS", "lbt_backoff_min_ms"), ("DR_LBT_BACKOFF_MAX_MS", "lbt_backoff_max_ms"),
                          ("DR_LBT_GIVE_UP_S", "lbt_give_up_s"), ("DR_BUCKET_S", "bucket_s"),
                          ("DR_AIR_BUCKETS", "buckets"), ("DR_DEFAULT_CODING_RATE", "default_coding_rate"),
                          ("DR_DEFAULT_SYNC_WORD", "default_sync_word")):
            m = re.search(r"(?m)^#define %s\s+(0x[0-9A-Fa-f]+|\d+)u" % name, h)
            self.assertIsNotNone(m, name)
            self.assertEqual(int(m.group(1), 0), c[key], name)
        for i, name in enumerate(self.DR["reasons"]):
            self.assertRegex(h, r"\bDR_%s\s+= %d\b" % (name, i))
        for r in self.DR["rule_sets"]:
            self.assertRegex(h, r"(?m)^#define DR_REGION_%s\s+%du" % (r["key"], r["id"]))
        self.assertEqual((c["normal_share_pct"], c["base_frame_bytes"], c["lbt_backoff_min_ms"], c["lbt_backoff_max_ms"],
                          c["lbt_give_up_s"], c["bucket_s"], c["buckets"], c["preamble_symbols"]),
                         (75, 64, 20, 200, 20, 60, 60, 8))

    def test_the_csv_key(self):
        cfg = R.SPEC["config_csv"]
        g = cfg["keys"]["global"]
        self.assertEqual(g[g.index("lora_wake_long_range") + 1], "lora_frequency_khz")
        self.assertIn("lora_frequency_khz", cfg["conditional"])          # written only when not a whole MHz
        self.assertNotIn("lora_frequency_khz", cfg["firmware_only"])

    def test_the_generated_files_carry_the_table(self):
        files = generate.render()
        h = files["collarid_contracts.h"]
        for r in self.DR["rule_sets"]:
            self.assertIn("#define CID_DR_RULE_SET_%s %du" % (r["key"], r["id"]), h)
        self.assertIn('X(7u, 0u, "920.5-923.5", 920500u, 923500u, 0x05u, 920600u, 200u, 1600, 13, 0u, (-80), 5u, '
                      '4000u, 50u)', h)
        self.assertIn('X("JP", "Japan", 7u, 0u)', h)
        self.assertIn("#define CID_DR_DEVICE_COLLAR_MK3_MIN_DBM 9", h)          # old: 16 (until 2026-11-17)
        self.assertIn("DIRECT_REGIONS = CONTRACTS['direct_regions']", files["collarid_contracts.py"])
        self.assertIn("export const DIRECT_REGIONS = CONTRACTS.direct_regions;", files["collaridContracts.ts"])
        self.assertIn("C.DIRECT_REGIONS_SHA256 = ", files["collarid-contracts.js"])

    # -------------------------------------------------------------- the reference

    def test_the_contract_s_convert_table(self):
        """Section 5's table: every row as the contract writes it."""
        import make_vectors as mv
        for key, i, o, why in mv.DR_CONTRACT_TABLE:
            self.assertEqual(R.dr_convert(key, *i)[:3], o, (key, i, why))

    def test_the_us_vectors(self):
        import make_vectors as mv
        for i, o in mv.DR_US500:
            self.assertEqual(R.to_us500(*i), o, i)
            self.assertTrue(R.us500_allowed(*o))

    def test_the_power_examples_of_section_3(self):
        cap = lambda key, band, dev: R.dr_power_cap(key, band, dev)  # noqa: E731
        self.assertEqual(cap("EU868", 4, "collar_wio"), (22, True))
        self.assertEqual(cap("EU868", 4, "collar_mk3"), (28, True))        # +2 at the chip, 26 dB (2026-11-17)
        self.assertEqual(cap("EU868", 0, "collar_wio"), (15, True))
        self.assertEqual(cap("EU868", 0, "collar_mk3"), (15, True))         # +9..+28: the band's own +15
        # old (2026-11-17 noon): (15, False), the band unusable on Mk III (+16..+27);
        # old (2026-11-17 afternoon): (16, True), it sent at its +16 floor
        self.assertEqual(cap("EU868", 3, "spotter"), (14, True))
        self.assertEqual(cap("JP920", 0, "collar_wio"), (13, True))
        self.assertEqual(cap("KR920", 0, "collar_wio"), (13, True))
        self.assertEqual(cap("RU868", 0, "collar_wio"), (21, True))
        self.assertEqual(cap("SG920", 0, "collar_wio"), (21, True))
        self.assertEqual(cap("AU915", 0, {"gain_cdbi": 1200, "min_dbm": -9, "max_dbm": 22}), (18, True))
        # A +16 floor is above what the EU 25 mW bands, Japan, Korea and
        # Vietnam allow; a send_at_floor profile sends at it there (section 3,
        # Patrick 2026-11-17)
        floor16 = {"gain_cdbi": 90, "min_dbm": 16, "max_dbm": 27, "below_floor": "send_at_floor"}
        below = {(r["key"], i): R.dr_power_allowed(r["id"], i, floor16) for r in self.DR["rule_sets"]
                 for i in range(len(r["bands"])) if R.dr_power_allowed(r["id"], i, floor16) < 16}
        self.assertEqual(below, {("EU868", 0): 15, ("EU868", 1): 15, ("EU868", 2): 15, ("EU868", 3): 15,
                                 ("EU868", 5): 15, ("JP920", 0): 13, ("KR920", 0): 13, ("VN920", 0): 15})
        for (key, i) in below:
            self.assertEqual(cap(key, i, floor16), (16, True), key)
        # The Mk III (+9..+28 since the reduced PA configuration) is at or
        # above its floor in every band of the table: the band's own figure
        for r in self.DR["rule_sets"]:
            for i in range(len(r["bands"])):
                allowed = R.dr_power_allowed(r["id"], i, "collar_mk3")
                self.assertGreaterEqual(allowed, 9, (r["key"], i))
                self.assertEqual(cap(r["id"], i, "collar_mk3"), (min(allowed, 28), True), (r["key"], i))
        # an "unusable" profile (none of the named ones today) still does not send there
        old_mk3 = {"gain_cdbi": 90, "min_dbm": 16, "max_dbm": 27, "below_floor": "unusable"}
        self.assertEqual({(r["key"], i) for r in self.DR["rule_sets"] for i in range(len(r["bands"]))
                          if not cap(r["id"], i, old_mk3)[1]}, set(below))
        self.assertEqual(cap("EU868", 2, {"gain_cdbi": 90, "min_dbm": 16, "max_dbm": 27}), (15, False))
        self.assertEqual(R.dr_check("JP920", 9, 125, 922000, "collar_mk3"), "OK")
        self.assertEqual(R.dr_check("JP920", 9, 125, 922000, floor16), "OK")
        self.assertEqual(R.dr_check("JP920", 9, 125, 922000, old_mk3), "POWER_FLOOR")
        self.assertEqual(R.dr_power_allowed("EU868", 4, floor16), 28)          # above the device's max: not held
        self.assertEqual(R.dr_power_allowed(0, 0, "collar_mk3"), 28)           # no region: the device's max

    def test_wake_channels_of_section_9(self):
        want = {"US915": (919000000, 500, 9, 12), "AU915": (919000000, 500, 9, 12), "BR915": (919000000, 500, 9, 12),
                "LA915": (919000000, 500, 9, 12), "EU868": (869525000, 125, 7, 10), "IN865": (867000000, 125, 7, 10),
                "JP920": (922000000, 125, 7, 10), "KR920": (923100000, 125, 7, 10), "SG920": (922000000, 125, 7, 10),
                "MY919": (922000000, 125, 7, 10), "TH920": (922000000, 125, 7, 10), "VN920": (922000000, 125, 7, 10),
                "ID920": (922000000, 125, 7, 10), "TW920": (923000000, 500, 9, 12), "RU868": (869100000, 125, 7, 10)}
        for key, (hz, bw, sf, sfl) in want.items():
            w, wl = R.dr_wake_channel(key), R.dr_wake_channel(key, True)
            self.assertEqual((w["freq_hz"], w["bw_khz"], w["sf"], wl["sf"]), (hz, bw, sf, sfl), key)
            for ch in (w, wl):          # every wake channel passes the check of its own rule set
                self.assertEqual(R.dr_check(key, ch["sf"], ch["bw_khz"], ch["freq_hz"] // 1000), "OK", key)
        self.assertIsNone(R.dr_wake_channel(0))

    def test_defaults_of_section_10(self):
        want = {"US915": (9, 500, 915000), "EU868": (9, 125, 869525), "AU915": (9, 500, 916000),
                "BR915": (9, 500, 916000), "LA915": (9, 500, 916000), "IN865": (9, 125, 866000),
                "JP920": (9, 125, 921000), "KR920": (9, 125, 922700), "SG920": (9, 125, 921000),
                "MY919": (9, 125, 921000), "TH920": (9, 125, 921000), "VN920": (9, 125, 921000),
                "ID920": (9, 125, 921000), "TW920": (9, 500, 921000), "RU868": (9, 125, 868900)}
        for key, d in want.items():
            self.assertEqual(R.dr_default_channel(key), d, key)
            self.assertEqual(R.dr_check(key, *d), "OK", key)
            for dev in ("collar_wio", "spotter"):
                self.assertEqual(R.dr_check(key, *d, dev), "OK", (key, dev))
        self.assertEqual(R.dr_default_channel(0), (9, 500, 915000))   # no region: today's (US)

    def test_convert_lands_on_a_legal_channel_and_stays(self):
        import make_vectors as mv
        for r in self.DR["rule_sets"] + [mv.DR_SYNTHETIC]:
            for f in mv._dr_sweep_freqs(r):
                for bw in (125, 250, 500):
                    for sf in range(7, 13):
                        s, b, nf, how = R.dr_convert(r, sf, bw, f)
                        self.assertIn(R.dr_check(r, s, b, nf), ("OK", "FRAME_TIME" if r is mv.DR_SYNTHETIC else "OK"))
                        self.assertEqual(R.dr_convert(r, s, b, nf), (s, b, nf, "kept"))
                        if how == "kept":
                            self.assertEqual((s, b, nf), (sf, bw, f))
                        self.assertEqual(how == "kept", R.dr_check(r, sf, bw, f) == "OK")

    def test_time_on_air_is_the_beacon_reference(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("beacon_v2_ref", os.path.join(ROOT, "beacon", "beacon_v2.py"))
        b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(b)
        for sf in range(7, 13):
            for bw in (125, 250, 500):
                for n in range(0, 256, 3):
                    for p in (8, 12):
                        self.assertEqual(R.dr_toa_us(sf, bw, n, p), b.lora_toa_us(sf, bw, n, p))
        # the beacon reference's wake table and regions are this table's
        for r in self.DR["rule_sets"]:
            w = R.dr_wake_channel(r["id"])
            ch = b.WAKE_TABLE[r["id"]]
            self.assertEqual((ch.name, ch.frequency_hz, ch.bw_khz, ch.sf, ch.sf_long, ch.max_dbm),
                             (r["key"], w["freq_hz"], w["bw_khz"], w["sf"], r["wake"]["sf_long"], w["max_dbm"]))
            self.assertEqual(getattr(b, "DIRECT_REGION_" + r["key"]), r["id"])
        self.assertEqual(sorted(b.WAKE_TABLE), [r["id"] for r in self.DR["rule_sets"]])
        for setting in (0, 1, 2, 3, 4, 9, 15, 16, 255):
            for lw in (None, 0, 1, 2, 3):
                for mhz in (0, 433, 862, 863, 868, 870, 871, 901, 902, 915, 928, 929):
                    self.assertEqual(b.direct_region_resolve(setting, lw, mhz),
                                     R.dr_region_resolve(setting, lw, mhz * 1000), (setting, lw, mhz))

    def test_the_air_account_waits_exactly_long_enough(self):
        """On random sequences: after wait_s(...) seconds the send fits, one
        second earlier it does not; used never counts a send older than 61
        minutes, and always counts one younger than 60."""
        import random
        rnd = random.Random(20261117)
        for trial in range(300):
            key = rnd.choice(["EU868", "IN865", "SG920", "RU868"])
            r = R.dr_rule_set(key)
            band = rnd.randrange(len(r["bands"]))
            if not r["bands"][band]["budget_ms_per_h"]:
                continue
            acct, sends, now = R.DrAirAccount(key), [], rnd.randrange(0, 10 ** 6)
            limit_b = R.dr_air_limit_ms(key, band, "beacon")
            for _ in range(rnd.randrange(1, 40)):
                now += rnd.choice([1, 7, 59, 60, 61, 300, 1800, 3599, 3600, 3660, 7200])
                ms = rnd.randrange(0, max(2, limit_b // 6))
                acct.record(band, now, ms)
                sends.append((now, ms))
            t = now + rnd.randrange(0, 4000)
            used = acct.used_ms(band, t)
            lo = sum(ms for s, ms in sends if t - s < 3600)           # surely in: younger than 60 minutes
            hi = sum(ms for s, ms in sends if t // 60 - s // 60 <= 60)  # the 61-minute window
            self.assertTrue(lo <= used == hi, (trial, used, lo, hi))
            for cls in ("normal", "beacon"):
                limit = R.dr_air_limit_ms(key, band, cls)
                ms = rnd.randrange(0, limit + 2)
                w = acct.wait_s(band, t, ms, cls)
                if ms > limit:
                    self.assertIsNone(w)
                    continue
                self.assertLessEqual(acct.used_ms(band, t + w) + ms, limit, (trial, cls))
                if w > 0:
                    self.assertGreater(acct.used_ms(band, t + w - 1) + ms, limit, (trial, cls))

    def test_frequency_fields(self):
        self.assertEqual(R.dr_freq_to_fields(915000), (915, 0))
        self.assertEqual(R.dr_freq_to_fields(869525), (870, 869525))
        self.assertEqual(R.dr_freq_to_fields(868499), (868, 868499))
        self.assertEqual(R.dr_freq_to_fields(869500), (870, 869500))      # a half up
        for f in range(860000, 930001, 37):
            self.assertEqual(R.dr_freq_from_fields(*R.dr_freq_to_fields(f)), f)

    def test_the_vectors_carry_every_section(self):
        with open(make_vectors.OUT) as fh:
            v = json.load(fh)["direct_regions"]
        self.assertEqual(v["table_sha256"], generate.dr_sha256(R.SPEC))
        for k in ("contract_table", "us500", "check_sweep", "convert_sweep", "odd_inputs", "check_devices",
                  "power_caps", "below_floor", "band_of", "toa", "max_len", "band_limits", "air", "schedule_need",
                  "region_resolve", "wake_channels", "defaults", "freq_fields", "freq_read", "synthetic"):
            self.assertIn(k, v)
        self.assertEqual(len(v["contract_table"]), 15)
        self.assertTrue(all(row["agrees"] for row in v["contract_table"]))
        self.assertEqual(len(v["us500"]), 11)
        # every rule set, SF7..12, 125/250/500, and every band edge +-1 kHz
        rows = {(rs, bw, f) for rs, bw, f, _ in v["check_sweep"]["rows"]}
        for r in self.DR["rule_sets"]:
            for b in r["bands"]:
                for f in (b["lo_khz"] - 1, b["lo_khz"], b["lo_khz"] + 1, b["hi_khz"] - 1, b["hi_khz"], b["hi_khz"] + 1):
                    for bw in (125, 250, 500):
                        self.assertIn((r["id"], bw, f), rows)
        self.assertEqual({len(c) for _, _, _, c in v["check_sweep"]["rows"]}, {6})
        self.assertEqual({len(c) for _, _, _, c in v["convert_sweep"]["rows"]}, {24})
        reasons = {REASON for _, _, _, c in v["check_sweep"]["rows"] for REASON in c}
        self.assertEqual(reasons, {0, 1, 2, 3})                    # the real table never misses power or time...
        syn = {x for _, _, c, _ in v["synthetic"]["sweep"] for x in c}
        self.assertEqual(syn, {0, 1, 2, 3, 5})                     # ...the synthetic one does (time)
        self.assertIn("POWER_FLOOR", {c["reason"] for c in v["check_devices"]})


if __name__ == "__main__":
    unittest.main()
