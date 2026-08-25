"""
Unit Test Suite for Cache Coherence & Flush+Reload Security Agent
=================================================================
Comprehensive verification of microarchitectural timing discrimination,
Otsu threshold calibration, MESI/MOESI coherence state transitions,
AES T-table side-channel entropy analysis, and threat severity classification.
"""

import json
import unittest

from cache_coherence_flush_reload import (
    AttackType,
    ThreatSeverity,
    CoherenceState,
    MesiCoherenceEngine,
    FlushReloadEngine,
    TTableLeakageScanner,
    CacheCoherenceFlushReloadAgent,
    format_security_dossier,
)
import cli


class TestTimingDiscriminationAndOtsu(unittest.TestCase):
    """Test timing trace generation, threshold calibration, and bit extraction."""

    def test_synthesize_traces_length_and_separation(self):
        bits = [1, 0, 1, 1, 0]
        rounds = 8
        traces = FlushReloadEngine.synthesize_traces(bits, rounds_per_bit=rounds, seed=42)
        self.assertEqual(len(traces), len(bits) * rounds)
        # Verify hit vs miss means
        hit_samples = traces[0:8]  # First bit is 1 -> Hit
        miss_samples = traces[8:16]  # Second bit is 0 -> Miss
        self.assertLess(sum(hit_samples) / len(hit_samples), 120.0)
        self.assertGreater(sum(miss_samples) / len(miss_samples), 200.0)

    def test_otsu_threshold_bimodal(self):
        hits = [60.0, 70.0, 75.0, 80.0, 85.0]
        misses = [260.0, 275.0, 280.0, 290.0, 310.0]
        all_timings = hits + misses
        thresh = FlushReloadEngine.compute_otsu_threshold(all_timings)
        self.assertGreater(thresh, 85.0)
        self.assertLess(thresh, 260.0)

    def test_analyze_timings_perfect_extraction(self):
        secret = [1, 0, 1, 0, 1]
        timings = FlushReloadEngine.synthesize_traces(secret, rounds_per_bit=10, seed=123)
        res = FlushReloadEngine.analyze_timings(timings, rounds_per_bit=10)
        self.assertEqual(res.extracted_bitstring, "10101")
        self.assertTrue(res.channel_confident)
        self.assertGreater(res.cohens_d_prime, 4.0)
        self.assertGreater(res.snr_db, 15.0)

    def test_empty_timings_raises_error(self):
        with self.assertRaises(ValueError):
            FlushReloadEngine.analyze_timings([])


class TestCoherenceProtocols(unittest.TestCase):
    """Test MESI / MOESI protocol state machines and cross-core invalidations."""

    def test_mesi_read_miss_to_exclusive(self):
        engine = MesiCoherenceEngine(num_cores=4, protocol="MESI")
        st = engine.processor_read(core_id=0, address=0x1000)
        self.assertEqual(st, CoherenceState.EXCLUSIVE)
        self.assertEqual(engine.get_state(0, 0x1000), CoherenceState.EXCLUSIVE)

    def test_mesi_second_core_read_transitions_to_shared(self):
        engine = MesiCoherenceEngine(num_cores=4, protocol="MESI")
        engine.processor_read(core_id=0, address=0x1000)
        st2 = engine.processor_read(core_id=1, address=0x1000)
        self.assertEqual(st2, CoherenceState.SHARED)
        self.assertEqual(engine.get_state(0, 0x1000), CoherenceState.SHARED)
        self.assertEqual(engine.get_state(1, 0x1000), CoherenceState.SHARED)

    def test_mesi_write_invalidates_peers(self):
        engine = MesiCoherenceEngine(num_cores=4, protocol="MESI")
        engine.processor_read(0, 0x1000)
        engine.processor_read(1, 0x1000)
        # Core 2 writes -> must become Modified, invalidating Core 0 and 1
        st_wr = engine.processor_write(core_id=2, address=0x1000, data=0x9999)
        self.assertEqual(st_wr, CoherenceState.MODIFIED)
        self.assertEqual(engine.get_state(0, 0x1000), CoherenceState.INVALID)
        self.assertEqual(engine.get_state(1, 0x1000), CoherenceState.INVALID)
        self.assertGreaterEqual(engine.invalidations_count, 2)

    def test_moesi_owner_state_transition(self):
        engine = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
        engine.processor_write(core_id=0, address=0x5000, data=0xAAAA)
        self.assertEqual(engine.get_state(0, 0x5000), CoherenceState.MODIFIED)

        # Core 1 reads -> Core 0 becomes OWNER in MOESI
        engine.processor_read(core_id=1, address=0x5000)
        self.assertEqual(engine.get_state(0, 0x5000), CoherenceState.OWNER)
        self.assertEqual(engine.get_state(1, 0x5000), CoherenceState.SHARED)

    def test_clflush_eviction_all_cores(self):
        engine = MesiCoherenceEngine(num_cores=4)
        engine.processor_read(0, 0x3000)
        engine.processor_read(1, 0x3000)
        flushed = engine.flush_line(core_id=2, address=0x3000)
        self.assertEqual(flushed, 2)
        self.assertEqual(engine.get_state(0, 0x3000), CoherenceState.INVALID)
        self.assertEqual(engine.get_state(1, 0x3000), CoherenceState.INVALID)


class TestTTableEntropyAnalysis(unittest.TestCase):
    """Test cryptographic AES T-table access distribution and key leakage detection."""

    def test_uniform_distribution_no_leakage(self):
        # 16 equal counts -> max entropy 4.0 bits
        uniform_counts = [50] * 16
        res = TTableLeakageScanner.evaluate_access_distribution(uniform_counts)
        self.assertAlmostEqual(res.entropy_score, 4.0, places=2)
        self.assertFalse(res.leakage_detected)

    def test_skewed_distribution_leakage_detected(self):
        # Line 4 has 400 accesses, other lines have 5 accesses
        skewed = [5, 4, 3, 5, 400, 4, 2, 3, 5, 2, 4, 3, 2, 5, 4, 3]
        res = TTableLeakageScanner.evaluate_access_distribution(skewed)
        self.assertTrue(res.leakage_detected)
        self.assertEqual(res.hottest_cache_line, 4)
        self.assertLess(res.entropy_score, 2.0)
        self.assertEqual(res.candidate_key_byte_rank[0], 4)

    def test_zero_accesses_handled_safely(self):
        zero_counts = [0] * 16
        res = TTableLeakageScanner.evaluate_access_distribution(zero_counts)
        self.assertFalse(res.leakage_detected)
        self.assertEqual(res.entropy_score, 4.0)


class TestSecurityCoordinatorAndAuditor(unittest.TestCase):
    """Test end-to-end audit engine, severity classification, and reports."""

    def test_full_security_audit_critical(self):
        skewed = [5, 4, 3, 5, 400, 4, 2, 3, 5, 2, 4, 3, 2, 5, 4, 3]
        dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
            analysis_id="AUDIT-CRIT-01",
            secret_bitstring="11011",
            ttable_counts=skewed,
            flush_rate_per_sec=150000.0
        )
        self.assertEqual(dossier.threat_severity, ThreatSeverity.CRITICAL)
        self.assertGreater(dossier.hpc_anomaly_score, 50.0)
        self.assertTrue(any("AES-NI" in m for m in dossier.mitigation_recommendations))

    def test_full_security_audit_high(self):
        dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
            analysis_id="AUDIT-HIGH-01",
            secret_bitstring="11001",
            flush_rate_per_sec=20000.0
        )
        self.assertEqual(dossier.threat_severity, ThreatSeverity.HIGH)

    def test_dossier_serialization_and_formatting(self):
        dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
            analysis_id="AUDIT-FMT-01",
            secret_bitstring="1010"
        )
        # JSON
        d = dossier.to_dict()
        self.assertEqual(d["analysis_id"], "AUDIT-FMT-01")
        j = dossier.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["analysis_id"], "AUDIT-FMT-01")

        # Text Formatting
        txt = format_security_dossier(dossier)
        self.assertIn("CACHE COHERENCE & FLUSH+RELOAD SECURITY AUDIT", txt)
        self.assertIn("AUDIT-FMT-01", txt)


class TestCLIExecution(unittest.TestCase):
    """Test CLI commands and argument flags."""

    def test_cli_demos(self):
        self.assertEqual(cli.main(["--demo", "flush_reload"]), 0)
        self.assertEqual(cli.main(["--demo", "ttable_leak"]), 0)
        self.assertEqual(cli.main(["--demo", "coherence_race"]), 0)
        self.assertEqual(cli.main(["--demo", "prime_probe"]), 0)

    def test_manual_threshold_override(self):
        timings = [50.0, 60.0, 200.0, 250.0]
        res = FlushReloadEngine.analyze_timings(timings, manual_threshold=100.0)
        self.assertEqual(res.optimal_threshold_cycles, 100.0)
        self.assertEqual(res.hit_count, 2)
        self.assertEqual(res.miss_count, 2)

    def test_single_class_timings_all_hits(self):
        timings = [50.0, 55.0, 60.0]
        res = FlushReloadEngine.analyze_timings(timings, manual_threshold=100.0)
        self.assertEqual(res.hit_count, 3)
        self.assertEqual(res.miss_count, 0)
        self.assertFalse(res.channel_confident)

    def test_moesi_multiple_readers_sharing(self):
        engine = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
        engine.processor_write(core_id=0, address=0x8000, data=0x5555)
        # Core 1 and Core 2 read
        engine.processor_read(core_id=1, address=0x8000)
        engine.processor_read(core_id=2, address=0x8000)
        self.assertEqual(engine.get_state(0, 0x8000), CoherenceState.OWNER)
        self.assertEqual(engine.get_state(1, 0x8000), CoherenceState.SHARED)
        self.assertEqual(engine.get_state(2, 0x8000), CoherenceState.SHARED)

    def test_ttable_padding_and_truncation(self):
        # Pass list with 8 elements -> should auto-pad to 16
        short_counts = [10] * 8
        res = TTableLeakageScanner.evaluate_access_distribution(short_counts)
        self.assertEqual(res.total_lines_monitored, 16)
        self.assertEqual(len(res.access_frequencies), 16)

    def test_cli_explicit_timings_arg(self):
        ret = cli.main([
            "--analysis-id", "CLI-EXPLICIT",
            "--timings", "60,65,70,280,290,300",
            "--threshold", "150.0",
            "--json"
        ])
        self.assertEqual(ret, 0)

    def test_cli_ttable_counts_arg(self):
        tt_str = "1,1,1,1,200,1,1,1,1,1,1,1,1,1,1,1"
        ret = cli.main([
            "--analysis-id", "CLI-TTABLE",
            "--ttable-counts", tt_str,
            "--json"
        ])
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
