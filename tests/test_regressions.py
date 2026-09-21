import math

import pytest

from cache_coherence_flush_reload import (
    AttackType,
    CacheCoherenceFlushReloadAgent,
    MesiCoherenceEngine,
    TTableLeakageScanner,
)
from prime_probe_detector import analyze_llc


def test_prime_probe_baseline_has_real_variance():
    report = analyze_llc([0x1000, 0x2000, 0x3000], attacker_sets=32, ways=4)
    assert report["baseline_variance"] > 0
    assert report["f_ratio"] != "inf"
    assert math.isfinite(float(report["f_ratio"]))


def test_prime_probe_rejects_degenerate_geometry():
    with pytest.raises(ValueError):
        analyze_llc([0x1000], attacker_sets=1, ways=4)


def test_invalid_coherence_protocol_is_rejected():
    with pytest.raises(ValueError):
        MesiCoherenceEngine(num_cores=4, protocol="INVALID")


def test_negative_table_counts_are_rejected():
    with pytest.raises(ValueError):
        TTableLeakageScanner.evaluate_access_distribution([1] * 15 + [-1])


def test_report_preserves_requested_model_label():
    dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
        analysis_id="PRIME-PROBE-LABEL",
        secret_bitstring="1010",
        attack_type=AttackType.PRIME_PROBE,
    )
    assert dossier.attack_type is AttackType.PRIME_PROBE
    assert dossier.data_source == "synthetic"


def test_provided_timings_are_labeled_as_provided():
    dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
        analysis_id="PROVIDED",
        timings=[50, 55, 250, 260],
    )
    assert dossier.data_source == "provided"
