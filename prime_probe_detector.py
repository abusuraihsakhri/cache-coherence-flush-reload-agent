#!/usr/bin/env python3
"""
Prime+Probe contention simulator and LLC timing analyzer.

This module operates on synthetic or user-supplied timing data. It does not
perform privileged cache probing or access another process. The routines are
intended for defensive analysis, teaching, and regression testing.
"""

import math
import random
from statistics import mean, pstdev


LINE_SIZE_BYTES = 64


def llc_set_index(address: int, total_sets: int) -> int:
    """Return the simplified cache-set index for a byte address."""
    if total_sets <= 0:
        raise ValueError("total_sets must be greater than zero")
    if address < 0:
        raise ValueError("address must be non-negative")
    return (address // LINE_SIZE_BYTES) % total_sets


def simulate_contention(
    victim_addresses: list[int],
    attacker_sets: int,
    ways: int,
    baseline_cycles: float = 90.0,
    penalty_per_way: float = 55.0,
    noise: float = 4.0,
    seed: int = 7,
) -> list[float]:
    """Generate per-set synthetic reload latencies after modeled contention."""
    if attacker_sets < 2:
        raise ValueError("attacker_sets must be at least 2")
    if ways <= 0:
        raise ValueError("ways must be greater than zero")
    if baseline_cycles <= 0 or penalty_per_way < 0 or noise < 0:
        raise ValueError("timing parameters must be non-negative and baseline must be positive")

    rng = random.Random(seed)
    occupancy = [0] * attacker_sets
    for addr in victim_addresses:
        occupancy[llc_set_index(addr, attacker_sets)] += 1

    return [
        baseline_cycles + penalty_per_way * min(count, ways) + rng.gauss(0, noise)
        for count in occupancy
    ]


def decode_covert_bits(latencies: list[float], baseline_cycles: float) -> list[int]:
    """Classify each monitored set as low- or high-contention using a gap threshold."""
    if baseline_cycles <= 0:
        raise ValueError("baseline_cycles must be greater than zero")
    if not latencies:
        return []
    if any(not math.isfinite(value) for value in latencies):
        raise ValueError("latencies must contain only finite values")

    ordered = sorted(latencies)
    gaps = [
        (ordered[i + 1] - ordered[i], (ordered[i] + ordered[i + 1]) / 2)
        for i in range(len(ordered) - 1)
    ]
    threshold = max(gaps)[1] if gaps else baseline_cycles * 1.5
    return [1 if latency > threshold else 0 for latency in latencies]


def f_ratio(baseline_latencies: list[float], monitored_latencies: list[float]) -> dict:
    """Compare timing variance as a simple contention-screening heuristic."""
    if len(baseline_latencies) < 2 or len(monitored_latencies) < 2:
        raise ValueError("at least two samples are required in each latency series")
    if any(not math.isfinite(value) for value in baseline_latencies + monitored_latencies):
        raise ValueError("latency series must contain only finite values")

    baseline_variance = pstdev(baseline_latencies) ** 2
    monitored_variance = pstdev(monitored_latencies) ** 2

    if baseline_variance <= 1e-12:
        ratio = float("inf")
        anomaly = False
    else:
        ratio = monitored_variance / baseline_variance
        anomaly = ratio > 9.0

    return {
        "baseline_variance": round(baseline_variance, 2),
        "monitored_variance": round(monitored_variance, 2),
        "f_ratio": round(ratio, 2) if math.isfinite(ratio) else "inf",
        "contention_anomaly": anomaly,
    }


def estimate_channel_capacity(n_sets: int, rounds_per_second: float) -> float:
    """Return a theoretical raw bit-rate for the simplified simulation."""
    if n_sets < 0 or rounds_per_second < 0:
        raise ValueError("n_sets and rounds_per_second must be non-negative")
    return round(n_sets * rounds_per_second, 0)


def analyze_llc(
    victim_addresses: list[int],
    attacker_sets: int = 512,
    ways: int = 12,
    quiet_seed: int = 1,
) -> dict:
    """Run an end-to-end synthetic LLC contention analysis."""
    if attacker_sets < 2:
        raise ValueError("attacker_sets must be at least 2")
    if ways <= 0:
        raise ValueError("ways must be greater than zero")

    quiet_rng = random.Random(quiet_seed)
    idle = [quiet_rng.gauss(90, 3) for _ in range(attacker_sets)]
    measured = simulate_contention(victim_addresses, attacker_sets, ways)
    bits = decode_covert_bits(measured, 90.0)

    stats = {
        "sets_monitored": attacker_sets,
        "ways_per_set": ways,
        "victim_touches": len(victim_addresses),
        "contended_sets_pct": round(100.0 * sum(bits) / len(bits), 1),
        "mean_latency_quiet": round(mean(idle), 1),
        "mean_latency_monitored": round(mean(measured), 1),
    }
    stats.update(f_ratio(idle, measured))
    stats["capacity_bits_per_sec_at_1kHz"] = estimate_channel_capacity(sum(bits) or 1, 1000.0)
    stats["verdict"] = (
        "Modeled contention pattern exceeds the variance threshold"
        if stats["contention_anomaly"]
        else "No modeled contention anomaly detected"
    )
    return stats


if __name__ == "__main__":
    rng = random.Random(2026)
    victim_pattern = [rng.randrange(0, 64 << 20) for _ in range(1400)]
    report = analyze_llc(victim_pattern)
    print("Prime+Probe LLC simulation")
    print("-" * 52)
    for key, value in report.items():
        print(f"{key:34s}: {value}")
