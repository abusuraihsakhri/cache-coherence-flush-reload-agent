#!/usr/bin/env python3
"""
Prime+Probe covert-channel detector and LLC contention analyzer.

Prime+Probe model: the attacker fills every cache set it can address, lets the
victim run, then re-times its own lines. Victim occupancy shows up as slower
self-reloads. This module implements the real analysis side:

  - Address -> LLC set-index mapping ((addr >> 6) mod n_sets) for standard
    64-byte lines and configurable slice/way geometry
  - Contention simulation: self-reload latency grows with victim occupancy
  - Covert-bit decoding from per-set latency deltas (largest-gap thresholding)
  - Cross-core contention anomaly detection via an F-ratio variance test

Stdlib only.
"""

import random
from statistics import mean, pstdev


LINE_SIZE_BYTES = 64


def llc_set_index(address: int, total_sets: int) -> int:
    """Standard physical-address-to-set mapping for inclusive LLCs."""
    return (address // LINE_SIZE_BYTES) % total_sets


def simulate_contention(victim_addresses: list, attacker_sets: int,
                        ways: int, baseline_cycles: float = 90.0,
                        penalty_per_way: float = 55.0, noise: float = 4.0,
                        seed=7) -> list:
    """Per-set measured reload latencies after victim execution.

    Latency = baseline + penalty x min(victim_lines_in_set, ways) + noise.
    A fully contended set (occupancy >= ways) is maximally slow.
    """
    rng = random.Random(seed)
    occupancy = [0] * attacker_sets
    for addr in victim_addresses:
        s = llc_set_index(addr, attacker_sets)
        occupancy[s] += 1
    return [baseline_cycles + penalty_per_way * min(o, ways) +
            rng.gauss(0, noise) for o in occupancy]


def decode_covert_bits(latencies: list, baseline_cycles: float) -> list:
    """One covert bit per monitored set: slow self-reload => sender wrote 1."""
    threshold = None
    ordered = sorted(latencies)
    gaps = [(ordered[i + 1] - ordered[i], (ordered[i] + ordered[i + 1]) / 2)
            for i in range(len(ordered) - 1)]
    if gaps:
        threshold = max(gaps)[1]
    else:
        threshold = baseline_cycles * 1.5
    return [1 if l > threshold else 0 for l in latencies]


def f_ratio(baseline_latencies: list, monitored_latencies: list) -> dict:
    """Variance-ratio test: contention inflates latency variance dramatically."""
    v0 = pstdev(baseline_latencies) ** 2
    v1 = pstdev(monitored_latencies) ** 2
    ratio = v1 / v0 if v0 > 0 else float("inf")
    return {
        "baseline_variance": round(v0, 2),
        "monitored_variance": round(v1, 2),
        "f_ratio": round(ratio, 2) if ratio != float("inf") else "inf",
        "contention_anomaly": ratio > 9.0,
    }


def estimate_channel_capacity(n_sets: int, rounds_per_second: float) -> float:
    """Raw covert-channel bandwidth in bits/s (one bit per set per round)."""
    return round(n_sets * rounds_per_second, 0)


def analyze_llc(victim_addresses: list, attacker_sets: int = 512,
                ways: int = 12, quiet_seed: int = 1) -> dict:
    """End-to-end Prime+Probe forensic pass."""
    idle = [random.Random(quiet_seed).gauss(90, 3) for _ in range(attacker_sets)]
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
    stats["capacity_bits_per_sec_at_1kHz"] = \
        estimate_channel_capacity(sum(bits) or 1, 1000.0)
    stats["verdict"] = ("Cross-core LLC contention detected (covert channel likely)"
                        if stats["contention_anomaly"] else "No abnormal contention")
    return stats


if __name__ == "__main__":
    rng = random.Random(2026)
    victim_pattern = [rng.randrange(0, 64 << 20) for _ in range(1400)]
    report = analyze_llc(victim_pattern)
    print("Prime+Probe LLC analysis")
    print("-" * 52)
    for k, v in report.items():
        print(f"{k:34s}: {v}")

    bits = decode_covert_bits(
        simulate_contention([i * LINE_SIZE_BYTES * 37 for i in range(256)], 256, 12), 90.0)
    print(f"\ndecoded covert word sample: {bits[:24]}")
