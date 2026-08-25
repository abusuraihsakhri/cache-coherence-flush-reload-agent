#!/usr/bin/env python3
"""
Flush+Reload side-channel detector.

Models and analyzes clflush/rdtsc probe-round timings against a shared memory
line. Real analysis pipeline operating on cycle-count arrays:

  1. Automatic hit/miss threshold selection (largest-gap / Otsu-style split)
  2. Binary bit extraction from the classified reload pattern
  3. Signal quality scoring: Cohen's d' separation between hit and miss clusters
  4. Periodicity detection via normalized autocorrelation (victim cadence)

Includes a physically-motivated synthesizer (Gaussian hit ~200 cycles,
miss ~300 cycles) so the full attack->detection loop is executable offline.
"""

import math
import random
from statistics import mean, pstdev


HIT_MEAN_CYCLES = 200.0     # line resident in L1 after victim access
MISS_MEAN_CYCLES = 320.0    # line evicted -> DRAM round trip
NOISE_SIGMA = 18.0


def synthesize_probe_rounds(secret_bits, rounds_per_bit=8,
                            hit_mean=HIT_MEAN_CYCLES, miss_mean=MISS_MEAN_CYCLES,
                            sigma=NOISE_SIGMA, seed=1337) -> list:
    """Victim touches the line when the secret bit is 1 -> fast reload."""
    rng = random.Random(seed)
    timings = []
    for bit in secret_bits:
        for _ in range(rounds_per_bit):
            mu = hit_mean if bit else miss_mean
            timings.append(max(60.0, rng.gauss(mu, sigma)))
    return timings


def auto_threshold(timings: list) -> float:
    """Largest-gap threshold: sort timings, pick the widest gap as the hit/miss seam."""
    ordered = sorted(timings)
    gaps = [(ordered[i + 1] - ordered[i], (ordered[i] + ordered[i + 1]) / 2.0)
            for i in range(len(ordered) - 1)]
    _, threshold = max(gaps)
    return threshold


def classify_timings(timings: list, threshold: float = None) -> dict:
    """Classify each round as HIT (fast reload, line was accessed) or MISS."""
    if threshold is None:
        threshold = auto_threshold(timings)
    flags = [t < threshold for t in timings]
    hits = [t for t, h in zip(timings, flags) if h]
    misses = [t for t, h in zip(timings, flags) if not h]

    d_prime = 0.0
    if hits and misses:
        pooled = math.sqrt((pstdev(hits) ** 2 + pstdev(misses) ** 2) / 2.0) or 1e-9
        d_prime = abs(mean(misses) - mean(hits)) / pooled

    return {"threshold_cycles": round(threshold, 1),
            "hit_flags": flags,
            "hit_count": len(hits),
            "miss_count": len(misses),
            "separation_d_prime": round(d_prime, 2),
            "attack_confident": d_prime > 6.0}


def extract_bits(flags: list, rounds_per_bit: int) -> list:
    """Majority-vote one bit per window of probe rounds."""
    bits = []
    for i in range(0, len(flags), rounds_per_bit):
        window = flags[i:i + rounds_per_bit]
        bits.append(1 if sum(window) * 2 > len(window) else 0)
    return bits


def bits_to_text(bits: list) -> str:
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        chars.append(chr(byte))
    return "".join(chars)


def detect_periodicity(flags: list, max_lag: int = 32) -> dict:
    """Autocorrelation of the binary access series to expose victim cadence."""
    series = [1.0 if f else 0.0 for f in flags]
    n = len(series)
    m = mean(series) or 1e-9
    var = sum((x - m) ** 2 for x in series) or 1e-9
    best_lag, best_r = 0, 0.0
    for lag in range(1, min(max_lag, n - 1)):
        num = sum((series[i] - m) * (series[i + lag] - m) for i in range(n - lag))
        r = num / var
        if r > best_r:
            best_r, best_lag = r, lag
    return {"best_lag_rounds": best_lag, "autocorrelation": round(best_r, 3),
            "periodic_victim_detected": best_r > 0.35}


def analyze_shared_line(timings: list, rounds_per_bit: int) -> dict:
    """Full Flush+Reload forensic report from raw probe timings."""
    cls = classify_timings(timings)
    bits = extract_bits(cls["hit_flags"], rounds_per_bit)
    cls.update({"recovered_bits_len": len(bits),
                "leaked_text_guess": bits_to_text(bits)})
    cls["cadence"] = detect_periodicity(cls["hit_flags"])
    verdict = ("Flush+Reload exfiltration CONFIRMED" if cls["attack_confident"]
               else "No significant shared-line access detected")
    return {"verdict": verdict, **{k: v for k, v in cls.items() if k != "hit_flags"}}


if __name__ == "__main__":
    secret = [int(b) for ch in "Hi!" for b in format(ord(ch), "08b")]
    print(f"Victim secret: 'Hi!' ({len(secret)} bits)")
    timings = synthesize_probe_rounds(secret, seed=42)
    report = analyze_shared_line(timings, rounds_per_bit=8)
    print(f"\nverdict          : {report['verdict']}")
    print(f"threshold        : {report['threshold_cycles']} cycles")
    print(f"hits/misses      : {report['hit_count']}/{report['miss_count']}")
    print(f"d-prime          : {report['separation_d_prime']}")
    print(f"recovered text   : {report['leaked_text_guess']!r}")
    print(f"victim cadence   : lag={report['cadence']['best_lag_rounds']} "
          f"r={report['cadence']['autocorrelation']}")
