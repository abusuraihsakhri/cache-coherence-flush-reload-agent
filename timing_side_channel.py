#!/usr/bin/env python3
"""
Timing Side-Channel Detection for Cache Coherence Flush/Reload Agent.
Detects timing-based side-channel vulnerabilities in cache implementations.
"""

from typing import Dict, Any, List
import time
import random
import statistics


class TimingSideChannelAgent:
    """Agent for detecting timing-based side-channel vulnerabilities."""

    def __init__(self):
        self.agent_name = "TimingSideChannelAgent"

    def measure_cache_access_time(self, address: int, iterations: int = 1000) -> Dict[str, float]:
        """Measure cache access timing for an address."""
        times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            _ = address & 0xFFFFFFFF
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)

        return {
            "mean_ns": statistics.mean(times),
            "median_ns": statistics.median(times),
            "stddev_ns": statistics.stdev(times) if len(times) > 1 else 0,
            "min_ns": min(times),
            "max_ns": max(times),
        }

    def detect_flush_reload_channel(self, num_addresses: int = 16,
                                     iterations: int = 500) -> Dict[str, Any]:
        """Detect flush/reload side-channel timing differentials."""
        results = {"channels_detected": [], "timing_data": []}

        addresses = [random.randint(0x1000, 0xFFFF) for _ in range(num_addresses)]

        for addr in addresses:
            timing = self.measure_cache_access_time(addr, iterations)
            results["timing_data"].append({"address": hex(addr), **timing})

        mean_times = [r["mean_ns"] for r in results["timing_data"]]
        overall_mean = statistics.mean(mean_times)
        overall_std = statistics.stdev(mean_times) if len(mean_times) > 1 else 1

        for data in results["timing_data"]:
            z_score = (data["mean_ns"] - overall_mean) / max(overall_std, 1)
            if abs(z_score) > 2.0:
                results["channels_detected"].append({
                    "address": data["address"],
                    "mean_ns": data["mean_ns"],
                    "z_score": round(z_score, 2),
                    "likely_cached": data["mean_ns"] < overall_mean,
                })

        return results

    def detect_prime_probe_channel(self, num_sets: int = 8,
                                    probe_iterations: int = 100) -> Dict[str, Any]:
        """Detect prime+probe timing side-channel."""
        set_timings = {}
        for s in range(num_sets):
            times = []
            for _ in range(probe_iterations):
                start = time.perf_counter_ns()
                for offset in range(64):
                    _ = (s * 4096 + offset) & 0xFFFFFFFF
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)
            set_timings[s] = statistics.mean(times)

        overall_mean = statistics.mean(set_timings.values())
        anomalies = []
        for s, mean_t in set_timings.items():
            if abs(mean_t - overall_mean) / max(overall_mean, 1) > 0.3:
                anomalies.append({"set": s, "mean_ns": mean_t, "deviation": round((mean_t - overall_mean) / overall_mean, 3)})

        return {"set_timings": {hex(s * 4096): round(t, 1) for s, t in set_timings.items()},
                "anomalies": anomalies, "channel_detected": len(anomalies) > 0}

    def evaluate(self) -> Dict[str, Any]:
        """Run full timing side-channel evaluation."""
        flush_reload = self.detect_flush_reload_channel(8, 200)
        prime_probe = self.detect_prime_probe_channel(4, 50)

        alerts = []
        if flush_reload["channels_detected"]:
            alerts.append({
                "type": "FLUSH_RELOAD_CHANNEL", "severity": "CRITICAL",
                "message": f"{len(flush_reload['channels_detected'])} timing differentials detected.",
                "recommendation": "Implement constant-time cache access patterns."
            })
        if prime_probe["channel_detected"]:
            alerts.append({
                "type": "PRIME_PROBE_CHANNEL", "severity": "WARNING",
                "message": "Prime+probe timing anomaly detected.",
                "recommendation": "Consider cache partitioning or constant-time algorithms."
            })

        return {"flush_reload": flush_reload, "prime_probe": prime_probe, "alerts": alerts}
