#!/usr/bin/env python3
"""
Cross-core Invalidation Agent for Cache Coherence Flush/Reload Agent.
Simulates and detects cross-core cache invalidation failures and stale data issues.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import time
import random


@dataclass
class CacheLine:
    """Represents a single cache line across cores."""
    address: int
    data: int
    valid: bool = True
    dirty: bool = False
    owner_core: int = 0
    state: str = "Shared"


class CrossCoreInvalidationAgent:
    """Agent for simulating and detecting cross-core cache invalidation failures."""

    def __init__(self, num_cores: int = 4):
        self.num_cores = num_cores
        self.agent_name = "CrossCoreInvalidationAgent"
        self.cores = {i: {} for i in range(num_cores)}

    def simulate_invalidation(self, address: int, data: int, core_id: int) -> Dict[str, Any]:
        """Simulate a write to address on a core and track invalidation."""
        events = []
        stale_detected = []

        for c in range(self.num_cores):
            if c != core_id and address in self.cores[c]:
                old_data = self.cores[c][address]["data"]
                if self.cores[c][address]["valid"] and old_data != data:
                    stale_detected.append({
                        "core": c,
                        "stale_value": old_data,
                        "new_value": data,
                    })
                self.cores[c][address]["valid"] = False
                self.cores[c][address]["state"] = "Invalid"
                events.append({
                    "type": "INVALIDATION",
                    "source_core": core_id,
                    "target_core": c,
                    "address": hex(address),
                    "success": True,
                })

        self.cores[core_id][address] = {
            "data": data, "valid": True, "dirty": True,
            "owner_core": core_id, "state": "Modified",
        }
        events.append({
            "type": "WRITE",
            "core": core_id,
            "address": hex(address),
            "value": data,
        })

        return {
            "address": hex(address),
            "write_core": core_id,
            "data": data,
            "events": events,
            "stale_detected": stale_detected,
            "invalidations_sent": len(events) - 1,
        }

    def detect_invalidation_failure(self) -> List[Dict[str, Any]]:
        """Detect stale cache lines across cores."""
        failures = []
        address_cores = {}
        for core_id, cache in self.cores.items():
            for addr, entry in cache.items():
                if entry["valid"]:
                    if addr not in address_cores:
                        address_cores[addr] = []
                    address_cores[addr].append({"core": core_id, "data": entry["data"]})

        for addr, entries in address_cores.items():
            if len(entries) > 1:
                unique_data = set(e["data"] for e in entries)
                if len(unique_data) > 1:
                    failures.append({
                        "address": hex(addr),
                        "stale_copies": entries,
                        "data_values": list(unique_data),
                        "severity": "CRITICAL",
                    })

        return failures

    def run_flush_reload_test(self, num_iterations: int = 100) -> Dict[str, Any]:
        """Run flush/reload test to detect timing-based invalidation issues."""
        results = {"flush_reload_hits": 0, "misses": 0, "timing_anomalies": []}

        for _ in range(num_iterations):
            addr = random.randint(0x1000, 0xFFFF)
            target_core = random.randint(0, self.num_cores - 1)
            self.simulate_invalidation(addr, random.randint(0, 0xFFFFFFFF), target_core)

            for c in range(self.num_cores):
                if c != target_core and addr in self.cores[c]:
                    start = time.perf_counter_ns()
                    hit = self.cores[c].get(addr, {}).get("valid", False)
                    elapsed_ns = time.perf_counter_ns() - start
                    if hit:
                        results["flush_reload_hits"] += 1
                        if elapsed_ns < 100:
                            results["timing_anomalies"].append({
                                "core": c, "time_ns": elapsed_ns,
                                "note": "Suspiciously fast hit after invalidation",
                            })
                    else:
                        results["misses"] += 1

        results["hit_rate"] = (results["flush_reload_hits"] /
                               max(1, results["flush_reload_hits"] + results["misses"]))
        return results

    def evaluate(self) -> Dict[str, Any]:
        """Run full cross-core invalidation evaluation."""
        for addr in range(0x1000, 0x1020):
            self.simulate_invalidation(addr, random.randint(0, 0xFFFFFFFF), random.randint(0, self.num_cores - 1))

        failures = self.detect_invalidation_failure()
        flush_reload = self.run_flush_reload_test(50)

        alerts = []
        if failures:
            alerts.append({
                "type": "STALE_CACHE_DETECTED", "severity": "CRITICAL",
                "message": f"{len(failures)} stale cache line(s) detected.",
                "recommendation": "Review cache coherence protocol implementation."
            })
        if flush_reload["timing_anomalies"]:
            alerts.append({
                "type": "TIMING_ANOMALY", "severity": "WARNING",
                "message": f"{len(flush_reload['timing_anomalies'])} timing anomalies detected.",
                "recommendation": "Investigate false sharing or memory ordering issues."
            })

        return {"failures": failures, "flush_reload": flush_reload, "alerts": alerts}
