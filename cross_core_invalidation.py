#!/usr/bin/env python3
"""
Cross-core Invalidation Agent for Cache Coherence Flush/Reload Agent.
Simulates and detects cross-core cache invalidation failures and stale data issues.
"""

from typing import Dict, Any, List
from dataclasses import dataclass
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
        if num_cores < 2:
            raise ValueError("num_cores must be at least 2")
        self.num_cores = num_cores
        self.agent_name = "CrossCoreInvalidationAgent"
        self.cores = {i: {} for i in range(num_cores)}

    def _validate_core(self, core_id: int) -> None:
        if core_id not in self.cores:
            raise ValueError(f"core_id must be between 0 and {self.num_cores - 1}")

    def simulate_invalidation(self, address: int, data: int, core_id: int) -> Dict[str, Any]:
        """Simulate a write to an address and track peer invalidations."""
        self._validate_core(core_id)
        if address < 0:
            raise ValueError("address must be non-negative")
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

    def run_flush_reload_test(self, num_iterations: int = 100, seed: int = 2026) -> Dict[str, Any]:
        """Run a deterministic invalidation-consistency simulation.

        The method name is retained for API compatibility. No hardware timing or
        cross-process probing is performed.
        """
        if num_iterations <= 0:
            raise ValueError("num_iterations must be greater than zero")
        rng = random.Random(seed)
        results = {"flush_reload_hits": 0, "misses": 0, "timing_anomalies": []}

        for iteration in range(num_iterations):
            address = 0x1000 + iteration * 64
            writer = rng.randrange(self.num_cores)
            observer = (writer + 1) % self.num_cores
            old_value = rng.randrange(0x100000000)
            new_value = old_value ^ 0xFFFFFFFF

            self.cores[observer][address] = {
                "data": old_value,
                "valid": True,
                "dirty": False,
                "owner_core": observer,
                "state": "Shared",
            }
            self.simulate_invalidation(address, new_value, writer)

            still_valid = self.cores[observer][address]["valid"]
            if still_valid:
                results["flush_reload_hits"] += 1
                results["timing_anomalies"].append({
                    "core": observer,
                    "address": hex(address),
                    "note": "Peer line remained valid after modeled invalidation",
                })
            else:
                results["misses"] += 1

        results["hit_rate"] = results["flush_reload_hits"] / num_iterations
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
