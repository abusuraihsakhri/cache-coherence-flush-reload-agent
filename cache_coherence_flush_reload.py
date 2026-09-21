"""
Cache timing analysis and MESI/MOESI coherence simulation utilities.

The module works with synthetic or user-supplied timing traces. It does not
perform privileged cache operations or inspect another process. Results are
heuristics for defensive analysis and education, not proof of a live attack.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class CoherenceState(str, Enum):
    MODIFIED = "M"
    OWNER = "O"
    EXCLUSIVE = "E"
    SHARED = "S"
    INVALID = "I"


class AttackType(str, Enum):
    FLUSH_RELOAD = "Flush+Reload"
    PRIME_PROBE = "Prime+Probe"
    FLUSH_FLUSH = "Flush+Flush"
    INVALIDATION_RACE = "Cross-Core Invalidation Race"


class ThreatSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class TimingAnalysisResult:
    """Statistical summary of cache access timings."""

    total_samples: int
    optimal_threshold_cycles: float
    hit_count: int
    miss_count: int
    hit_mean_cycles: float
    miss_mean_cycles: float
    hit_std_cycles: float
    miss_std_cycles: float
    cohens_d_prime: float
    snr_db: float
    channel_confident: bool
    extracted_bitstring: str


@dataclass
class CoherenceEvent:
    """Single modeled coherence transaction across cores."""

    source_core: int
    action: str
    address: int
    target_core: Optional[int]
    old_state: str
    new_state: str
    is_invalidation: bool = False
    is_stale_read: bool = False


@dataclass
class TTableAnalysisResult:
    """Summary of cache-line access distribution for a 16-line table."""

    table_index: int
    total_lines_monitored: int
    access_frequencies: List[int]
    hottest_cache_line: int
    entropy_score: float
    leakage_detected: bool
    candidate_key_byte_rank: List[int]


@dataclass
class SideChannelDossier:
    """Combined timing/coherence analysis report."""

    analysis_id: str
    attack_type: AttackType
    threat_severity: ThreatSeverity
    data_source: str
    timing_analysis: Optional[TimingAnalysisResult]
    coherence_events_count: int
    stale_access_count: int
    ttable_leakage: Optional[TTableAnalysisResult]
    hpc_anomaly_score: float
    mitigation_recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["attack_type"] = self.attack_type.value
        data["threat_severity"] = self.threat_severity.value
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class FlushReloadEngine:
    """Timing-trace synthesizer and two-cluster analyzer."""

    L1_HIT_CYCLES = 40.0
    LLC_HIT_CYCLES = 80.0
    DRAM_MISS_CYCLES = 280.0
    DEFAULT_SIGMA = 15.0

    @staticmethod
    def _validated_timings(timings: List[float]) -> List[float]:
        if not timings:
            raise ValueError("Timing array cannot be empty.")
        values = [float(value) for value in timings]
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("Timings must be finite, non-negative numbers.")
        return values

    @classmethod
    def synthesize_traces(
        cls,
        secret_bits: List[int],
        rounds_per_bit: int = 10,
        hit_mean: float = 75.0,
        miss_mean: float = 280.0,
        noise_sigma: float = 16.0,
        seed: int = 42,
    ) -> List[float]:
        """Generate a deterministic synthetic two-cluster timing trace."""
        if not secret_bits:
            raise ValueError("secret_bits cannot be empty")
        if any(bit not in (0, 1) for bit in secret_bits):
            raise ValueError("secret_bits must contain only 0 and 1")
        if rounds_per_bit <= 0:
            raise ValueError("rounds_per_bit must be greater than zero")
        if hit_mean < 0 or miss_mean < 0 or noise_sigma < 0:
            raise ValueError("timing parameters must be non-negative")

        rng = random.Random(seed)
        timings: List[float] = []
        for bit in secret_bits:
            for _ in range(rounds_per_bit):
                mean_value = hit_mean if bit == 1 else miss_mean
                value = max(10.0, rng.gauss(mean_value, noise_sigma))
                timings.append(round(value, 1))
        return timings

    @classmethod
    def compute_otsu_threshold(cls, timings: List[float]) -> float:
        """Compute an Otsu-style threshold for a one-dimensional timing series."""
        values = cls._validated_timings(timings)
        if len(values) < 2:
            return values[0]

        sorted_timings = sorted(values)
        min_t, max_t = sorted_timings[0], sorted_timings[-1]
        if min_t == max_t:
            return min_t

        num_bins = min(100, max(10, len(values) // 2))
        bin_width = (max_t - min_t) / num_bins
        bins = [0] * num_bins

        for timing in values:
            idx = min(int((timing - min_t) / bin_width), num_bins - 1)
            bins[idx] += 1

        total = len(values)
        sum_total = sum(i * bins[i] for i in range(num_bins))
        weight_bg = 0
        sum_bg = 0
        max_variance = -1.0
        best_bin = 0

        for i in range(num_bins):
            weight_bg += bins[i]
            if weight_bg == 0:
                continue
            weight_fg = total - weight_bg
            if weight_fg == 0:
                break

            sum_bg += i * bins[i]
            mean_bg = sum_bg / weight_bg
            mean_fg = (sum_total - sum_bg) / weight_fg
            variance_between = weight_bg * weight_fg * (mean_bg - mean_fg) ** 2

            if variance_between > max_variance:
                max_variance = variance_between
                best_bin = i

        return round(min_t + (best_bin + 0.5) * bin_width, 1)

    @classmethod
    def analyze_timings(
        cls,
        timings: List[float],
        rounds_per_bit: int = 10,
        manual_threshold: Optional[float] = None,
    ) -> TimingAnalysisResult:
        """Classify a timing series, summarize separation, and group binary states."""
        values = cls._validated_timings(timings)
        if rounds_per_bit <= 0:
            raise ValueError("rounds_per_bit must be greater than zero")

        if manual_threshold is not None:
            threshold = float(manual_threshold)
            if not math.isfinite(threshold) or threshold < 0:
                raise ValueError("manual_threshold must be a finite, non-negative number")
        else:
            threshold = cls.compute_otsu_threshold(values)

        hits = [value for value in values if value < threshold]
        misses = [value for value in values if value >= threshold]

        hit_mean = sum(hits) / len(hits) if hits else 0.0
        miss_mean = sum(misses) / len(misses) if misses else 0.0

        hit_var = (
            sum((value - hit_mean) ** 2 for value in hits) / (len(hits) - 1)
            if len(hits) > 1
            else 0.0
        )
        miss_var = (
            sum((value - miss_mean) ** 2 for value in misses) / (len(misses) - 1)
            if len(misses) > 1
            else 0.0
        )

        hit_std = math.sqrt(hit_var)
        miss_std = math.sqrt(miss_var)
        both_classes = bool(hits and misses)
        pooled_std = math.sqrt((hit_var + miss_var) / 2.0) if both_classes else 0.0
        delta = abs(miss_mean - hit_mean) if both_classes else 0.0

        if both_classes and pooled_std > 1e-12:
            d_prime = delta / pooled_std
            snr_db = 20.0 * math.log10(max(1e-12, delta / pooled_std))
        else:
            d_prime = 0.0
            snr_db = 0.0

        extracted_bits = []
        for i in range(0, len(values), rounds_per_bit):
            chunk = values[i : i + rounds_per_bit]
            hit_in_chunk = sum(1 for value in chunk if value < threshold)
            extracted_bits.append("1" if hit_in_chunk > (len(chunk) / 2) else "0")

        return TimingAnalysisResult(
            total_samples=len(values),
            optimal_threshold_cycles=round(threshold, 1),
            hit_count=len(hits),
            miss_count=len(misses),
            hit_mean_cycles=round(hit_mean, 2),
            miss_mean_cycles=round(miss_mean, 2),
            hit_std_cycles=round(hit_std, 2),
            miss_std_cycles=round(miss_std, 2),
            cohens_d_prime=round(d_prime, 2),
            snr_db=round(snr_db, 2),
            channel_confident=(d_prime >= 3.5 and both_classes),
            extracted_bitstring="".join(extracted_bits),
        )


class MesiCoherenceEngine:
    """Small MESI/MOESI state-machine simulator for coherence behavior."""

    def __init__(self, num_cores: int = 4, protocol: str = "MOESI"):
        if num_cores <= 0:
            raise ValueError("num_cores must be greater than zero")
        normalized_protocol = protocol.upper()
        if normalized_protocol not in {"MESI", "MOESI"}:
            raise ValueError("protocol must be 'MESI' or 'MOESI'")

        self.num_cores = num_cores
        self.protocol = normalized_protocol
        self.cores: Dict[int, Dict[int, Dict[str, Any]]] = {c: {} for c in range(num_cores)}
        self.event_log: List[CoherenceEvent] = []
        self.stale_reads_count = 0
        self.invalidations_count = 0

    def _validate_request(self, core_id: int, address: int) -> None:
        if core_id not in self.cores:
            raise ValueError(f"core_id must be between 0 and {self.num_cores - 1}")
        if not isinstance(address, int) or address < 0:
            raise ValueError("address must be a non-negative integer")

    def get_state(self, core_id: int, address: int) -> CoherenceState:
        self._validate_request(core_id, address)
        line = self.cores[core_id].get(address)
        if line is None:
            return CoherenceState.INVALID
        return line.get("state", CoherenceState.INVALID)

    def processor_read(self, core_id: int, address: int) -> CoherenceState:
        """Simulate a processor read request on one core."""
        self._validate_request(core_id, address)
        current_state = self.get_state(core_id, address)

        if current_state in {
            CoherenceState.MODIFIED,
            CoherenceState.OWNER,
            CoherenceState.EXCLUSIVE,
            CoherenceState.SHARED,
        }:
            self.event_log.append(
                CoherenceEvent(
                    source_core=core_id,
                    action="PrRd_Hit",
                    address=address,
                    target_core=None,
                    old_state=current_state.value,
                    new_state=current_state.value,
                )
            )
            return current_state

        other_holders = [
            core
            for core in range(self.num_cores)
            if core != core_id and self.get_state(core, address) != CoherenceState.INVALID
        ]

        if not other_holders:
            new_state = CoherenceState.EXCLUSIVE
            self.cores[core_id][address] = {
                "state": new_state,
                "data": 0xCAFE,
                "dirty": False,
            }
        else:
            new_state = CoherenceState.SHARED
            self.cores[core_id][address] = {
                "state": new_state,
                "data": 0xCAFE,
                "dirty": False,
            }

            for other_core in other_holders:
                other_state = self.get_state(other_core, address)
                if other_state == CoherenceState.EXCLUSIVE:
                    self.cores[other_core][address]["state"] = CoherenceState.SHARED
                elif other_state == CoherenceState.MODIFIED:
                    if self.protocol == "MOESI":
                        self.cores[other_core][address]["state"] = CoherenceState.OWNER
                    else:
                        self.cores[other_core][address]["state"] = CoherenceState.SHARED
                        self.cores[other_core][address]["dirty"] = False

        self.event_log.append(
            CoherenceEvent(
                source_core=core_id,
                action="PrRd_Miss->BusRd",
                address=address,
                target_core=None,
                old_state=current_state.value,
                new_state=new_state.value,
            )
        )
        return new_state

    def processor_write(self, core_id: int, address: int, data: int = 0xDEAD) -> CoherenceState:
        """Simulate a processor write and peer invalidations."""
        self._validate_request(core_id, address)
        current_state = self.get_state(core_id, address)

        for other_core in range(self.num_cores):
            if other_core == core_id or address not in self.cores[other_core]:
                continue
            other_state = self.get_state(other_core, address)
            if other_state != CoherenceState.INVALID:
                self.cores[other_core][address]["state"] = CoherenceState.INVALID
                self.invalidations_count += 1
                self.event_log.append(
                    CoherenceEvent(
                        source_core=core_id,
                        action="BusUpgr/Invalidate",
                        address=address,
                        target_core=other_core,
                        old_state=other_state.value,
                        new_state=CoherenceState.INVALID.value,
                        is_invalidation=True,
                    )
                )

        new_state = CoherenceState.MODIFIED
        self.cores[core_id][address] = {"state": new_state, "data": data, "dirty": True}
        self.event_log.append(
            CoherenceEvent(
                source_core=core_id,
                action="PrWr->Modified",
                address=address,
                target_core=None,
                old_state=current_state.value,
                new_state=new_state.value,
            )
        )
        return new_state

    def flush_line(self, core_id: int, address: int) -> int:
        """Simulate invalidating one cache line across modeled cores."""
        self._validate_request(core_id, address)
        flushed_count = 0
        for core in range(self.num_cores):
            if address not in self.cores[core]:
                continue
            old_state = self.get_state(core, address)
            if old_state == CoherenceState.INVALID:
                continue
            self.cores[core][address]["state"] = CoherenceState.INVALID
            flushed_count += 1
            self.event_log.append(
                CoherenceEvent(
                    source_core=core_id,
                    action="clflush",
                    address=address,
                    target_core=core,
                    old_state=old_state.value,
                    new_state=CoherenceState.INVALID.value,
                    is_invalidation=True,
                )
            )
        return flushed_count


class TTableLeakageScanner:
    """Evaluate a 16-line table access distribution with entropy heuristics."""

    NUM_TABLES = 4
    LINES_PER_TABLE = 16

    @classmethod
    def evaluate_access_distribution(
        cls, access_counts: List[int], table_idx: int = 0
    ) -> TTableAnalysisResult:
        if not 0 <= table_idx < cls.NUM_TABLES:
            raise ValueError(f"table_idx must be between 0 and {cls.NUM_TABLES - 1}")
        if any(int(value) != value or value < 0 for value in access_counts):
            raise ValueError("access_counts must contain non-negative integers")

        counts = [int(value) for value in access_counts]
        if len(counts) != cls.LINES_PER_TABLE:
            counts = (counts + [0] * cls.LINES_PER_TABLE)[: cls.LINES_PER_TABLE]

        total_accesses = sum(counts)
        if total_accesses == 0:
            return TTableAnalysisResult(
                table_index=table_idx,
                total_lines_monitored=cls.LINES_PER_TABLE,
                access_frequencies=counts,
                hottest_cache_line=0,
                entropy_score=4.0,
                leakage_detected=False,
                candidate_key_byte_rank=list(range(cls.LINES_PER_TABLE)),
            )

        entropy = 0.0
        for count in counts:
            if count > 0:
                probability = count / total_accesses
                entropy -= probability * math.log2(probability)

        hottest_line = counts.index(max(counts))
        ranked = sorted(range(cls.LINES_PER_TABLE), key=lambda i: counts[i], reverse=True)
        dominant_fraction = max(counts) / total_accesses
        is_skewed = (entropy < 3.2 and total_accesses >= 50) or dominant_fraction > 0.35

        return TTableAnalysisResult(
            table_index=table_idx,
            total_lines_monitored=cls.LINES_PER_TABLE,
            access_frequencies=counts,
            hottest_cache_line=hottest_line,
            entropy_score=round(entropy, 3),
            leakage_detected=is_skewed,
            candidate_key_byte_rank=ranked,
        )


class CacheCoherenceFlushReloadAgent:
    """Coordinate timing, coherence, and access-distribution heuristics."""

    @classmethod
    def run_full_security_audit(
        cls,
        analysis_id: str = "SEC-AUDIT-01",
        timings: Optional[List[float]] = None,
        secret_bitstring: Optional[str] = None,
        coherence_engine: Optional[MesiCoherenceEngine] = None,
        ttable_counts: Optional[List[int]] = None,
        flush_rate_per_sec: float = 0.0,
        attack_type: AttackType = AttackType.FLUSH_RELOAD,
    ) -> SideChannelDossier:
        if not analysis_id.strip():
            raise ValueError("analysis_id cannot be empty")
        if flush_rate_per_sec < 0 or not math.isfinite(flush_rate_per_sec):
            raise ValueError("flush_rate_per_sec must be finite and non-negative")
        if not isinstance(attack_type, AttackType):
            attack_type = AttackType(attack_type)

        data_source = "provided"
        if timings is None:
            raw_bits = secret_bitstring or "10110011"
            if not raw_bits or any(bit not in "01" for bit in raw_bits):
                raise ValueError("secret_bitstring must contain only 0 and 1")
            timings = FlushReloadEngine.synthesize_traces([int(bit) for bit in raw_bits])
            data_source = "synthetic"

        timing_result = FlushReloadEngine.analyze_timings(timings)

        if coherence_engine is None:
            coherence_engine = MesiCoherenceEngine(num_cores=4)
            coherence_engine.processor_read(core_id=0, address=0x1000)
            coherence_engine.processor_write(core_id=1, address=0x1000)
            coherence_engine.flush_line(core_id=2, address=0x1000)

        ttable_result = None
        if ttable_counts is not None:
            ttable_result = TTableLeakageScanner.evaluate_access_distribution(ttable_counts)

        hpc_score = min(
            100.0,
            (flush_rate_per_sec / 2000.0)
            + (timing_result.snr_db * 2.0 if timing_result.channel_confident else 0.0),
        )

        mitigations: List[str] = []
        if timing_result.channel_confident and ttable_result and ttable_result.leakage_detected:
            severity = ThreatSeverity.CRITICAL
            mitigations.append(
                "Strong timing separation and a skewed table-access distribution were observed."
            )
            mitigations.append(
                "Prefer AES-NI/ARM cryptographic instructions or constant-time implementations."
            )
            mitigations.append(
                "Reduce cross-domain cache sharing where the threat model requires isolation."
            )
        elif timing_result.channel_confident:
            severity = ThreatSeverity.HIGH
            mitigations.append("Strong separation between timing clusters was observed.")
            mitigations.append(
                "Review shared-memory exposure, cache isolation, and timing-sensitive code paths."
            )
        elif hpc_score > 50.0:
            severity = ThreatSeverity.MEDIUM
            mitigations.append("The heuristic activity score is elevated.")
            mitigations.append("Correlate with independent performance-counter and workload telemetry.")
        else:
            severity = ThreatSeverity.LOW
            mitigations.append("No strong timing-separation signal was observed in this analysis.")

        return SideChannelDossier(
            analysis_id=analysis_id,
            attack_type=attack_type,
            threat_severity=severity,
            data_source=data_source,
            timing_analysis=timing_result,
            coherence_events_count=len(coherence_engine.event_log),
            stale_access_count=coherence_engine.stale_reads_count,
            ttable_leakage=ttable_result,
            hpc_anomaly_score=round(hpc_score, 2),
            mitigation_recommendations=mitigations,
        )


def format_security_dossier(dossier: SideChannelDossier) -> str:
    """Render a compact text report."""
    lines = [
        "=" * 78,
        f" CACHE TIMING & COHERENCE ANALYSIS : {dossier.analysis_id}",
        "=" * 78,
        (
            f"Model: {dossier.attack_type.value} | Risk level: {dossier.threat_severity.value} "
            f"| Data: {dossier.data_source}"
        ),
        (
            f"Heuristic activity score: {dossier.hpc_anomaly_score:.1f}/100.0 "
            f"| Coherence events: {dossier.coherence_events_count}"
        ),
        "-" * 78,
    ]

    if dossier.timing_analysis:
        timing = dossier.timing_analysis
        lines.extend(
            [
                "TIMING SUMMARY:",
                (
                    f"  * Samples: {timing.total_samples} | Threshold: "
                    f"{timing.optimal_threshold_cycles:.1f} cycles"
                ),
                (
                    f"  * Lower-latency cluster: {timing.hit_count} "
                    f"(mean {timing.hit_mean_cycles:.1f}c, SD {timing.hit_std_cycles:.1f}c)"
                ),
                (
                    f"  * Higher-latency cluster: {timing.miss_count} "
                    f"(mean {timing.miss_mean_cycles:.1f}c, SD {timing.miss_std_cycles:.1f}c)"
                ),
                (
                    f"  * Standardized separation: {timing.cohens_d_prime:.2f} "
                    f"| SNR heuristic: {timing.snr_db:.2f} dB"
                ),
                f"  * Strong two-cluster separation: {'yes' if timing.channel_confident else 'no'}",
                f"  * Grouped binary pattern: {timing.extracted_bitstring}",
                "-" * 78,
            ]
        )

    if dossier.ttable_leakage:
        table = dossier.ttable_leakage
        lines.extend(
            [
                "TABLE ACCESS DISTRIBUTION:",
                (
                    f"  * Table T{table.table_index} | Lines monitored: "
                    f"{table.total_lines_monitored}"
                ),
                f"  * Shannon entropy: {table.entropy_score:.3f} / 4.000 bits",
                f"  * Distribution skew flag: {'yes' if table.leakage_detected else 'no'}",
                f"  * Most-accessed line: {table.hottest_cache_line}",
                "-" * 78,
            ]
        )

    lines.append("DEFENSIVE FOLLOW-UP:")
    lines.extend(f"  * {recommendation}" for recommendation in dossier.mitigation_recommendations)
    lines.append("=" * 78)
    return "\n".join(lines)
