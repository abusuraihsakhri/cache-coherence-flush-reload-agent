#!/usr/bin/env python3
"""Command-line interface for cache timing and coherence analysis."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from typing import List, Optional

from cache_coherence_flush_reload import (
    AttackType,
    CacheCoherenceFlushReloadAgent,
    FlushReloadEngine,
    MesiCoherenceEngine,
    format_security_dossier,
)


def _parse_float_list(raw: str, label: str) -> List[float]:
    try:
        values = [float(value.strip()) for value in raw.split(",") if value.strip()]
    except ValueError as exc:
        raise ValueError(f"{label} must be a comma-separated list of numbers") from exc
    if not values or any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError(f"{label} must contain finite, non-negative numbers")
    return values


def _parse_int_list(raw: str, label: str) -> List[int]:
    try:
        values = [int(value.strip()) for value in raw.split(",") if value.strip()]
    except ValueError as exc:
        raise ValueError(f"{label} must be a comma-separated list of integers") from exc
    if not values or any(value < 0 for value in values):
        raise ValueError(f"{label} must contain non-negative integers")
    return values


def _validate_bitstring(raw: str) -> str:
    if not raw or any(bit not in "01" for bit in raw):
        raise ValueError("bitstring must contain only 0 and 1")
    return raw


def run_demo(scenario: str = "all") -> int:
    """Run deterministic demonstration scenarios."""
    scenarios = ["flush_reload", "prime_probe", "ttable_leak", "coherence_race"]
    selected = scenarios if scenario == "all" else [scenario] if scenario in scenarios else []
    if not selected:
        print(f"Unknown scenario: {scenario}. Choose from: {scenarios} or 'all'", file=sys.stderr)
        return 2

    for selected_scenario in selected:
        if selected_scenario == "flush_reload":
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-FLUSH-RELOAD",
                secret_bitstring="1101001011",
                flush_rate_per_sec=125000.0,
                attack_type=AttackType.FLUSH_RELOAD,
            )
        elif selected_scenario == "ttable_leak":
            skewed_counts = [5, 3, 2, 4, 185, 6, 2, 1, 3, 4, 2, 1, 5, 2, 3, 2]
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-TTABLE-LEAK",
                secret_bitstring="101010",
                ttable_counts=skewed_counts,
                flush_rate_per_sec=80000.0,
                attack_type=AttackType.FLUSH_RELOAD,
            )
        elif selected_scenario == "coherence_race":
            engine = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
            engine.processor_read(0, 0x2000)
            engine.processor_read(1, 0x2000)
            engine.processor_write(2, 0x2000, data=0xABCD)
            engine.processor_read(3, 0x2000)
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-COHERENCE",
                coherence_engine=engine,
                flush_rate_per_sec=15000.0,
                attack_type=AttackType.INVALIDATION_RACE,
            )
        else:
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-PRIME-PROBE",
                secret_bitstring="11100011",
                flush_rate_per_sec=45000.0,
                attack_type=AttackType.PRIME_PROBE,
            )

        print(format_security_dossier(dossier))
        print()
    return 0


def interactive_mode() -> int:
    """Guide a user through a local, synthetic timing analysis."""
    print("=" * 60)
    print(" Cache Timing Analysis - Interactive Entry")
    print("=" * 60)
    try:
        analysis_id = input("Analysis ID [AUDIT-001]: ").strip() or "AUDIT-001"
        secret_bits = _validate_bitstring(
            input("Synthetic bit pattern [101101]: ").strip() or "101101"
        )
        rounds = int(input("Measurements per group [10]: ").strip() or "10")
        if rounds <= 0:
            raise ValueError("measurements per group must be greater than zero")

        flush_rate = float(input("Optional flush-rate heuristic [0]: ").strip() or "0")
        if not math.isfinite(flush_rate) or flush_rate < 0:
            raise ValueError("flush rate must be finite and non-negative")

        table_input = input("16 table access counts (comma-separated, optional): ").strip()
        table_counts = _parse_int_list(table_input, "table counts") if table_input else None

        timings = FlushReloadEngine.synthesize_traces(
            [int(bit) for bit in secret_bits],
            rounds_per_bit=rounds,
        )
        dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
            analysis_id=analysis_id,
            timings=timings,
            ttable_counts=table_counts,
            flush_rate_per_sec=flush_rate,
        )
        print("\n" + format_security_dossier(dossier))
        return 0
    except (OSError, ValueError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2


def process_batch_csv(
    input_path: str,
    output_path: Optional[str] = None,
    threshold: Optional[float] = None,
) -> int:
    """Classify timing rows in a CSV without treating every cache hit as an anomaly."""
    if threshold is not None and (not math.isfinite(threshold) or threshold < 0):
        raise ValueError("threshold must be finite and non-negative")

    rows = []
    with open(input_path, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        rows.extend(reader)

    if not rows:
        print(f"No records found in {input_path}")
        return 0

    reload_key = next(
        (
            key
            for key in [
                "reload_access_cycles",
                "reload_time",
                "reload_cycles",
                "latency",
                "primary_metric",
            ]
            if key in fieldnames
        ),
        None,
    )

    timings = []
    if reload_key:
        for row in rows:
            try:
                value = float(row[reload_key])
                if math.isfinite(value) and value >= 0:
                    timings.append(value)
            except (ValueError, TypeError):
                continue

    calibrated_threshold = threshold
    if calibrated_threshold is None:
        calibrated_threshold = (
            FlushReloadEngine.compute_otsu_threshold(timings) if timings else 120.0
        )

    out_fieldnames = list(fieldnames)
    for extra_column in [
        "calibrated_threshold",
        "evaluated_classification",
        "inferred_binary_state",
        "side_channel_anomaly",
    ]:
        if extra_column not in out_fieldnames:
            out_fieldnames.append(extra_column)

    processed_rows = []
    for row in rows:
        output_row = dict(row)
        reload_value = None
        if reload_key and row.get(reload_key) not in (None, ""):
            try:
                candidate = float(row[reload_key])
                if math.isfinite(candidate) and candidate >= 0:
                    reload_value = candidate
            except (ValueError, TypeError):
                pass

        if reload_value is not None:
            is_hit = reload_value < calibrated_threshold
            binary_state = 1 if is_hit else 0
            classification = "HIT" if is_hit else "MISS"
        else:
            binary_state = 0
            classification = (row.get("classification") or "UNKNOWN").upper()

        declared = (row.get("classification") or "").upper()
        explicit_anomaly = (row.get("anomaly_detected") or "").lower() in {
            "true",
            "1",
            "yes",
        }
        classification_mismatch = (
            declared in {"HIT", "MISS"}
            and classification in {"HIT", "MISS"}
            and declared != classification
        )

        output_row["calibrated_threshold"] = f"{calibrated_threshold:.1f}"
        output_row["evaluated_classification"] = classification
        output_row["inferred_binary_state"] = str(binary_state)
        output_row["side_channel_anomaly"] = str(explicit_anomaly or classification_mismatch)
        processed_rows.append(output_row)

    if output_path:
        with open(output_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=out_fieldnames)
            writer.writeheader()
            writer.writerows(processed_rows)
        print(f"Batch processing complete. Wrote {len(processed_rows)} rows to {output_path}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=out_fieldnames)
        writer.writeheader()
        writer.writerows(processed_rows)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze cache timing traces and model MESI/MOESI coherence behavior"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command mode")

    batch_parser = subparsers.add_parser("batch", help="Process a CSV batch file")
    batch_parser.add_argument("--input", "-i", required=True, help="Input CSV file path")
    batch_parser.add_argument("--output", "-o", help="Output CSV file path")
    batch_parser.add_argument("--threshold", "-t", type=float, help="Manual timing threshold")

    parser.add_argument("--batch", "-b", help="Process a CSV batch file (flag mode)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive mode")
    parser.add_argument(
        "--demo",
        choices=["flush_reload", "prime_probe", "ttable_leak", "coherence_race", "all"],
        help="Run a deterministic demonstration",
    )
    parser.add_argument("--analysis-id", default="AUDIT-001", help="Analysis identifier")
    parser.add_argument(
        "--synthesize-bits",
        default="10110011",
        help="Binary pattern used when synthetic timings are requested",
    )
    parser.add_argument("--timings", help="Comma-separated cycle timings")
    parser.add_argument("--threshold", type=float, help="Manual timing threshold")
    parser.add_argument(
        "--rounds-per-bit",
        type=int,
        default=10,
        help="Measurements per grouped binary state",
    )
    parser.add_argument("--cores", type=int, default=4, help="Number of modeled CPU cores")
    parser.add_argument(
        "--protocol",
        choices=["MESI", "MOESI"],
        default="MOESI",
        help="Cache coherence protocol",
    )
    parser.add_argument("--ttable-counts", help="16 comma-separated table access counts")
    parser.add_argument(
        "--flush-rate",
        type=float,
        default=0.0,
        help="Optional flush-rate heuristic value",
    )
    parser.add_argument("--file", "-f", help="Load analysis configuration from JSON")
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON")
    parser.add_argument("--output", "-o", help="Write the report to a file")

    args = parser.parse_args(argv)

    try:
        if args.command == "batch":
            return process_batch_csv(args.input, args.output, args.threshold)

        if getattr(args, "batch", None):
            return process_batch_csv(args.batch, args.output, args.threshold)

        if args.interactive:
            return interactive_mode()

        if args.demo:
            return run_demo(args.demo)

        if args.rounds_per_bit <= 0:
            raise ValueError("rounds-per-bit must be greater than zero")
        if args.flush_rate < 0 or not math.isfinite(args.flush_rate):
            raise ValueError("flush-rate must be finite and non-negative")

        if args.file:
            with open(args.file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            timings = data.get("timings")
            secret_bitstring = _validate_bitstring(data.get("secret_bitstring", "10110011"))
            ttable_counts = data.get("ttable_counts")
            flush_rate = float(data.get("flush_rate", 0.0))
            analysis_id = str(data.get("analysis_id", "FILE-AUDIT"))
        else:
            analysis_id = args.analysis_id
            secret_bitstring = _validate_bitstring(args.synthesize_bits)
            timings = _parse_float_list(args.timings, "timings") if args.timings else None
            ttable_counts = (
                _parse_int_list(args.ttable_counts, "table counts")
                if args.ttable_counts
                else None
            )
            flush_rate = args.flush_rate

        engine = MesiCoherenceEngine(num_cores=args.cores, protocol=args.protocol)
        engine.processor_read(0, 0x1000)
        engine.processor_write(1, 0x1000)
        engine.flush_line(2, 0x1000)

        dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
            analysis_id=analysis_id,
            timings=timings,
            secret_bitstring=secret_bitstring,
            coherence_engine=engine,
            ttable_counts=ttable_counts,
            flush_rate_per_sec=flush_rate,
        )
        output_text = dossier.to_json() if args.json else format_security_dossier(dossier)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output_text)
        else:
            print(output_text)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
