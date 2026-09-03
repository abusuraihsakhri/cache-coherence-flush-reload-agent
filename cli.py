#!/usr/bin/env python3
"""
Command-Line Interface for Cache Coherence & Flush+Reload Security Agent
========================================================================
Supports interactive trace entry, automated threshold calibration,
cryptographic T-table side-channel detection, and multi-core MESI/MOESI simulation.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

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


def run_demo(scenario: str = "all") -> int:
    """Runs validated benchmark side-channel security scenarios."""
    scenarios = ["flush_reload", "prime_probe", "ttable_leak", "coherence_race"]
    selected = scenarios if scenario == "all" else [scenario] if scenario in scenarios else []
    if not selected:
        print(f"Unknown scenario: {scenario}. Choose from: {scenarios} or 'all'")
        return 1

    for s in selected:
        if s == "flush_reload":
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-FLUSH-RELOAD",
                secret_bitstring="1101001011",
                flush_rate_per_sec=125000.0
            )
        elif s == "ttable_leak":
            # Highly skewed T-table access pattern (leaking AES key round)
            skewed_counts = [5, 3, 2, 4, 185, 6, 2, 1, 3, 4, 2, 1, 5, 2, 3, 2]
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-TTABLE-LEAK",
                secret_bitstring="101010",
                ttable_counts=skewed_counts,
                flush_rate_per_sec=80000.0
            )
        elif s == "coherence_race":
            engine = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
            engine.processor_read(0, 0x2000)
            engine.processor_read(1, 0x2000)
            engine.processor_write(2, 0x2000, data=0xABCD)
            engine.processor_read(3, 0x2000)
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-COHERENCE-RACE",
                coherence_engine=engine,
                flush_rate_per_sec=15000.0
            )
        elif s == "prime_probe":
            dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
                analysis_id="DEMO-PRIME-PROBE",
                secret_bitstring="11100011",
                flush_rate_per_sec=45000.0
            )
        print(format_security_dossier(dossier))
        print("\n")
    return 0


def interactive_mode() -> int:
    """Guides user through interactive microarchitectural security analysis."""
    print("=" * 60)
    print(" Microarchitectural Timing Side-Channel - Interactive Entry")
    print("=" * 60)
    try:
        analysis_id = input("Enter Analysis ID [AUDIT-2026-001]: ").strip() or "AUDIT-2026-001"
        secret_bits = input("Enter Secret Bitstring to simulate [101101]: ").strip() or "101101"
        rounds_str = input("Probe rounds per bit [10]: ").strip() or "10"
        rounds = int(rounds_str)

        flush_rate_str = input("Estimated clflush rate (invocations/sec) [50000]: ").strip() or "50000"
        flush_rate = float(flush_rate_str)

        ttable_in = input("Enter 16 T-table access counts (comma-separated, or enter for none): ").strip()
        ttable_counts = None
        if ttable_in:
            ttable_counts = [int(x.strip()) for x in ttable_in.split(",") if x.strip()]

        bits = [int(b) for b in secret_bits if b in "01"]
        timings = FlushReloadEngine.synthesize_traces(bits, rounds_per_bit=rounds)

        dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
            analysis_id=analysis_id,
            timings=timings,
            ttable_counts=ttable_counts,
            flush_rate_per_sec=flush_rate
        )

        print("\n" + format_security_dossier(dossier))
        return 0
    except Exception as e:
        print(f"Error during interactive analysis: {e}", file=sys.stderr)
        return 1


import csv


def process_batch_csv(input_path: str, output_path: Optional[str] = None, threshold: Optional[float] = None) -> int:
    """
    Processes a CSV of cache line access events and telemetry data,
    evaluating hit/miss status, secret bit, and side-channel anomaly detection.
    """
    rows = []
    with open(input_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for r in reader:
            rows.append(r)

    if not rows:
        print(f"No records found in {input_path}")
        return 0

    # Auto-calibrate threshold if reload_access_cycles is present
    reload_key = None
    for k in ["reload_access_cycles", "reload_time", "reload_cycles", "latency", "primary_metric"]:
        if k in fieldnames:
            reload_key = k
            break

    timings = []
    if reload_key:
        for r in rows:
            try:
                timings.append(float(r[reload_key]))
            except (ValueError, TypeError):
                pass

    calibrated_threshold = threshold
    if calibrated_threshold is None:
        if timings:
            calibrated_threshold = FlushReloadEngine.compute_otsu_threshold(timings)
        else:
            calibrated_threshold = 120.0

    out_fieldnames = list(fieldnames)
    for extra_col in ["calibrated_threshold", "evaluated_classification", "inferred_secret_bit", "side_channel_anomaly"]:
        if extra_col not in out_fieldnames:
            out_fieldnames.append(extra_col)

    processed_rows = []
    for r in rows:
        row_out = dict(r)
        reload_val = None
        if reload_key and r.get(reload_key) is not None:
            try:
                reload_val = float(r[reload_key])
            except (ValueError, TypeError):
                pass

        if reload_val is not None:
            is_hit = reload_val < calibrated_threshold
            inferred_bit = 1 if is_hit else 0
            classification = "HIT" if is_hit else "MISS"
            anomaly = is_hit or (r.get("anomaly_detected", "").lower() in ("true", "1", "yes"))
        else:
            is_hit = False
            inferred_bit = 0
            classification = r.get("classification", "MISS")
            anomaly = False

        row_out["calibrated_threshold"] = f"{calibrated_threshold:.1f}"
        row_out["evaluated_classification"] = classification
        row_out["inferred_secret_bit"] = str(inferred_bit)
        row_out["side_channel_anomaly"] = str(anomaly)
        processed_rows.append(row_out)

    if output_path:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=out_fieldnames)
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
        description="Cache Coherence & Flush+Reload Side-Channel Security Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command mode")

    # Batch subparser
    batch_parser = subparsers.add_parser("batch", help="Process a CSV batch file of cache access events")
    batch_parser.add_argument("--input", "-i", required=True, help="Input CSV file path")
    batch_parser.add_argument("--output", "-o", help="Output CSV file path")
    batch_parser.add_argument("--threshold", "-t", type=float, help="Manual hit/miss cycle threshold")

    # Audit / standalone arguments
    parser.add_argument("--batch", "-b", help="Process a CSV batch file (flag mode)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive audit mode")
    parser.add_argument("--demo", choices=["flush_reload", "prime_probe", "ttable_leak", "coherence_race", "all"], help="Run benchmark demo scenario")
    parser.add_argument("--analysis-id", default="AUDIT-001", help="Audit run identifier")
    parser.add_argument("--synthesize-bits", default="10110011", help="Secret bitstring to synthesize and audit")
    parser.add_argument("--timings", help="Comma-separated cycle timings (e.g. 70,75,280,290)")
    parser.add_argument("--threshold", type=float, help="Manual hit/miss cycle threshold")
    parser.add_argument("--rounds-per-bit", type=int, default=10, help="Number of measurements per bit")
    parser.add_argument("--cores", type=int, default=4, help="Number of CPU cores for coherence model")
    parser.add_argument("--protocol", choices=["MESI", "MOESI"], default="MOESI", help="Cache coherence protocol")
    parser.add_argument("--ttable-counts", help="16 comma-separated integer counts for AES T-table lines")
    parser.add_argument("--flush-rate", type=float, default=0.0, help="Measured clflush invocations per second")
    parser.add_argument("--file", "-f", help="Load analysis configuration from JSON file")
    parser.add_argument("--json", "-j", action="store_true", help="Output audit dossier in JSON format")
    parser.add_argument("--output", "-o", help="Write report to output file")

    args = parser.parse_args(argv)

    if args.command == "batch":
        return process_batch_csv(args.input, args.output, args.threshold)

    if getattr(args, "batch", None):
        return process_batch_csv(args.batch, args.output, args.threshold)

    if args.interactive:
        return interactive_mode()

    if args.demo:
        return run_demo(args.demo)

    if args.file:
        with open(args.file, "r") as fp:
            data = json.load(fp)
        timings = data.get("timings")
        secret_bitstring = data.get("secret_bitstring", "10110011")
        ttable_counts = data.get("ttable_counts")
        flush_rate = float(data.get("flush_rate", 0.0))
        analysis_id = data.get("analysis_id", "FILE-AUDIT")
    else:
        analysis_id = args.analysis_id
        secret_bitstring = args.synthesize_bits
        timings = [float(x.strip()) for x in args.timings.split(",") if x.strip()] if args.timings else None
        ttable_counts = [int(x.strip()) for x in args.ttable_counts.split(",") if x.strip()] if args.ttable_counts else None
        flush_rate = args.flush_rate

    engine = MesiCoherenceEngine(num_cores=args.cores, protocol=args.protocol)
    # Simulate multi-core memory accesses
    engine.processor_read(0, 0x1000)
    engine.processor_write(1, 0x1000)
    engine.flush_line(2, 0x1000)

    dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
        analysis_id=analysis_id,
        timings=timings,
        secret_bitstring=secret_bitstring,
        coherence_engine=engine,
        ttable_counts=ttable_counts,
        flush_rate_per_sec=flush_rate
    )

    if args.json:
        out_str = dossier.to_json()
    else:
        out_str = format_security_dossier(dossier)

    if args.output:
        with open(args.output, "w") as fp:
            fp.write(out_str)
    else:
        print(out_str)

    return 0


if __name__ == "__main__":
    sys.exit(main())

