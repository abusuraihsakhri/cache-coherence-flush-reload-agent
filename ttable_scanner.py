#!/usr/bin/env python3
"""
AES T-table vulnerability scanner and first-round key-recovery simulator.

Classic cache-timing attack structure (Bernstein; Osvik-Shamir-Tromer):
software AES using 4 x 256-entry T-tables leaks the first-round key byte
through which cache line of a table is touched:

    y = plaintext_byte XOR key_byte          (first round)
    T[y] -> cache line = (table_base + 4*y) >> 6, i.e. y >> 4

Each T-table is 256 entries * 4 bytes = 1024 bytes = exactly 16 cache lines,
so one observed line narrows a key byte to 16 candidates. Intersecting
candidate sets across known-plaintext observations recovers the byte.

This module scans lookup traces for secret-dependent table indexing, scores
the leak with entropy analysis, and runs a full candidate-intersection attack.
"""

import math
from collections import Counter
from typing import Dict, List, Sequence


ENTRIES_PER_TABLE = 256
ENTRY_SIZE_BYTES = 4
LINE_SIZE_BYTES = 64
LINES_PER_TABLE = ENTRIES_PER_TABLE * ENTRY_SIZE_BYTES // LINE_SIZE_BYTES   # 16


def entry_to_line(entry_index: int) -> int:
    """Cache line of T-table entry i within a single aligned table."""
    return (entry_index * ENTRY_SIZE_BYTES) // LINE_SIZE_BYTES


def scan_lookup_trace(trace: Sequence[int], table_base: int = 0) -> dict:
    """Scan a sequence of table indices accessed during encryption rounds.

    Leak metrics:
      - distinct lines touched per index position
      - entropy of the observed line distribution (max log2(16) = 4 bits)
      - leak score: fraction of the theoretical maximum information leaked
    """
    if not trace:
        raise ValueError("empty trace")
    lines = [entry_to_line(i) for i in trace]
    dist = Counter(lines)
    total = len(lines)
    entropy = -sum((c / total) * math.log2(c / total) for c in dist.values())
    max_entropy = math.log2(LINES_PER_TABLE)
    return {
        "lookups": total,
        "distinct_lines_touched": len(dist),
        "lines_available": LINES_PER_TABLE,
        "line_distribution": {str(k): v for k, v in sorted(dist.items())},
        "observed_line_entropy_bits": round(entropy, 3),
        "leak_score_pct": round(100.0 * entropy / max_entropy, 1),
        "secret_dependent_indexing": len(dist) > 1 or trace[0] != trace[-1],
    }


def first_round_key_candidates(observed_line: int, plaintext_byte: int) -> set:
    """Key-byte candidates consistent with one observed cache-line access.

    y in [16*line, 16*line+15]; k = y XOR x.
    """
    base = observed_line << 4
    return {y ^ plaintext_byte for y in range(base, base + ENTRIES_PER_TABLE // LINES_PER_TABLE)}


def recover_key_byte(observations: List[tuple]) -> dict:
    """Intersect candidate sets across (plaintext_byte, observed_line) pairs.

    Observations that would empty the intersection are discarded as
    measurement noise, mirroring real attacker-side filtering.
    """
    candidates: set = None
    discarded = 0
    for pt, line in observations:
        c = first_round_key_candidates(line, pt)
        merged = c if candidates is None else (candidates & c)
        if not merged:
            discarded += 1
            continue
        candidates = merged
    if not candidates:
        return {"recovered": False, "candidates_remaining": [],
                "note": "no consistent key hypothesis", "discarded": discarded}
    unique = len(candidates) == 1
    # First-round observations cannot separate keys differing only in the
    # low nibble (identical cache-line behavior); 16 survivors = high
    # nibble fully recovered, which is the classic first-round result.
    note = ("unique key byte" if unique else
            f"high nibble recovered; {len(candidates)} candidates share "
            "cache-line behavior - resolve via second-round or multi-table analysis")
    return {
        "recovered": unique,
        "high_nibble": next(iter(candidates)) >> 4,
        "key_byte": next(iter(candidates)) if unique else None,
        "candidates_remaining": sorted(candidates),
        "note": note,
        "observations_used": len(observations),
    }


def simulate_first_round_attack(key_byte: int, plaintexts: List[int],
                                noise_lines: int = 0, seed: int = 99) -> dict:
    """Simulate attacker observations then run recovery against them."""
    import random
    rng = random.Random(seed)
    obs = []
    for pt in plaintexts:
        y = pt ^ key_byte
        obs.append((pt, entry_to_line(y)))
    for _ in range(noise_lines):  # false positives from other traffic
        pt = rng.randrange(256)
        obs.append((pt, rng.randrange(LINES_PER_TABLE)))
    result = recover_key_byte(obs)
    result["true_key_byte"] = key_byte
    result["high_nibble_correct"] = bool(
        result["candidates_remaining"]
        and all(c >> 4 == key_byte >> 4 for c in result["candidates_remaining"]))
    return result


def hardening_recommendations(scan: dict) -> List[str]:
    recs: List[str] = ["Replace T-table AES with bitsliced/AES-NI implementation"]
    if scan.get("secret_dependent_indexing"):
        recs += [
            "Enable constant-time S-box via bit-sliced boolean expressions",
            "Add cache-line padding to spread each table over >=32 lines",
            "Prefer hardware AES-NI/ARMv8 crypto extensions where available",
            "Disable clflush from untrusted code paths / enable CAT partitioning",
        ]
    else:
        recs.append("No secret-dependent table access pattern detected in this trace")
    return recs


if __name__ == "__main__":
    demo_trace: List[int] = []
    for k in range(4):
        demo_trace.extend([(i * 17 + k * 41) % ENTRIES_PER_TABLE for i in range(64)])
    scan = scan_lookup_trace(demo_trace)
    print("T-table lookup scan")
    print("-" * 56)
    print(f"distinct lines : {scan['distinct_lines_touched']}/{scan['lines_available']}")
    print(f"entropy        : {scan['observed_line_entropy_bits']} bits "
          f"(leak score {scan['leak_score_pct']}%)")

    true_key = 0xA7
    plaintexts = list(range(0, 240, 5))
    attack = simulate_first_round_attack(true_key, plaintexts, noise_lines=6)
    print(f"\nfirst-round attack on key byte {hex(true_key)}:")
    print(f"  high nibble recovered : {hex(attack['high_nibble'])} "
          f"(correct={attack['high_nibble_correct']})")
    print(f"  candidates remaining  : {len(attack['candidates_remaining'])} "
          f"-> {attack['note']}")
    print("\nhardening plan:")
    for r in hardening_recommendations(scan):
        print(f"  - {r}")
