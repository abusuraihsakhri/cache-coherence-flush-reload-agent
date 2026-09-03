# Cache Coherence & Flush+Reload Side-Channel Security Engine

> **Domain:** Hardware Security, Microarchitectural Side-Channels, & Cache Coherence Verification  
> **Reference Standards & Literature:** Yarom & Falkner (*USENIX Security 2014*), Gruss et al. (*DIMVA 2016*), IEEE 1596 / AMD64 MESI/MOESI Protocol Specifications

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Microarchitectural_Audit-crimson.svg)
![Tests](https://img.shields.io/badge/Tests-Pytest%20Passing-brightgreen.svg)

</div>

---

## 📖 Overview

The **Cache Coherence & Flush+Reload Side-Channel Security Engine** is an architectural and software security analysis suite designed to model, simulate, detect, and mitigate microarchitectural timing attacks. It evaluates:

* **Flush+Reload (Yarom & Falkner 2014):** Exploits page deduplication and shared read-only memory mappings via `clflush` and cycle timing measurement (`rdtsc`/`rdtscp`).
* **Prime+Probe & Flush+Flush:** Cache set contention profiling without shared memory or cache-hit timing signatures.
* **Multi-Core MESI / MOESI Protocol State Machines:** Cross-core cache coherence tracking, invalidation races, snooping bus transitions, and stale data reads.
* **Cryptographic T-Table Leakage Analysis:** Shannon entropy and access frequency profiling targeting table-based implementations of cryptographic primitives (such as AES S-boxes).
* **Hardware Performance Counter (HPC) Telemetry:** Real-time monitoring of high-frequency flush instruction rates and LLC miss spikes.

---

## 📐 Mathematical Formulation & Microarchitectural Foundations

### 1. Flush+Reload Attack Cycle Discrimination

In an inclusive Last-Level Cache (LLC) architecture, the attacker executes three distinct phases:

1. **FLUSH:** Evicts target cache line $L$ across all cache levels using `clflush $L`.
2. **WAIT:** Allows victim thread execution (e.g., cryptographic exponentiation or AES round substitution). If the victim accesses $L$, the processor loads it into L1/L2 and LLC.
3. **RELOAD:** Measures the access latency $t$ using serialized time-stamp counters (`rdtscp` / `lfence; rdtsc`).

$$\text{Reload State} = \begin{cases} \text{Cache Hit } (L1/L2/LLC), & t < \tau \\ \text{Cache Miss } (\text{DRAM Fetch}), & t \ge \tau \end{cases}$$

### 2. Discrimination Threshold Calibration ($\tau$)

The decision threshold $\tau$ separates the bimodal distribution of cache hits from cache misses:

$$\tau \approx \frac{\mu_{\text{hit}} + \mu_{\text{miss}}}{2}$$

For non-symmetric or noisy distributions, the engine calibrates $\tau$ via **Otsu's Variance Minimization Method**, maximizing inter-class variance $\sigma_B^2(T)$:

$$\sigma_B^2(T) = \omega_0(T) \omega_1(T) \left(\mu_0(T) - \mu_1(T)\right)^2$$

where $\omega_0, \omega_1$ are cumulative probabilities of the hit and miss partitions separated by candidate threshold $T$.

### 3. Signal Quality & Channel Capacity

To quantify side-channel exfiltration reliability and bit error rates, the engine computes **Cohen's $d'$** effect size and Signal-to-Noise Ratio ($\text{SNR}_{\text{dB}}$):

$$d' = \frac{|\mu_{\text{miss}} - \mu_{\text{hit}}|}{\sqrt{\frac{\sigma_{\text{hit}}^2 + \sigma_{\text{miss}}^2}{2}}}$$

$$\text{SNR}_{\text{dB}} = 20 \log_{10}\left(\frac{|\mu_{\text{miss}} - \mu_{\text{hit}}|}{\sigma_{\text{pooled}}}\right)$$

A channel with $d' \ge 3.5$ and $\text{SNR} > 15 \text{ dB}$ provides high-confidence secret bit exfiltration ($>99.9\%$ accuracy with minimal majority-voting rounds).

### 4. MESI / MOESI Coherence Protocol Transitions

Multi-core cache coherence coordinates cache line ownership across private L1/L2 and shared LLC caches:

* **M (Modified):** Line is dirty and held exclusively by the local core; must be written back on eviction.
* **O (Owner - MOESI):** Line is dirty, shared with other cores; the owner core services peer reads without DRAM write-back.
* **E (Exclusive):** Line is clean and held exclusively by one core.
* **S (Shared):** Line is clean and replicated in multiple private caches.
* **I (Invalid):** Line is not present or has been invalidated by a peer core's `PrWr` (`BusRdX` / `BusUpgr`) or `clflush`.

Cross-core invalidations trigger bus snooping transactions:
$$\text{Core}_i \xrightarrow{\text{PrWr}(A)} \text{BusRdX}(A) \implies \forall j \neq i: \text{State}_j(A) \leftarrow \text{INVALID}$$

### 5. Cryptographic T-Table Entropy & Key Leakage

For table-based implementations where AES round keys are indexed as $T[p \oplus k]$:
$$\text{Line Index} = \left\lfloor \frac{\text{Byte Offset}}{64} \right\rfloor$$

Under a non-leaking, constant-time execution profile, the distribution across the 16 cache lines of a 1024-byte table is uniform ($H_{\max} = \log_2(16) = 4.0\text{ bits}$). Secret key byte recovery is detected when the Shannon entropy drops:

$$H(X) = -\sum_{i=0}^{15} p_i \log_2(p_i) < 3.20\text{ bits}$$

### 6. Constant-Time Software Mitigations

* **Hardware Crypto Instructions:** Replace software lookup tables with constant-time AES-NI (`vaesenc`, `vaesenclast`) or bit-sliced vector implementations (`vpaes`).
* **Cache Partitioning & CAT:** Utilize Intel Cache Allocation Technology (CAT) to partition ways between victim and attacker domains.
* **Memory Isolation & Serialization:** Restrict unprivileged `clflush` instructions or use memory serialization fences (`lfence`, `mfence`).

---

## 💻 CLI Quickstart & Usage

### 1. Batch Processing Mode (`sample.csv`)

Process an input batch CSV of cache line access events and telemetry data:

```bash
python cli.py batch -i sample.csv -o results.csv
```

With manual threshold override:

```bash
python cli.py batch -i sample.csv -o results.csv --threshold 100.0
```

### 2. Standalone & Synthetic Audit

Run an audit with synthetic bitstreams or custom cycle timings:

```bash
# Synthetic bitstring analysis
python cli.py --analysis-id AUDIT-001 --synthesize-bits 10110011 --rounds-per-bit 10 --json

# Direct timing sequence evaluation
python cli.py --analysis-id TIMING-TEST --timings 45.2,52.1,48.0,270.5,285.0,290.1 --threshold 120.0

# AES T-table leakage assessment
python cli.py --analysis-id AES-EVAL --ttable-counts 2,4,1,3,380,2,1,4,2,3,1,2,5,1,2,3
```

### 3. Built-in Benchmark Demos

```bash
python cli.py --demo flush_reload
python cli.py --demo prime_probe
python cli.py --demo ttable_leak
python cli.py --demo coherence_race
python cli.py --demo all
```

### 4. Interactive Guided Audit

```bash
python cli.py --interactive
```

---

## 📊 CSV Input/Output Schema

### Input Schema (`sample.csv`)

| Column Name | Type | Description | Example |
|:---|:---|:---|:---|
| `address` | String (Hex) | Monitored cache line address | `0x7fff5bc0` |
| `mesi_state` | String | Coherence state (`Modified`, `Exclusive`, `Shared`, `Invalid`) | `Shared` |
| `flush_latency_cycles` | Float / Int | Duration of `clflush` operation in CPU cycles | `185` |
| `reload_access_cycles` | Float / Int | Measured reload latency (L1 hit vs. DRAM miss) | `42` |
| `classification` | String | Observed state classification (`HIT` / `MISS`) | `HIT` |
| `secret_bit` | Integer | Inferred secret bit (`1` for reload hit, `0` for miss) | `1` |
| `anomaly_detected` | Boolean | Microarchitectural anomaly indicator | `True` |

### Batch Output Additions

The `batch` command appends the following calibrated fields:
* `calibrated_threshold`: Calculated Otsu or user-specified cycle discrimination threshold.
* `evaluated_classification`: Evaluated `HIT` or `MISS` based on calibrated threshold.
* `inferred_secret_bit`: Extracted binary value (`1` or `0`).
* `side_channel_anomaly`: Combined anomaly detection flag.

---

## 🐍 Python Quickstart

```python
from cache_coherence_flush_reload import (
    FlushReloadEngine,
    MesiCoherenceEngine,
    TTableLeakageScanner,
    CacheCoherenceFlushReloadAgent,
    format_security_dossier,
)

# 1. Simulate & evaluate Flush+Reload timing traces
secret_bits = [1, 0, 1, 1, 0]
timings = FlushReloadEngine.synthesize_traces(secret_bits, rounds_per_bit=10)
timing_results = FlushReloadEngine.analyze_timings(timings)
print(f"Optimal Threshold: {timing_results.optimal_threshold_cycles} cycles")
print(f"Extracted Bitstring: {timing_results.extracted_bitstring} (d' = {timing_results.cohens_d_prime})")

# 2. Simulate multi-core MESI cache coherence
engine = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
engine.processor_read(core_id=0, address=0x1000)   # Core 0: Exclusive
engine.processor_read(core_id=1, address=0x1000)   # Core 0, 1: Shared
engine.processor_write(core_id=2, address=0x1000)  # Core 2: Modified, Core 0, 1: Invalidated

# 3. Run full security audit
dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
    analysis_id="QUICKSTART-AUDIT",
    timings=timings,
    coherence_engine=engine,
    flush_rate_per_sec=95000.0,
)
print(format_security_dossier(dossier))
```

---

## 🧪 Testing & Verification

Run the automated test suite with pytest:

```bash
python -m pytest -p no:zarr -v
```

Execute CLI batch smoke test:

```bash
python cli.py batch -i sample.csv -o out_smoke.csv
```

