# Cache Coherence & Flush+Reload Side-Channel Security Engine

An enterprise microarchitectural security analysis, covert-channel auditing, and multi-core cache coherence verification engine designed to model, detect, and mitigate **Flush+Reload**, **Prime+Probe**, and **Flush+Flush** timing side-channel attacks across CPU cache hierarchies.

---

## Technical & Microarchitectural Overview

### 1. Flush+Reload Side-Channel Mechanics
The Flush+Reload technique targets shared, read-only memory pages (such as shared cryptographic libraries or system binaries) mapped across multiple security domains:
1. **FLUSH**: The attacker evicts a specific target cache line from the entire cache hierarchy using the unprivileged `clflush` instruction.
2. **VICTIM EXECUTION**: The attacker pauses to allow the victim process to execute. If the victim accesses the target line (e.g., an AES S-box/T-table entry or RSA modular exponentiation branch), the line is reloaded into cache.
3. **RELOAD**: The attacker measures access latency to the line using hardware cycle timestamp counters (`rdtsc` / `rdtscp`).
   - **Cache Hit ($50 - 100\text{ cycles}$)**: Line was accessed by the victim.
   - **Cache Miss / DRAM ($200 - 350\text{ cycles}$)**: Line was not accessed.

### 2. Automated Threshold Calibration & Signal Metrics
- **Otsu's Discriminant Thresholding**: Computes the optimal threshold $T^*$ minimizing intra-class timing variance and maximizing separation between hit and miss clusters:
  $$\sigma_w^2(T) = \omega_0(T)\sigma_0^2(T) + \omega_1(T)\sigma_1^2(T)$$
- **Cohen's $d'$ Sensitivity Index**: Measures effect size and channel reliability:
  $$d' = \frac{|\mu_{\text{miss}} - \mu_{\text{hit}}|}{\sqrt{\frac{\sigma_{\text{hit}}^2 + \sigma_{\text{miss}}^2}{2}}}$$
  Values of $d' \ge 3.5$ indicate high-fidelity key recovery conditions.
- **Signal-to-Noise Ratio (SNR)**:
  $$\text{SNR}_{\text{dB}} = 20 \log_{10}\left(\frac{|\mu_{\text{miss}} - \mu_{\text{hit}}|}{\sigma_{\text{pooled}}}\right)$$

### 3. MESI / MOESI Multi-Core Coherence Protocol State Machine
Models multi-core L1/L2/LLC private and shared cache line transitions across $N$ CPU cores:
- **Modified (M)**: Exclusive ownership, dirty data.
- **Owner (O)**: Shared ownership with dirty write-back responsibility (MOESI).
- **Exclusive (E)**: Exclusive ownership, clean data.
- **Shared (S)**: Shared across one or more caches, clean.
- **Invalid (I)**: Evicted or invalidated via bus broadcast (`BusUpgr`, `BusRdX`, `clflush`).

### 4. Cryptographic AES T-Table Shannon Entropy Scanner
Calculates Shannon entropy across the 16 cache lines comprising an AES T-table ($1024\text{ bytes} / 64\text{ bytes} = 16\text{ lines}$):
$$H(X) = -\sum_{i=0}^{15} p_i \log_2(p_i)$$
Deviations from maximum entropy ($4.0\text{ bits}$) expose key-dependent lookup biases.

---

## Installation

Requires **Python 3.9+** (zero external dependencies).

```bash
git clone https://github.com/abusuraihsakhri/cache-coherence-flush-reload-agent.git
cd cache-coherence-flush-reload-agent
```

---

## CLI Usage Examples

### 1. Run Pre-Configured Benchmark Scenarios

```bash
python cli.py --demo flush_reload
python cli.py --demo ttable_leak
python cli.py --demo coherence_race
python cli.py --demo prime_probe
```

### 2. Direct Trace Timing Audit with JSON Output

```bash
python cli.py --analysis-id AUDIT-X86-01 --timings 65,70,68,280,290,285 \
  --threshold 120.0 --flush-rate 95000 --json
```

### 3. Interactive Security Audit

```bash
python cli.py --interactive
```

---

## Python API Usage

```python
from cache_coherence_flush_reload import (
    MesiCoherenceEngine,
    FlushReloadEngine,
    TTableLeakageScanner,
    CacheCoherenceFlushReloadAgent,
    format_security_dossier,
)

# 1. Synthesize and evaluate timing trace
traces = FlushReloadEngine.synthesize_traces([1, 0, 1, 1, 0, 1], rounds_per_bit=12)
timing_result = FlushReloadEngine.analyze_timings(traces)

# 2. Multi-core MOESI coherence tracking
engine = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
engine.processor_write(core_id=0, address=0x4000, data=0xBEEF)
engine.processor_read(core_id=1, address=0x4000)

# 3. Full security audit dossier
dossier = CacheCoherenceFlushReloadAgent.run_full_security_audit(
    analysis_id="AUDIT-SERVER-04",
    timings=traces,
    coherence_engine=engine,
    flush_rate_per_sec=110000.0
)

print(format_security_dossier(dossier))
```

---

## Unit Testing

Run the automated test suite with 22 unit test cases:

```bash
python -m unittest test_cache_coherence_flush_reload.py -v
```

---

## License

MIT License. Authored and maintained by Dr. Abu Suraih Sakhri.
