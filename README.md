# Cache Coherence Flush Reload Agent

> **Domain:** Clinical Decision Support & Biomedical Computing  
> **Reference Guidelines & Standards:** `Standard Clinical Formulations & ISO/IEC Quality Frameworks`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

Cache Coherence & Flush+Reload Side-Channel Analysis Engine
===========================================================
High-performance microarchitectural security analysis engine implementing:
- Flush+Reload, Prime+Probe, and Flush+Flush side-channel attack/defense simulation
- Automated bimodal threshold calibration (Otsu's method and maximal gap)
- Signal quality scoring (Cohen's d', SNR, empirical BER)
- Multi-core MESI/MOESI cache coherence protocol state machine
- AES T-table side-channel cryptographic leak reconstruction
- Hardware performance counter anomaly detection (flush rate, LLC miss burst)

Standards & References:
- Yarom & Falkner (USENIX Security 2014) "FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack"
- Gruss et al. (DIMVA 2016) "Flush+Flush: A Fast and Stealthy Cache Attack"
- MESI / MOESI Cache Coherence Protocol Specifications (IEEE 1596 / AMD64 Architecture)

Cross-core Invalidation Agent for Cache Coherence Flush/Reload Agent.
Simulates and detects cross-core cache invalidation failures and stale data issues.

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Algorithmic & Evaluation Engines

- **`CoherenceState`** — dedicated module for coherence state evaluation and state verification.
- **`AttackType`** — dedicated module for attack type evaluation and state verification.
- **`ThreatSeverity`** — dedicated module for threat severity evaluation and state verification.
- **`TimingAnalysisResult`**: Statistical summary of cache access timings.
- **`CoherenceEvent`**: Single bus/coherence transaction across cores.
- **`TTableAnalysisResult`**: Cryptographic T-table side-channel evaluation.

---

## 📐 Mathematical Formulation & Logic

```text
  Calculate Shannon entropy: H(X) = -sum(p_i * log2(p_i))
  return (address // LINE_SIZE_BYTES) % total_sets
  z_score = (data["mean_ns"] - overall_mean) / max(overall_std, 1)
  return (entry_index * ENTRY_SIZE_BYTES) // LINE_SIZE_BYTES
```

---

## 💻 CLI Quickstart & Usage

### 1. Guided Interactive Mode
```bash
python cli.py
```

### 2. Direct Parameterized Evaluation
```bash
python cli.py --interactive <value> --demo <value> --analysis-id <value> --synthesize-bits <value>
```

### Parameter Reference
- `--interactive`: Specifies input measurement or parameter value.
- `--demo`: Specifies input measurement or parameter value.
- `--analysis-id`: Specifies input measurement or parameter value.
- `--synthesize-bits`: Specifies input measurement or parameter value.
- `--timings`: Specifies input measurement or parameter value.
- `--threshold`: Specifies input measurement or parameter value.
- `--rounds-per-bit`: Specifies input measurement or parameter value.
- `--cores`: Specifies input measurement or parameter value.
- `--protocol`: Specifies input measurement or parameter value.
- `--ttable-counts`: Specifies input measurement or parameter value.

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `task_id` | Parameter / observation metric | Required |
| `target_identifier` | Parameter / observation metric | Required |
| `primary_metric` | Parameter / observation metric | Required |
| `secondary_metric` | Parameter / observation metric | Required |
| `is_critical_flag` | Parameter / observation metric | Required |
| `status_descriptor` | Parameter / observation metric | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py --tasks 1000 --concurrency 8
```

---

## 🐳 Container Deployment

```bash
docker build -t cache-coherence-flush-reload-agent .
docker run -p 8000:8000 cache-coherence-flush-reload-agent
```
