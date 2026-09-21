# Cache Timing & Coherence Analyzer

### [Open the Live Application →](https://abusuraihsakhri.github.io/cache-coherence-flush-reload-agent/)

A small Python and browser-based toolkit for analyzing timing traces and simulating basic MESI/MOESI cache-coherence state transitions.

The project operates on synthetic or user-supplied data. It does **not** perform privileged cache operations, inspect another process, or establish that a live side-channel attack is occurring.

## Features

- Otsu-style threshold selection for two-cluster timing traces
- Lower- and higher-latency classification with standardized separation and an SNR heuristic
- Grouped binary-state summaries for repeated measurements
- MESI/MOESI state-transition simulation across multiple modeled cores
- Entropy-based screening of 16-line access distributions
- CSV batch processing from the command line
- Local browser interface with light/dark theme, CSV import, CSV export, and a coherence example
- Automated tests on Python 3.10, 3.11, and 3.12

## Browser application

The static application is in `docs/` and is designed for GitHub Pages. It runs entirely in the browser using HTML, CSS, and JavaScript; uploaded CSV data is not sent to a server.

The browser interface implements the timing-trace and compact coherence workflows directly in JavaScript. Pyodide is intentionally not required, which keeps startup fast and avoids a large external WebAssembly runtime download.

### CSV input

The browser and CLI recognize the first available timing column with one of these names:

- `reload_access_cycles`
- `reload_time`
- `reload_cycles`
- `latency`
- `primary_metric`

A compatible example is provided in `sample.csv` and `docs/sample.csv`.

## Python usage

Python 3.10 or newer is required.

```bash
python -m pip install -e .
cache-coherence-analyze --analysis-id EXAMPLE --timings 72,78,81,275,289,301 --threshold 120 --json
```

Process a CSV file:

```bash
cache-coherence-analyze batch -i sample.csv -o results.csv
```

Run deterministic demonstrations:

```bash
cache-coherence-analyze --demo flush_reload
cache-coherence-analyze --demo prime_probe
cache-coherence-analyze --demo coherence_race
```

The demonstration commands use synthetic/model data. Their risk labels summarize the model output; they are not evidence of activity on the host running the program.

## Python API

```python
from cache_coherence_flush_reload import FlushReloadEngine, MesiCoherenceEngine

timings = [72, 78, 81, 75, 276, 289, 301, 284]
result = FlushReloadEngine.analyze_timings(timings, rounds_per_bit=4)
print(result.optimal_threshold_cycles)
print(result.extracted_bitstring)

coherence = MesiCoherenceEngine(num_cores=4, protocol="MOESI")
coherence.processor_read(0, 0x1000)
coherence.processor_read(1, 0x1000)
coherence.processor_write(2, 0x1000)
print([coherence.get_state(core, 0x1000).value for core in range(4)])
```

## Development

Install the development tools and run the same checks used by CI:

```bash
python -m pip install -e ".[dev]"
python -m pip check
python -m compileall -q .
ruff check .
python -m build
python -m pytest -p no:zarr -v
```

The package has no third-party runtime dependencies. Development-only dependencies are pytest, Ruff, and build.

## Privacy and security

The browser application processes data locally. It does not use analytics, external APIs, remote fonts, or client-side secrets. The Python tools read only the files explicitly provided to them.

Timing separation, variance thresholds, entropy flags, and the activity score are heuristics. Confirm security findings with appropriate native instrumentation, hardware performance counters, controlled experiments, and the relevant processor documentation before drawing operational conclusions.

## Browser compatibility

The Pages interface targets current versions of Chrome, Edge, Firefox, and Safari. It uses standard browser APIs for local file reading, Blob-based CSV download, and optional theme persistence in `localStorage`.

## License

MIT. See [LICENSE](LICENSE).
