"use strict";

const timingInput = document.getElementById("timingInput");
const groupSizeInput = document.getElementById("groupSize");
const manualThresholdInput = document.getElementById("manualThreshold");
const analyzeButton = document.getElementById("analyzeButton");
const loadExampleButton = document.getElementById("loadExample");
const csvInput = document.getElementById("csvInput");
const downloadButton = document.getElementById("downloadButton");
const errorMessage = document.getElementById("errorMessage");
const sourceLabel = document.getElementById("sourceLabel");

const timingAliases = [
  "reload_access_cycles",
  "reload_time",
  "reload_cycles",
  "latency",
  "primary_metric",
];

let currentCsv = null;
let currentAnalysis = null;

function finiteNonNegative(value) {
  return Number.isFinite(value) && value >= 0;
}

function parseTimingText(raw) {
  const tokens = raw
    .split(/[\s,;]+/)
    .map((token) => token.trim())
    .filter(Boolean);
  if (tokens.length < 2) {
    throw new Error("Enter at least two timing samples.");
  }
  const values = tokens.map(Number);
  if (!values.every(finiteNonNegative)) {
    throw new Error("Timing samples must be finite, non-negative numbers.");
  }
  return values;
}

function mean(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function sampleVariance(values, valueMean) {
  if (values.length <= 1) return 0;
  return (
    values.reduce((sum, value) => sum + (value - valueMean) ** 2, 0) /
    (values.length - 1)
  );
}

function otsuThreshold(values) {
  if (!values.length) throw new Error("Timing samples cannot be empty.");
  if (values.length === 1) return values[0];

  const ordered = [...values].sort((a, b) => a - b);
  const minValue = ordered[0];
  const maxValue = ordered[ordered.length - 1];
  if (minValue === maxValue) return minValue;

  const binCount = Math.min(100, Math.max(10, Math.floor(values.length / 2)));
  const binWidth = (maxValue - minValue) / binCount;
  const bins = new Array(binCount).fill(0);

  for (const value of values) {
    const index = Math.min(Math.floor((value - minValue) / binWidth), binCount - 1);
    bins[index] += 1;
  }

  const total = values.length;
  const totalWeighted = bins.reduce((sum, count, index) => sum + index * count, 0);
  let backgroundWeight = 0;
  let backgroundWeighted = 0;
  let maxVariance = -1;
  let bestBin = 0;

  for (let index = 0; index < binCount; index += 1) {
    backgroundWeight += bins[index];
    if (backgroundWeight === 0) continue;

    const foregroundWeight = total - backgroundWeight;
    if (foregroundWeight === 0) break;

    backgroundWeighted += index * bins[index];
    const backgroundMean = backgroundWeighted / backgroundWeight;
    const foregroundMean =
      (totalWeighted - backgroundWeighted) / foregroundWeight;
    const betweenVariance =
      backgroundWeight *
      foregroundWeight *
      (backgroundMean - foregroundMean) ** 2;

    if (betweenVariance > maxVariance) {
      maxVariance = betweenVariance;
      bestBin = index;
    }
  }

  return minValue + (bestBin + 0.5) * binWidth;
}

function analyze(values, groupSize, manualThreshold) {
  if (!Number.isInteger(groupSize) || groupSize <= 0) {
    throw new Error("Group size must be a positive integer.");
  }

  const threshold =
    manualThreshold === null ? otsuThreshold(values) : manualThreshold;
  if (!finiteNonNegative(threshold)) {
    throw new Error("Threshold must be a finite, non-negative number.");
  }

  const low = values.filter((value) => value < threshold);
  const high = values.filter((value) => value >= threshold);
  const lowMean = low.length ? mean(low) : 0;
  const highMean = high.length ? mean(high) : 0;
  const lowVariance = sampleVariance(low, lowMean);
  const highVariance = sampleVariance(high, highMean);
  const bothClasses = low.length > 0 && high.length > 0;
  const pooledStd = bothClasses
    ? Math.sqrt((lowVariance + highVariance) / 2)
    : 0;
  const delta = bothClasses ? Math.abs(highMean - lowMean) : 0;
  const separation =
    bothClasses && pooledStd > 1e-12 ? delta / pooledStd : 0;
  const snr =
    separation > 0 ? 20 * Math.log10(Math.max(1e-12, separation)) : 0;

  const bits = [];
  for (let index = 0; index < values.length; index += groupSize) {
    const chunk = values.slice(index, index + groupSize);
    const lowCount = chunk.filter((value) => value < threshold).length;
    bits.push(lowCount > chunk.length / 2 ? "1" : "0");
  }

  return {
    threshold,
    low,
    high,
    separation,
    snr,
    bits: bits.join(""),
    strongSeparation: separation >= 3.5 && bothClasses,
  };
}

function formatMetric(value, suffix = "") {
  return Number.isFinite(value) ? `${value.toFixed(2)}${suffix}` : "—";
}

function renderAnalysis(values, result) {
  document.getElementById("sampleCount").textContent = String(values.length);
  document.getElementById("thresholdValue").textContent =
    formatMetric(result.threshold, " c");
  document.getElementById("separationValue").textContent =
    result.separation.toFixed(2);
  document.getElementById("snrValue").textContent =
    formatMetric(result.snr, " dB");
  document.getElementById("hitCount").textContent = String(result.low.length);
  document.getElementById("missCount").textContent = String(result.high.length);
  document.getElementById("bitPattern").textContent = result.bits || "—";

  const total = Math.max(values.length, 1);
  document.getElementById("hitBar").style.width =
    `${(100 * result.low.length) / total}%`;
  document.getElementById("missBar").style.width =
    `${(100 * result.high.length) / total}%`;

  const badge = document.getElementById("statusBadge");
  badge.classList.remove("good", "warn");
  if (result.strongSeparation) {
    badge.textContent = "Strong separation";
    badge.classList.add("warn");
  } else {
    badge.textContent = "No strong split";
    badge.classList.add("good");
  }

  downloadButton.disabled = false;
}

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function clearError() {
  errorMessage.textContent = "";
  errorMessage.hidden = true;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];

    if (quoted) {
      if (char === '"' && next === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }

  if (quoted) throw new Error("CSV contains an unterminated quoted field.");
  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ""));
    rows.push(row);
  }

  const nonEmptyRows = rows.filter((cells) =>
    cells.some((cell) => cell.trim() !== "")
  );
  if (nonEmptyRows.length < 2) {
    throw new Error("CSV must contain a header and at least one data row.");
  }
  return nonEmptyRows;
}

function csvTimingData(rows) {
  const header = rows[0].map((value) => value.trim());
  const lowerHeader = header.map((value) => value.toLowerCase());
  const timingIndex = timingAliases
    .map((alias) => lowerHeader.indexOf(alias))
    .find((index) => index >= 0);

  if (timingIndex === undefined) {
    throw new Error(
      `CSV needs one timing column: ${timingAliases.join(", ")}.`
    );
  }

  const values = [];
  for (const row of rows.slice(1)) {
    const value = Number((row[timingIndex] || "").trim());
    if (finiteNonNegative(value)) values.push(value);
  }

  if (values.length < 2) {
    throw new Error("CSV contains fewer than two valid timing values.");
  }

  return { header, timingIndex, values, rows: rows.slice(1) };
}

function escapeCsv(value) {
  const text = String(value ?? "");
  return /[",\n\r]/.test(text)
    ? `"${text.replaceAll('"', '""')}"`
    : text;
}

function buildProcessedCsv(values, result) {
  if (!currentCsv) {
    const lines = [
      [
        "sample_index",
        "timing_cycles",
        "calibrated_threshold",
        "evaluated_classification",
        "inferred_binary_state",
      ],
    ];
    values.forEach((value, index) => {
      const isLow = value < result.threshold;
      lines.push([
        index + 1,
        value,
        result.threshold.toFixed(1),
        isLow ? "HIT" : "MISS",
        isLow ? 1 : 0,
      ]);
    });
    return lines.map((row) => row.map(escapeCsv).join(",")).join("\n");
  }

  const extras = [
    "calibrated_threshold",
    "evaluated_classification",
    "inferred_binary_state",
    "side_channel_anomaly",
  ];
  const header = [...currentCsv.header, ...extras];
  const declaredIndex = currentCsv.header.findIndex(
    (value) => value.toLowerCase() === "classification"
  );
  const anomalyIndex = currentCsv.header.findIndex(
    (value) => value.toLowerCase() === "anomaly_detected"
  );

  const lines = [header];
  for (const originalRow of currentCsv.rows) {
    const row = [...originalRow];
    while (row.length < currentCsv.header.length) row.push("");

    const timingValue = Number(
      (row[currentCsv.timingIndex] || "").trim()
    );
    let evaluated = "UNKNOWN";
    let binaryState = 0;

    if (finiteNonNegative(timingValue)) {
      const isLow = timingValue < result.threshold;
      evaluated = isLow ? "HIT" : "MISS";
      binaryState = isLow ? 1 : 0;
    }

    const declared =
      declaredIndex >= 0 ? (row[declaredIndex] || "").trim().toUpperCase() : "";
    const explicitAnomaly =
      anomalyIndex >= 0 &&
      ["true", "1", "yes"].includes(
        (row[anomalyIndex] || "").trim().toLowerCase()
      );
    const mismatch =
      ["HIT", "MISS"].includes(declared) &&
      ["HIT", "MISS"].includes(evaluated) &&
      declared !== evaluated;

    row.push(
      result.threshold.toFixed(1),
      evaluated,
      String(binaryState),
      String(explicitAnomaly || mismatch)
    );
    lines.push(row);
  }

  return lines.map((row) => row.map(escapeCsv).join(",")).join("\n");
}

function runAnalysis() {
  clearError();
  try {
    const values = currentCsv ? currentCsv.values : parseTimingText(timingInput.value);
    const groupSize = Number(groupSizeInput.value);
    const manualRaw = manualThresholdInput.value.trim();
    const manualThreshold = manualRaw === "" ? null : Number(manualRaw);
    const result = analyze(values, groupSize, manualThreshold);
    currentAnalysis = { values, result };
    renderAnalysis(values, result);
  } catch (error) {
    currentAnalysis = null;
    downloadButton.disabled = true;
    showError(error instanceof Error ? error.message : "Analysis failed.");
  }
}

analyzeButton.addEventListener("click", () => {
  currentCsv = null;
  sourceLabel.textContent = "Manual input";
  runAnalysis();
});

loadExampleButton.addEventListener("click", () => {
  timingInput.value =
    "72, 78, 81, 75, 76, 83, 275, 289, 301, 284, 292, 271";
  groupSizeInput.value = "4";
  manualThresholdInput.value = "";
  currentCsv = null;
  sourceLabel.textContent = "Example data";
  runAnalysis();
});

csvInput.addEventListener("change", async (event) => {
  clearError();
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  try {
    if (file.size > 5 * 1024 * 1024) {
      throw new Error("CSV files larger than 5 MB are not accepted in the browser tool.");
    }
    const rows = parseCsv(await file.text());
    currentCsv = csvTimingData(rows);
    timingInput.value = currentCsv.values.slice(0, 80).join(", ");
    sourceLabel.textContent = file.name;
    runAnalysis();
  } catch (error) {
    currentCsv = null;
    showError(error instanceof Error ? error.message : "Could not read CSV.");
  } finally {
    event.target.value = "";
  }
});

downloadButton.addEventListener("click", () => {
  if (!currentAnalysis) return;
  const content = buildProcessedCsv(
    currentAnalysis.values,
    currentAnalysis.result
  );
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cache-timing-analysis.csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

function activateTab(target) {
  const timingActive = target === "timing";
  document.getElementById("timingPanel").hidden = !timingActive;
  document.getElementById("coherencePanel").hidden = timingActive;

  for (const [buttonId, active] of [
    ["timingTab", timingActive],
    ["coherenceTab", !timingActive],
  ]) {
    const button = document.getElementById(buttonId);
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  }
}

document.getElementById("timingTab").addEventListener("click", () => activateTab("timing"));
document.getElementById("coherenceTab").addEventListener("click", () => activateTab("coherence"));

document.querySelector(".tabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
  event.preventDefault();
  const next =
    document.getElementById("timingTab").getAttribute("aria-selected") === "true"
      ? "coherence"
      : "timing";
  activateTab(next);
  document.getElementById(next === "timing" ? "timingTab" : "coherenceTab").focus();
});

function renderCoherence() {
  const protocol = document.getElementById("protocol").value;
  const cores = Number(document.getElementById("coreCount").value);
  const badge = document.getElementById("coherenceBadge");

  if (!Number.isInteger(cores) || cores < 2 || cores > 8) {
    badge.textContent = "Use 2–8 cores";
    badge.classList.remove("good");
    badge.classList.add("warn");
    return;
  }

  const states = new Array(cores).fill("I");
  const events = [];

  states[0] = "E";
  events.push("Core 0 read: I → E");

  states[0] = "S";
  states[1] = "S";
  events.push("Core 1 read: Core 0 E → S; Core 1 I → S");

  const writer = cores > 2 ? 2 : 1;
  states.fill("I");
  states[writer] = "M";
  events.push(`Core ${writer} write: peer copies → I; writer → M`);

  if (protocol === "MOESI") {
    events.push("MOESI Owner state applies when a peer reads a Modified line.");
  }

  const coreGrid = document.getElementById("coreGrid");
  coreGrid.replaceChildren();
  states.forEach((state, index) => {
    const item = document.createElement("div");
    item.className = "core-state";
    const label = document.createElement("span");
    label.textContent = `Core ${index}`;
    const value = document.createElement("strong");
    value.textContent = state;
    item.append(label, value);
    coreGrid.appendChild(item);
  });

  const eventList = document.getElementById("eventList");
  eventList.replaceChildren();
  events.forEach((eventText) => {
    const item = document.createElement("li");
    item.textContent = eventText;
    eventList.appendChild(item);
  });

  badge.textContent = protocol;
  badge.classList.remove("warn");
  badge.classList.add("good");
}

document.getElementById("simulateButton").addEventListener("click", renderCoherence);

const themeToggle = document.getElementById("themeToggle");
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeToggle.setAttribute(
    "aria-label",
    theme === "dark" ? "Switch to light theme" : "Switch to dark theme"
  );
}

let savedTheme = null;
try {
  savedTheme = localStorage.getItem("cache-timing-theme");
} catch {
  savedTheme = null;
}
const preferredTheme =
  savedTheme ||
  (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
applyTheme(preferredTheme);

themeToggle.addEventListener("click", () => {
  const next =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try {
    localStorage.setItem("cache-timing-theme", next);
  } catch {
    // Theme persistence is optional.
  }
});

runAnalysis();
renderCoherence();
