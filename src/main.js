/**
 * PRIVEX application controller.
 * Strict zero-storage, zero-network, safe DOM construction.
 */

import { AuditLogger } from "./audit/logger.js";
import { NOISY_SAMPLE_TEXT } from "./data/sample.js";
import { ENTITY_META, ENTITY_TYPES } from "./engine/detectors.js";
import { createEmptyCounts, PseudonymRegistry, REDACTION_MODES, redactText } from "./engine/redactor.js";
import { assessPrivacyRisk } from "./engine/risk.js";
import { parseCsv, sanitizeCsvDocument, serializeCsv } from "./parsers/csv.js";
import { runTestSuite } from "./tests/suite.js";
import { copyTextToClipboard, downloadTextFile } from "./utils/export.js";

const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB safety cap for responsive browser memory

const state = {
  rawText: "",
  inputFormat: "text", // 'text' | 'csv'
  fileName: "",
  fileSizeBytes: 0,
  mode: REDACTION_MODES.PSEUDONYM,
  leftView: "edit", // 'edit' | 'highlight'
  activeFilter: "ALL",
  lastResult: null,
  lastRisk: assessPrivacyRisk(createEmptyCounts()),
};

const auditLogger = new AuditLogger();

const els = {
  rawInput: document.getElementById("raw-input"),
  originalHighlight: document.getElementById("original-highlight-view"),
  sanitizedOutput: document.getElementById("sanitized-output-view"),
  inputFormatBadge: document.getElementById("input-format-badge"),
  modeStatusBadge: document.getElementById("mode-status-badge"),
  originalMeta: document.getElementById("original-meta"),
  sanitizedMeta: document.getElementById("sanitized-meta"),
  copyFeedback: document.getElementById("copy-feedback"),

  btnSample: document.getElementById("btn-sample"),
  btnUpload: document.getElementById("btn-upload"),
  fileInput: document.getElementById("file-input"),
  btnSanitize: document.getElementById("btn-sanitize"),
  btnClear: document.getElementById("btn-clear"),
  btnTests: document.getElementById("btn-tests"),

  tabEdit: document.getElementById("tab-edit"),
  tabHighlight: document.getElementById("tab-highlight"),

  btnCopy: document.getElementById("btn-copy"),
  btnDownloadTxt: document.getElementById("btn-download-txt"),
  btnDownloadCsv: document.getElementById("btn-download-csv"),

  riskBadge: document.getElementById("risk-badge"),
  riskSummary: document.getElementById("risk-summary"),
  riskFactors: document.getElementById("risk-factors"),

  countTotal: document.getElementById("count-total"),
  subUnique: document.getElementById("sub-unique"),
  countLuhnRejected: document.getElementById("count-luhn-rejected"),
  entityCounts: {
    [ENTITY_TYPES.EMAIL]: document.getElementById("count-EMAIL"),
    [ENTITY_TYPES.PHONE]: document.getElementById("count-PHONE"),
    [ENTITY_TYPES.IPV4]: document.getElementById("count-IPV4"),
    [ENTITY_TYPES.PAN]: document.getElementById("count-PAN"),
    [ENTITY_TYPES.AADHAAR]: document.getElementById("count-AADHAAR"),
    [ENTITY_TYPES.CREDIT_CARD]: document.getElementById("count-CREDIT_CARD"),
  },

  auditTbody: document.getElementById("audit-tbody"),
  btnClearAudit: document.getElementById("btn-clear-audit"),
  btnExportAudit: document.getElementById("btn-export-audit"),

  testModal: document.getElementById("test-modal"),
  testSummaryText: document.getElementById("test-summary-text"),
  testResultsList: document.getElementById("test-results-list"),
  btnRerunTests: document.getElementById("btn-rerun-tests"),
  btnCloseTests: document.getElementById("btn-close-tests"),
};

let editDebounceTimer = null;
let auditEditTimer = null;

/**
 * Safely renders text + highlighted segments into a container via text nodes and DOM elements.
 * @param {HTMLElement} container
 * @param {Array<object>} segments
 * @param {'original' | 'sanitized'} side
 */
function renderSegmentedView(container, segments, side) {
  container.replaceChildren();

  if (!segments || segments.length === 0) {
    const empty = document.createElement("span");
    empty.className = "empty-state";
    empty.textContent =
      side === "original"
        ? "No input loaded yet."
        : "Sanitized output will appear here automatically.";
    container.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();

  for (const seg of segments) {
    if (seg.kind === "plain") {
      fragment.appendChild(document.createTextNode(seg.text));
      continue;
    }

    const mark = document.createElement("mark");
    const isDimmed = state.activeFilter !== "ALL" && seg.type !== state.activeFilter;
    if (side === "original") {
      mark.className = `hl hl-${seg.type}${isDimmed ? " hl-dimmed" : ""}`;
      const label = ENTITY_META[seg.type]?.label || seg.type;
      mark.title = `${label} · ${seg.validation}\nReplaced with: ${seg.replacement}\nRisk: ${seg.riskReason}`;
    } else {
      mark.className = `redacted-hl${isDimmed ? " hl-dimmed" : ""}`;
      const label = ENTITY_META[seg.type]?.label || seg.type;
      mark.title = `Redacted ${label} (${seg.validation})`;
    }
    mark.textContent = seg.text;
    fragment.appendChild(mark);
  }

  container.appendChild(fragment);
}

/**
 * Switches the left pane between raw textarea editing and highlighted PII view.
 * @param {'edit' | 'highlight'} view
 */
function setLeftView(view) {
  state.leftView = view;
  const isEdit = view === "edit";
  els.tabEdit.classList.toggle("active", isEdit);
  els.tabEdit.setAttribute("aria-selected", String(isEdit));
  els.tabHighlight.classList.toggle("active", !isEdit);
  els.tabHighlight.setAttribute("aria-selected", String(!isEdit));

  els.rawInput.classList.toggle("hidden", !isEdit);
  els.originalHighlight.classList.toggle("hidden", isEdit);
}

/**
 * Executes detection + redaction on current state and updates all dashboard panels.
 */
function processCurrentData() {
  const text = state.rawText;

  if (!text) {
    state.lastResult = null;
    state.lastRisk = assessPrivacyRisk(createEmptyCounts());
    renderDashboard();
    return;
  }

  if (state.inputFormat === "csv") {
    state.lastResult = sanitizeCsvDocument(text, state.mode);
  } else {
    state.lastResult = redactText(text, state.mode, new PseudonymRegistry());
  }

  state.lastRisk = assessPrivacyRisk(state.lastResult.counts);
  renderDashboard();
}

function renderDashboard() {
  const res = state.lastResult;
  const counts = res ? res.counts : createEmptyCounts();
  const risk = state.lastRisk;

  // Format & mode badges
  if (state.inputFormat === "csv" && res?.rowCount != null) {
    els.inputFormatBadge.textContent = `CSV · ${res.rowCount}R × ${res.colCount}C`;
  } else {
    els.inputFormatBadge.textContent = state.inputFormat.toUpperCase();
  }
  els.modeStatusBadge.textContent =
    state.mode === REDACTION_MODES.FULL
      ? "FULL MASK"
      : state.mode === REDACTION_MODES.PARTIAL
        ? "PARTIAL MASK"
        : "PSEUDONYM";

  // Counters
  els.countTotal.textContent = String(counts.total);
  const uniqueCount = res ? res.uniqueCount : 0;
  els.subUnique.textContent = `${uniqueCount} unique ${uniqueCount === 1 ? "entity" : "entities"}`;
  els.countLuhnRejected.textContent = String(res ? res.luhnRejected.length : 0);

  for (const [type, el] of Object.entries(els.entityCounts)) {
    el.textContent = String(counts.byType[type] || 0);
  }

  // Risk indicator
  els.riskBadge.textContent = `${risk.level} · ${risk.score} PTS`;
  els.riskBadge.className = `risk-badge risk-${risk.level.toLowerCase()}`;
  els.riskSummary.textContent = risk.summary;

  els.riskFactors.replaceChildren();
  for (const factor of risk.factors) {
    const chip = document.createElement("span");
    chip.className = "risk-chip";
    chip.textContent = factor;
    els.riskFactors.appendChild(chip);
  }

  // Original & Sanitized views
  renderSegmentedView(els.originalHighlight, res?.originalSegments, "original");
  renderSegmentedView(els.sanitizedOutput, res?.sanitizedSegments, "sanitized");

  const charCount = state.rawText.length;
  const lineCount = state.rawText ? state.rawText.split(/\r\n|\r|\n/).length : 0;
  els.originalMeta.textContent = `${charCount.toLocaleString()} chars · ${lineCount.toLocaleString()} lines`;
  els.sanitizedMeta.textContent = `${counts.total} redactions applied · ${res ? res.luhnRejected.length : 0} Luhn false-positives blocked`;
}

function renderAuditLog() {
  const entries = auditLogger.getAll();
  els.auditTbody.replaceChildren();

  if (entries.length === 0) {
    const tr = document.createElement("tr");
    tr.className = "audit-empty";
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = "No events recorded yet. Load the noisy sample, paste text, or upload a file.";
    tr.appendChild(td);
    els.auditTbody.appendChild(tr);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const entry of entries) {
    const tr = document.createElement("tr");
    const cells = [
      entry.timestamp.slice(11, 19),
      entry.action,
      entry.mode,
      `${entry.fileType.toUpperCase()} (${entry.fileSizeBytes} B)`,
      String(entry.totalFindings),
      String(entry.luhnRejectedCount),
      entry.riskLevel,
      entry.note || formatEntitySummary(entry.entityCounts),
    ];
    for (const val of cells) {
      const td = document.createElement("td");
      td.textContent = val;
      tr.appendChild(td);
    }
    fragment.appendChild(tr);
  }
  els.auditTbody.appendChild(fragment);
}

function formatEntitySummary(entityCounts) {
  const parts = [];
  for (const [type, count] of Object.entries(entityCounts || {})) {
    if (count > 0) {
      parts.push(`${ENTITY_META[type]?.placeholderPrefix || type}:${count}`);
    }
  }
  return parts.length > 0 ? parts.join(" ") : "No PII";
}

function recordAudit(action, note = "") {
  const counts = state.lastResult?.counts || createEmptyCounts();
  auditLogger.log({
    action,
    mode: state.mode,
    fileType: state.inputFormat,
    fileSizeBytes: state.fileSizeBytes || new Blob([state.rawText]).size,
    counts,
    luhnRejectedCount: state.lastResult?.luhnRejected?.length || 0,
    riskLevel: state.lastRisk.level,
    note,
  });
  renderAuditLog();
}

function showCopyFeedback(msg) {
  els.copyFeedback.textContent = msg;
  window.setTimeout(() => {
    if (els.copyFeedback.textContent === msg) {
      els.copyFeedback.textContent = "";
    }
  }, 2200);
}

function buildSanitizedCsvForExport() {
  if (!state.lastResult) return "";
  if (state.inputFormat === "csv") {
    return state.lastResult.sanitizedText;
  }
  // Convert plain sanitized lines into a clean 2-column CSV when user exports plain text as CSV
  const lines = state.lastResult.sanitizedText.split(/\r\n|\r|\n/);
  const rows = [["line_number", "sanitized_content"]];
  lines.forEach((line, idx) => {
    rows.push([String(idx + 1), line]);
  });
  return serializeCsv(rows, { neutralizeFormulas: true });
}

function openTestModalAndRun() {
  const report = runTestSuite();
  els.testSummaryText.textContent = `PRIVEX TEST SUITE — ${report.passed}/${report.total} TESTS PASSED`;
  els.testSummaryText.classList.toggle("test-summary-fail", report.failed > 0);
  els.btnTests.textContent = `Tests: ${report.passed}/${report.total}`;

  els.testResultsList.replaceChildren();
  for (const item of report.results) {
    const li = document.createElement("li");
    li.className = "test-item";

    const labelWrap = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = item.name;
    labelWrap.appendChild(title);
    if (item.error) {
      const errEl = document.createElement("div");
      errEl.className = "muted-hint";
      errEl.textContent = item.error;
      labelWrap.appendChild(errEl);
    }

    const badge = document.createElement("span");
    badge.className = `test-status ${item.passed ? "test-pass" : "test-fail"}`;
    badge.textContent = item.passed ? "PASS" : "FAIL";

    li.appendChild(labelWrap);
    li.appendChild(badge);
    els.testResultsList.appendChild(li);
  }

  els.testModal.classList.remove("hidden");
}

// EVENT LISTENERS
els.rawInput.addEventListener("input", () => {
  state.rawText = els.rawInput.value;
  state.fileName = "";
  state.fileSizeBytes = new Blob([state.rawText]).size;
  if (state.inputFormat !== "csv") {
    state.inputFormat = "text";
  }

  window.clearTimeout(editDebounceTimer);
  editDebounceTimer = window.setTimeout(() => {
    processCurrentData();
  }, 100);

  window.clearTimeout(auditEditTimer);
  auditEditTimer = window.setTimeout(() => {
    if (state.rawText.trim().length > 0) {
      recordAudit("TEXT_EDIT");
    }
  }, 800);
});

els.btnSample.addEventListener("click", () => {
  state.rawText = NOISY_SAMPLE_TEXT;
  state.inputFormat = "text";
  state.fileName = "noisy-sample.txt";
  state.fileSizeBytes = new Blob([NOISY_SAMPLE_TEXT]).size;
  els.rawInput.value = NOISY_SAMPLE_TEXT;

  processCurrentData();
  setLeftView("highlight");
  recordAudit("SAMPLE_LOAD", "Loaded built-in noisy dataset");
});

els.btnSanitize.addEventListener("click", () => {
  state.rawText = els.rawInput.value;
  processCurrentData();
  if (state.rawText.trim().length > 0) {
    setLeftView("highlight");
  }
  recordAudit("SANITIZE", "Manual scan executed");
  showCopyFeedback("Scanned ✓");
});

els.btnClear.addEventListener("click", () => {
  state.rawText = "";
  state.inputFormat = "text";
  state.fileName = "";
  state.fileSizeBytes = 0;
  state.activeFilter = "ALL";
  els.rawInput.value = "";
  document.querySelectorAll(".metric-card[data-filter]").forEach((card) => {
    card.classList.toggle("active-filter", card.dataset.filter === "ALL");
  });
  setLeftView("edit");
  processCurrentData();
  showCopyFeedback("Workspace cleared");
});

els.btnUpload.addEventListener("click", () => {
  els.fileInput.value = "";
  els.fileInput.click();
});

els.fileInput.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;

  if (file.size > MAX_FILE_BYTES) {
    showCopyFeedback("File exceeds 5 MB browser safety cap");
    return;
  }

  const lower = file.name.toLowerCase();
  const isCsv = lower.endsWith(".csv") || file.type === "text/csv";
  const isTxt = lower.endsWith(".txt") || file.type === "text/plain" || isCsv;
  if (!isTxt) {
    showCopyFeedback("Only .txt and .csv files are supported");
    return;
  }

  const content = await file.text();
  state.rawText = content;
  state.inputFormat = isCsv ? "csv" : "text";
  state.fileName = file.name;
  state.fileSizeBytes = file.size;
  els.rawInput.value = content;

  if (isCsv) {
    // Verify CSV parses cleanly
    parseCsv(content);
  }

  processCurrentData();
  setLeftView("highlight");
  recordAudit(isCsv ? "UPLOAD_CSV" : "UPLOAD_TXT", `Local file parsed (${isCsv ? "CSV" : "TXT"})`);
});

// Mode switching
document.querySelectorAll(".seg-btn[data-mode]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const nextMode = btn.dataset.mode;
    if (!nextMode || nextMode === state.mode) return;
    state.mode = nextMode;
    document.querySelectorAll(".seg-btn[data-mode]").forEach((b) => {
      const active = b.dataset.mode === nextMode;
      b.classList.toggle("active", active);
      b.setAttribute("aria-checked", String(active));
    });
    processCurrentData();
    recordAudit("MODE_SWITCH", `Switched mode to ${nextMode}`);
  });
});

// Entity filter cards
document.querySelectorAll(".metric-card[data-filter]").forEach((card) => {
  card.addEventListener("click", () => {
    const filter = card.dataset.filter;
    state.activeFilter = state.activeFilter === filter && filter !== "ALL" ? "ALL" : filter;
    document.querySelectorAll(".metric-card[data-filter]").forEach((c) => {
      c.classList.toggle("active-filter", c.dataset.filter === state.activeFilter);
    });
    renderDashboard();
  });
});

// Left pane edit/highlight tabs & double-click shortcut
els.tabEdit.addEventListener("click", () => {
  setLeftView("edit");
  els.rawInput.focus();
});

els.tabHighlight.addEventListener("click", () => {
  setLeftView("highlight");
});

els.originalHighlight.addEventListener("dblclick", () => {
  setLeftView("edit");
  els.rawInput.focus();
});

// Copy & Export buttons
els.btnCopy.addEventListener("click", async () => {
  const text = state.lastResult?.sanitizedText || "";
  if (!text) {
    showCopyFeedback("Nothing to copy");
    return;
  }
  const ok = await copyTextToClipboard(text);
  if (ok) {
    recordAudit("COPY", "Copied sanitized output to clipboard");
    showCopyFeedback("Copied ✓");
  } else {
    showCopyFeedback("Clipboard permission denied");
  }
});

els.btnDownloadTxt.addEventListener("click", () => {
  const text = state.lastResult?.sanitizedText || "";
  if (!text) {
    showCopyFeedback("Nothing to export");
    return;
  }
  const base = state.fileName ? state.fileName.replace(/\.[^.]+$/, "") : "privex-sanitized";
  downloadTextFile(text, `${base}-sanitized.txt`, "text/plain;charset=utf-8");
  recordAudit("EXPORT_TXT", "Downloaded sanitized .txt locally");
  showCopyFeedback("TXT downloaded ✓");
});

els.btnDownloadCsv.addEventListener("click", () => {
  const csvOut = buildSanitizedCsvForExport();
  if (!csvOut) {
    showCopyFeedback("Nothing to export");
    return;
  }
  const base = state.fileName ? state.fileName.replace(/\.[^.]+$/, "") : "privex-sanitized";
  downloadTextFile(csvOut, `${base}-sanitized.csv`, "text/csv;charset=utf-8");
  recordAudit("EXPORT_CSV", "Downloaded sanitized .csv locally");
  showCopyFeedback("CSV downloaded ✓");
});

// Audit log controls
els.btnClearAudit.addEventListener("click", () => {
  auditLogger.clear();
  renderAuditLog();
});

els.btnExportAudit.addEventListener("click", () => {
  downloadTextFile(auditLogger.toSafeJson(), "privex-audit-log.json", "application/json;charset=utf-8");
  showCopyFeedback("Audit JSON downloaded ✓");
});

// Test suite modal
els.btnTests.addEventListener("click", openTestModalAndRun);
els.btnRerunTests.addEventListener("click", openTestModalAndRun);
els.btnCloseTests.addEventListener("click", () => {
  els.testModal.classList.add("hidden");
});
els.testModal.addEventListener("click", (e) => {
  if (e.target === els.testModal) {
    els.testModal.classList.add("hidden");
  }
});

// Initial boot: run self-tests silently to populate badge count and render empty dashboard
const bootReport = runTestSuite();
els.btnTests.textContent = `Tests: ${bootReport.passed}/${bootReport.total}`;
renderDashboard();
renderAuditLog();
