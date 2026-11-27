/**
 * RFC-4180 compliant client-side CSV parser, serializer, and document sanitizer.
 * Shares a single PseudonymRegistry across all cells and rows of a CSV document.
 */

import { createEmptyCounts, PseudonymRegistry, redactText } from "../engine/redactor.js";

/**
 * Parses a CSV string into a 2D array of strings.
 * Supports quoted fields, commas inside quotes, escaped quotes (""), and embedded newlines.
 * @param {string} input
 * @returns {string[][]}
 */
export function parseCsv(input) {
  if (!input) return [];
  const text = input.replace(/^\uFEFF/, ""); // strip UTF-8 BOM if present
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\r") {
      if (text[i + 1] === "\n") i += 1;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += ch;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

/**
 * Escapes and quotes a single CSV cell if needed.
 * Optionally neutralizes spreadsheet formula injection prefixes (=, @, tab, CR) on export.
 * @param {string} value
 * @param {{ neutralizeFormulas?: boolean }} [options]
 * @returns {string}
 */
export function formatCsvCell(value, options = {}) {
  let cell = value == null ? "" : String(value);
  if (options.neutralizeFormulas && /^[=@\t\r]/.test(cell)) {
    cell = `'${cell}`;
  }
  if (/[",\r\n]/.test(cell)) {
    return `"${cell.replace(/"/g, '""')}"`;
  }
  return cell;
}

/**
 * Serializes a 2D array of strings into an RFC-4180 CSV string.
 * @param {string[][]} rows
 * @param {{ neutralizeFormulas?: boolean }} [options]
 * @returns {string}
 */
export function serializeCsv(rows, options = {}) {
  return rows
    .map((row) => row.map((cell) => formatCsvCell(cell, options)).join(","))
    .join("\r\n");
}

/**
 * Converts a plain cell segment list into CSV-quoted segment list so highlighted diffs
 * remain properly escaped when rendered as CSV text.
 * @param {Array<object>} segments
 * @param {string} fullCellValue
 * @returns {Array<object>}
 */
function quoteSegmentsForCsvDisplay(segments, fullCellValue) {
  const needsQuotes = /[",\r\n]/.test(fullCellValue);
  if (!needsQuotes) return segments;
  const quoted = [{ kind: "plain", text: '"' }];
  for (const seg of segments) {
    quoted.push({
      ...seg,
      text: seg.text.replace(/"/g, '""'),
    });
  }
  quoted.push({ kind: "plain", text: '"' });
  return quoted;
}

/**
 * Sanitizes an entire CSV document cell-by-cell using one shared PseudonymRegistry.
 * @param {string} csvText
 * @param {string} mode
 * @param {{ neutralizeFormulas?: boolean }} [options]
 */
export function sanitizeCsvDocument(csvText, mode, options = {}) {
  const rowsOriginal = parseCsv(csvText);
  const registry = new PseudonymRegistry();

  const rowsSanitized = [];
  const originalSegments = [];
  const sanitizedSegments = [];
  const allDetections = [];
  const allLuhnRejected = [];
  const counts = createEmptyCounts();

  rowsOriginal.forEach((row, rowIndex) => {
    const sanitizedRow = [];
    row.forEach((cell, colIndex) => {
      const result = redactText(cell, mode, registry);
      sanitizedRow.push(result.sanitizedText);

      counts.total += result.counts.total;
      for (const [type, count] of Object.entries(result.counts.byType)) {
        counts.byType[type] += count;
      }
      for (const det of result.detections) {
        allDetections.push({ ...det, row: rowIndex + 1, col: colIndex + 1 });
      }
      for (const rej of result.luhnRejected) {
        allLuhnRejected.push({ ...rej, row: rowIndex + 1, col: colIndex + 1 });
      }

      if (colIndex > 0) {
        originalSegments.push({ kind: "plain", text: "," });
        sanitizedSegments.push({ kind: "plain", text: "," });
      }
      originalSegments.push(...quoteSegmentsForCsvDisplay(result.originalSegments, cell));
      sanitizedSegments.push(
        ...quoteSegmentsForCsvDisplay(result.sanitizedSegments, result.sanitizedText)
      );
    });

    rowsSanitized.push(sanitizedRow);
    if (rowIndex < rowsOriginal.length - 1) {
      originalSegments.push({ kind: "plain", text: "\n" });
      sanitizedSegments.push({ kind: "plain", text: "\n" });
    }
  });

  const sanitizedCsvText = serializeCsv(rowsSanitized, {
    neutralizeFormulas: options.neutralizeFormulas ?? true,
  });

  return {
    sanitizedText: sanitizedCsvText,
    rowsOriginal,
    rowsSanitized,
    originalSegments,
    sanitizedSegments,
    detections: allDetections,
    luhnRejected: allLuhnRejected,
    counts,
    uniqueCount: registry.uniqueCount,
    uniquePseudonyms: registry.size,
    rowCount: rowsOriginal.length,
    colCount: rowsOriginal.reduce((max, r) => Math.max(max, r.length), 0),
  };
}
