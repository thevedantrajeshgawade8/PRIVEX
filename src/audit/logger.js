/**
 * Strictly in-memory privacy audit logger.
 * Never persists to storage and never records raw unredacted PII values.
 */

const MAX_LOG_ENTRIES = 250;

export class AuditLogger {
  constructor() {
    this.entries = [];
    this.seq = 0;
  }

  /**
   * Appends a sanitized audit event containing only metadata and aggregate counts.
   * @param {{
   *   action: string,
   *   mode: string,
   *   fileType?: string,
   *   fileSizeBytes?: number,
   *   counts?: { total: number, byType: Record<string, number> },
   *   luhnRejectedCount?: number,
   *   riskLevel?: string,
   *   note?: string
   * }} event
   */
  log(event) {
    this.seq += 1;
    const entry = {
      id: this.seq,
      timestamp: new Date().toISOString(),
      action: String(event.action || "UNKNOWN"),
      mode: String(event.mode || "unknown"),
      fileType: event.fileType || "text",
      fileSizeBytes: Number.isFinite(event.fileSizeBytes) ? event.fileSizeBytes : 0,
      totalFindings: event.counts?.total ?? 0,
      entityCounts: event.counts?.byType ? { ...event.counts.byType } : {},
      luhnRejectedCount: event.luhnRejectedCount ?? 0,
      riskLevel: event.riskLevel || "LOW",
      note: event.note || "",
    };

    this.entries.unshift(entry);
    if (this.entries.length > MAX_LOG_ENTRIES) {
      this.entries.length = MAX_LOG_ENTRIES;
    }
    return entry;
  }

  getAll() {
    return [...this.entries];
  }

  clear() {
    this.entries = [];
  }

  /**
   * Produces a PII-free JSON string ready for local download.
   */
  toSafeJson() {
    return JSON.stringify(
      {
        tool: "PRIVEX — Privacy Intelligence & Redaction Engine",
        exportedAt: new Date().toISOString(),
        containsRawPII: false,
        entryCount: this.entries.length,
        entries: this.entries,
      },
      null,
      2
    );
  }
}
