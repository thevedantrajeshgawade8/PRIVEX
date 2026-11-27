/**
 * Redaction strategies and consistent session-scoped pseudonymization.
 */

import { detectPII, ENTITY_META, ENTITY_TYPES } from "./detectors.js";

export const REDACTION_MODES = Object.freeze({
  FULL: "full",
  PARTIAL: "partial",
  PSEUDONYM: "pseudonym",
});

/**
 * Volatile in-memory mapping ensuring identical normalized entities receive
 * identical placeholders across a document or multi-row CSV.
 */
export class PseudonymRegistry {
  constructor() {
    this.counters = new Map();
    this.mappings = new Map();
    this.seen = new Set();
  }

  /**
   * Builds the canonical key shared between unique-entity counting and pseudonym mapping.
   * @param {string} type
   * @param {string} normalized
   * @returns {string}
   */
  static makeKey(type, normalized) {
    return `${type}:${normalized}`;
  }

  /**
   * Records a normalized entity so unique counts remain accurate across all redaction modes.
   * @param {string} type
   * @param {string} normalized
   */
  track(type, normalized) {
    this.seen.add(PseudonymRegistry.makeKey(type, normalized));
  }

  /**
   * @param {string} type
   * @param {string} normalized
   * @returns {string}
   */
  getPlaceholder(type, normalized) {
    const key = PseudonymRegistry.makeKey(type, normalized);
    this.seen.add(key);
    if (this.mappings.has(key)) {
      return this.mappings.get(key);
    }
    const nextIndex = (this.counters.get(type) || 0) + 1;
    this.counters.set(type, nextIndex);
    const prefix = ENTITY_META[type]?.placeholderPrefix || type;
    const token = `${prefix}_${String(nextIndex).padStart(2, "0")}`;
    this.mappings.set(key, token);
    return token;
  }

  get uniqueCount() {
    return this.seen.size;
  }

  get size() {
    return this.mappings.size;
  }
}

/**
 * Formats a full mask replacement for an entity.
 * @param {object} entity
 * @returns {string}
 */
function applyFullMask(entity) {
  const prefix = ENTITY_META[entity.type]?.placeholderPrefix || entity.type;
  return `[REDACTED_${prefix}]`;
}

/**
 * Formats a partial mask preserving structural hints while hiding sensitive digits/characters.
 * @param {object} entity
 * @returns {string}
 */
function applyPartialMask(entity) {
  const { type, raw } = entity;
  switch (type) {
    case ENTITY_TYPES.EMAIL: {
      const atIdx = raw.indexOf("@");
      if (atIdx <= 0) return "[REDACTED_EMAIL]";
      const local = raw.slice(0, atIdx);
      const domain = raw.slice(atIdx + 1);
      const head = local.slice(0, local.length > 2 ? 2 : 1);
      return `${head}***@${domain}`;
    }
    case ENTITY_TYPES.PHONE: {
      const digits = raw.replace(/\D/g, "");
      const tail = digits.slice(-4);
      const hasPlus = raw.trim().startsWith("+");
      if (digits.length === 12 && digits.startsWith("91")) {
        return `+91 ******${tail}`;
      }
      if (hasPlus) {
        return `+** ******${tail}`;
      }
      return `${"*".repeat(Math.max(4, digits.length - 4))}${tail}`;
    }
    case ENTITY_TYPES.IPV4: {
      const parts = raw.split(".");
      if (parts.length !== 4) return "***.***.***.***";
      return `${parts[0]}.${parts[1]}.***.***`;
    }
    case ENTITY_TYPES.PAN: {
      const upper = raw.toUpperCase();
      return `${upper.slice(0, 2)}*******${upper.slice(-1)}`;
    }
    case ENTITY_TYPES.AADHAAR: {
      const digits = raw.replace(/\D/g, "");
      return `XXXX XXXX ${digits.slice(-4)}`;
    }
    case ENTITY_TYPES.CREDIT_CARD: {
      const digits = raw.replace(/\D/g, "");
      return `**** **** **** ${digits.slice(-4)}`;
    }
    default:
      return applyFullMask(entity);
  }
}

/**
 * Produces a single replacement string for a detected entity under the given mode.
 * @param {object} entity
 * @param {string} mode
 * @param {PseudonymRegistry} registry
 * @returns {string}
 */
export function formatReplacement(entity, mode, registry) {
  switch (mode) {
    case REDACTION_MODES.FULL:
      return applyFullMask(entity);
    case REDACTION_MODES.PARTIAL:
      return applyPartialMask(entity);
    case REDACTION_MODES.PSEUDONYM:
      return registry.getPlaceholder(entity.type, entity.normalized);
    default:
      return applyFullMask(entity);
  }
}

/**
 * Redacts a plain text string and returns segmented original/sanitized slices for safe DOM rendering.
 * @param {string} text
 * @param {string} mode
 * @param {PseudonymRegistry} [sharedRegistry]
 */
export function redactText(text, mode = REDACTION_MODES.PSEUDONYM, sharedRegistry = new PseudonymRegistry()) {
  const { detections, luhnRejected } = detectPII(text);

  const originalSegments = [];
  const sanitizedSegments = [];
  let sanitizedText = "";
  let cursor = 0;

  const counts = createEmptyCounts();

  for (const det of detections) {
    if (det.start > cursor) {
      const plain = text.slice(cursor, det.start);
      originalSegments.push({ kind: "plain", text: plain });
      sanitizedSegments.push({ kind: "plain", text: plain });
      sanitizedText += plain;
    }

    sharedRegistry.track(det.type, det.normalized);
    const replacement = formatReplacement(det, mode, sharedRegistry);
    counts.total += 1;
    counts.byType[det.type] += 1;

    originalSegments.push({
      kind: "entity",
      text: det.raw,
      type: det.type,
      validation: det.validation,
      riskReason: det.riskReason,
      replacement,
    });

    sanitizedSegments.push({
      kind: "redacted",
      text: replacement,
      type: det.type,
      validation: det.validation,
    });

    sanitizedText += replacement;
    cursor = det.end;
  }

  if (cursor < text.length) {
    const tail = text.slice(cursor);
    originalSegments.push({ kind: "plain", text: tail });
    sanitizedSegments.push({ kind: "plain", text: tail });
    sanitizedText += tail;
  }

  return {
    sanitizedText,
    originalSegments,
    sanitizedSegments,
    detections,
    luhnRejected,
    counts,
    uniqueCount: sharedRegistry.uniqueCount,
    uniquePseudonyms: sharedRegistry.size,
  };
}

/**
 * Creates a zeroed entity count structure.
 */
export function createEmptyCounts() {
  return {
    total: 0,
    byType: {
      [ENTITY_TYPES.EMAIL]: 0,
      [ENTITY_TYPES.PHONE]: 0,
      [ENTITY_TYPES.IPV4]: 0,
      [ENTITY_TYPES.PAN]: 0,
      [ENTITY_TYPES.AADHAAR]: 0,
      [ENTITY_TYPES.CREDIT_CARD]: 0,
    },
  };
}
