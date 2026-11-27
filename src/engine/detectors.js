/**
 * PII detection and deterministic overlap resolution engine.
 * All regular expressions use bounded quantifiers to avoid ReDoS backtracking.
 */

import {
  classifyIPv4Scope,
  detectCardNetwork,
  isValidIPv4,
  isValidLuhn,
  validateAadhaar,
  validatePan,
} from "./validators.js";

export const ENTITY_TYPES = Object.freeze({
  CREDIT_CARD: "CREDIT_CARD",
  EMAIL: "EMAIL",
  PAN: "PAN",
  IPV4: "IPV4",
  AADHAAR: "AADHAAR",
  PHONE: "PHONE",
});

export const ENTITY_META = Object.freeze({
  [ENTITY_TYPES.EMAIL]: {
    label: "Email",
    placeholderPrefix: "EMAIL",
    priority: 50,
    riskReason: "Direct personal identifier enabling phishing and account correlation.",
  },
  [ENTITY_TYPES.PHONE]: {
    label: "Phone",
    placeholderPrefix: "PHONE",
    priority: 10,
    riskReason: "Personal contact number exposed to spam, social engineering, or SIM-swap risks.",
  },
  [ENTITY_TYPES.IPV4]: {
    label: "IPv4",
    placeholderPrefix: "IPV4",
    priority: 30,
    riskReason: "Device/network address revealing infrastructure topology or user geolocation.",
  },
  [ENTITY_TYPES.PAN]: {
    label: "PAN",
    placeholderPrefix: "PAN",
    priority: 45,
    riskReason: "Indian Permanent Account Number tied to tax records, KYC, and financial identity.",
  },
  [ENTITY_TYPES.AADHAAR]: {
    label: "Aadhaar",
    placeholderPrefix: "AADHAAR",
    priority: 25,
    riskReason: "Indian 12-digit national identity number with high KYC and identity-theft impact.",
  },
  [ENTITY_TYPES.CREDIT_CARD]: {
    label: "Credit Card",
    placeholderPrefix: "CARD",
    priority: 60,
    riskReason: "Luhn-validated payment card number carrying direct financial fraud risk.",
  },
});

// ReDoS-safe bounded patterns
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g;
const PAN_REGEX = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
const IPV4_REGEX = /(?<![A-Za-z0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![A-Za-z0-9.])/g;
const CREDIT_CARD_REGEX = /(?<![+A-Za-z0-9.])(\d(?:[ -]?\d){12,18})(?![A-Za-z0-9.])/g;
const AADHAAR_REGEX = /(?<![+A-Za-z0-9.]|\d[ -])([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?![A-Za-z0-9.]|[ -]\d)/g;

// Indian mobile (+91 / 91 / 0 + 10 digits starting 6-9), Indian landlines (0XX-XXXXXXXX), and E.164 international phones
const PHONE_REGEX =
  /(?<![A-Za-z0-9.])((?:\+91[\s-]?|91[\s-]|0)?[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{4}|(?:\+91[\s-]?|91[\s-]|0)?[6-9]\d{4}[\s-]?\d{5}|(?:\+91[\s-]?|0)\d{2,4}[\s-]\d{6,8}|\+[1-9]\d{0,2}[\s.-]\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,4})(?![A-Za-z0-9.])/g;

/**
 * Normalizes a matched entity for consistent pseudonymization across formatting variations.
 * @param {string} type
 * @param {string} raw
 * @returns {string}
 */
export function normalizeEntity(type, raw) {
  switch (type) {
    case ENTITY_TYPES.EMAIL:
      return raw.trim().toLowerCase();
    case ENTITY_TYPES.PAN:
      return raw.trim().toUpperCase();
    case ENTITY_TYPES.AADHAAR:
    case ENTITY_TYPES.CREDIT_CARD:
      return raw.replace(/\D/g, "");
    case ENTITY_TYPES.IPV4:
      return raw.trim();
    case ENTITY_TYPES.PHONE: {
      const digits = raw.replace(/\D/g, "");
      if (digits.length === 10 && /^[6-9]/.test(digits)) return `+91${digits}`;
      if (digits.length === 11 && digits.startsWith("0") && /^[6-9]/.test(digits.slice(1))) {
        return `+91${digits.slice(1)}`;
      }
      if (digits.length === 12 && digits.startsWith("91") && /^[6-9]/.test(digits.slice(2))) {
        return `+91${digits.slice(2)}`;
      }
      return `+${digits}`;
    }
    default:
      return raw.trim();
  }
}

/**
 * Runs all PII detectors and resolves overlapping candidates deterministically.
 * @param {string} text
 * @returns {{ detections: Array<object>, luhnRejected: Array<object> }}
 */
export function detectPII(text) {
  if (!text) {
    return { detections: [], luhnRejected: [] };
  }

  const candidates = [];
  const luhnRejected = [];

  // 1. Credit Cards (mandatory Luhn check)
  for (const match of text.matchAll(CREDIT_CARD_REGEX)) {
    const raw = match[1];
    const start = match.index;
    const end = start + raw.length;
    const digits = raw.replace(/\D/g, "");
    if (isValidLuhn(digits)) {
      const network = detectCardNetwork(digits);
      candidates.push({
        type: ENTITY_TYPES.CREDIT_CARD,
        start,
        end,
        raw,
        normalized: normalizeEntity(ENTITY_TYPES.CREDIT_CARD, raw),
        priority: ENTITY_META.CREDIT_CARD.priority,
        validation: `Luhn Valid (${network})`,
        riskReason: ENTITY_META.CREDIT_CARD.riskReason,
      });
    } else {
      luhnRejected.push({
        start,
        end,
        digitsLength: digits.length,
        reason: "Failed Luhn mod-10 checksum",
      });
    }
  }

  // 2. Email
  for (const match of text.matchAll(EMAIL_REGEX)) {
    const raw = match[0];
    const start = match.index;
    candidates.push({
      type: ENTITY_TYPES.EMAIL,
      start,
      end: start + raw.length,
      raw,
      normalized: normalizeEntity(ENTITY_TYPES.EMAIL, raw),
      priority: ENTITY_META.EMAIL.priority,
      validation: "RFC-5322 Syntax Match",
      riskReason: ENTITY_META.EMAIL.riskReason,
    });
  }

  // 3. Indian PAN
  for (const match of text.matchAll(PAN_REGEX)) {
    const raw = match[0];
    const start = match.index;
    const check = validatePan(raw);
    if (check.valid) {
      candidates.push({
        type: ENTITY_TYPES.PAN,
        start,
        end: start + raw.length,
        raw,
        normalized: normalizeEntity(ENTITY_TYPES.PAN, raw),
        priority: ENTITY_META.PAN.priority,
        validation: `Valid Structure (${check.holderType})`,
        riskReason: ENTITY_META.PAN.riskReason,
      });
    }
  }

  // 4. IPv4
  for (const match of text.matchAll(IPV4_REGEX)) {
    const raw = match[1];
    const start = match.index;
    // Skip software version prefixes such as v1.2.3.4
    if (start > 0 && /[vV]/.test(text[start - 1])) continue;
    if (isValidIPv4(raw)) {
      candidates.push({
        type: ENTITY_TYPES.IPV4,
        start,
        end: start + raw.length,
        raw,
        normalized: normalizeEntity(ENTITY_TYPES.IPV4, raw),
        priority: ENTITY_META.IPV4.priority,
        validation: classifyIPv4Scope(raw),
        riskReason: ENTITY_META.IPV4.riskReason,
      });
    }
  }

  // 5. Indian Aadhaar
  for (const match of text.matchAll(AADHAAR_REGEX)) {
    const raw = match[1];
    const start = match.index;
    const end = start + raw.length;
    if (luhnRejected.some((rej) => start < rej.end && end > rej.start)) continue;
    const check = validateAadhaar(raw);
    if (check.validFormat) {
      candidates.push({
        type: ENTITY_TYPES.AADHAAR,
        start,
        end,
        raw,
        normalized: normalizeEntity(ENTITY_TYPES.AADHAAR, raw),
        priority: ENTITY_META.AADHAAR.priority,
        validation: check.verhoeffValid
          ? "12-Digit Format + Verhoeff Valid"
          : "12-Digit Aadhaar Pattern",
        riskReason: ENTITY_META.AADHAAR.riskReason,
      });
    }
  }

  // 6. Phone Numbers
  for (const match of text.matchAll(PHONE_REGEX)) {
    const raw = match[1];
    const start = match.index;
    const end = start + raw.length;
    if (luhnRejected.some((rej) => start < rej.end && end > rej.start)) continue;
    const digits = raw.replace(/\D/g, "");
    if (digits.length < 10 || digits.length > 15) continue;
    candidates.push({
      type: ENTITY_TYPES.PHONE,
      start,
      end,
      raw,
      normalized: normalizeEntity(ENTITY_TYPES.PHONE, raw),
      priority: ENTITY_META.PHONE.priority,
      validation: raw.trim().startsWith("+91") || digits.length === 10 ? "Indian Phone Format" : "Phone Format",
      riskReason: ENTITY_META.PHONE.riskReason,
    });
  }

  // Deterministic overlap resolution:
  // Rank by priority DESC, then span length DESC, then start ASC.
  const ranked = [...candidates].sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted = [];
  for (const candidate of ranked) {
    const overlaps = accepted.some(
      (existing) => candidate.start < existing.end && candidate.end > existing.start
    );
    if (!overlaps) {
      accepted.push(candidate);
    }
  }

  accepted.sort((a, b) => a.start - b.start);

  // Filter out luhnRejected spans that fall inside an accepted non-card entity (e.g. a phone/Aadhaar)
  const trueLuhnRejected = luhnRejected.filter(
    (rej) => !accepted.some((acc) => rej.start < acc.end && rej.end > acc.start)
  );

  return { detections: accepted, luhnRejected: trueLuhnRejected };
}
