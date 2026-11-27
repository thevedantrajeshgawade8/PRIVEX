/**
 * Pure validation helpers for PRIVEX PII detection.
 * All validation runs locally in memory with zero external calls.
 */

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const PAN_HOLDER_TYPES = {
  P: "Individual",
  C: "Company",
  H: "HUF",
  F: "Firm / LLP",
  A: "AOP",
  T: "Trust",
  B: "BOI",
  L: "Local Authority",
  J: "Artificial Juridical Person",
  G: "Government",
};

/**
 * Validates a 13-19 digit payment card number using the Luhn mod-10 algorithm.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidLuhn(raw) {
  const digits = String(raw).replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Infers payment card network from IIN prefix for explainability.
 * @param {string} digits
 * @returns {string}
 */
export function detectCardNetwork(digits) {
  if (/^4\d{12}(\d{3}|\d{6})?$/.test(digits)) return "Visa";
  if (/^(5[1-5]\d{14}|2(2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})$/.test(digits)) return "Mastercard";
  if (/^3[47]\d{13}$/.test(digits)) return "American Express";
  if (/^(60|65|81|82|508)\d+$/.test(digits)) return "RuPay / Discover";
  return "Payment Card";
}

/**
 * Validates an IPv4 dotted-quad string ensuring every octet is 0..255 without invalid leading zeros.
 * @param {string} ip
 * @returns {boolean}
 */
export function isValidIPv4(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return false;
    const num = Number(part);
    if (num < 0 || num > 255) return false;
  }
  return true;
}

/**
 * Classifies IPv4 scope (private/loopback/public) for risk explanation.
 * @param {string} ip
 * @returns {string}
 */
export function classifyIPv4Scope(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return "Private RFC1918 IPv4";
  }
  if (a === 127) return "Loopback IPv4";
  return "Public IPv4";
}

/**
 * Validates Indian PAN format and decodes the 4th-character taxpayer entity type.
 * @param {string} pan
 * @returns {{ valid: boolean, holderType: string }}
 */
export function validatePan(pan) {
  const upper = String(pan).toUpperCase();
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(upper)) {
    return { valid: false, holderType: "Unknown" };
  }
  const holderType = PAN_HOLDER_TYPES[upper[3]] || "Other Entity";
  return { valid: true, holderType };
}

/**
 * Computes Verhoeff checksum validity on a 12-digit Aadhaar number.
 * Note: Synthetic test Aadhaar numbers may match 12-digit rules without passing Verhoeff.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidVerhoeff(raw) {
  const digits = String(raw).replace(/\D/g, "");
  if (digits.length !== 12) return false;
  let c = 0;
  for (let i = 0; i < digits.length; i += 1) {
    const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

/**
 * Validates a 12-digit Indian Aadhaar candidate (starts 2-9, not all identical digits).
 * @param {string} raw
 * @returns {{ validFormat: boolean, verhoeffValid: boolean }}
 */
export function validateAadhaar(raw) {
  const digits = String(raw).replace(/\D/g, "");
  const validFormat = /^[2-9]\d{11}$/.test(digits) && !/^(\d)\1{11}$/.test(digits);
  if (!validFormat) return { validFormat: false, verhoeffValid: false };
  return { validFormat: true, verhoeffValid: isValidVerhoeff(digits) };
}
