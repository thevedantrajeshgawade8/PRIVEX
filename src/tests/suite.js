/**
 * Lightweight self-contained test suite for PRIVEX.
 * Runs entirely in browser memory (and works in standard JS runtimes for CI verification).
 */

import { detectPII, ENTITY_TYPES } from "../engine/detectors.js";
import { PseudonymRegistry, REDACTION_MODES, redactText } from "../engine/redactor.js";
import { assessPrivacyRisk } from "../engine/risk.js";
import { parseCsv, sanitizeCsvDocument, serializeCsv } from "../parsers/csv.js";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

const TEST_CASES = [
  {
    name: "Email detection",
    run() {
      const res = detectPII("Contact priya.sharma@finbank.in or ops@acme-corp.co.in");
      const emails = res.detections.filter((d) => d.type === ENTITY_TYPES.EMAIL);
      assert(emails.length === 2, `Expected 2 emails, got ${emails.length}`);
    },
  },
  {
    name: "Phone detection (Indian & international)",
    run() {
      const res = detectPII("Call +91 98765 43210, 9820112233, or +1-415-555-0198");
      const phones = res.detections.filter((d) => d.type === ENTITY_TYPES.PHONE);
      assert(phones.length === 3, `Expected 3 phones, got ${phones.length}`);
    },
  },
  {
    name: "IPv4 validation & invalid octet rejection",
    run() {
      const res = detectPII("Valid: 192.168.14.22 & 10.0.0.1 | Invalid: 999.300.12.1 | Ver: v2.4.1.9");
      const ips = res.detections.filter((d) => d.type === ENTITY_TYPES.IPV4);
      assert(ips.length === 2, `Expected 2 valid IPv4s, got ${ips.length}`);
      assert(ips[0].raw === "192.168.14.22", `Unexpected IP[0]: ${ips[0]?.raw}`);
    },
  },
  {
    name: "Indian PAN detection",
    run() {
      const res = detectPII("Primary PAN: ABCDE1234F, Secondary: BKZPM8472K");
      const pans = res.detections.filter((d) => d.type === ENTITY_TYPES.PAN);
      assert(pans.length === 2, `Expected 2 PANs, got ${pans.length}`);
    },
  },
  {
    name: "Indian Aadhaar detection",
    run() {
      const res = detectPII("Aadhaar: 4532 8910 2345 and 4532-8910-2345");
      const aadhaars = res.detections.filter((d) => d.type === ENTITY_TYPES.AADHAAR);
      assert(aadhaars.length === 2, `Expected 2 Aadhaar matches, got ${aadhaars.length}`);
    },
  },
  {
    name: "Valid credit card detection (Luhn pass)",
    run() {
      const res = detectPII("Visa Card: 4532 0158 7621 9046");
      const cards = res.detections.filter((d) => d.type === ENTITY_TYPES.CREDIT_CARD);
      assert(cards.length === 1, `Expected 1 valid card, got ${cards.length}`);
      assert(res.luhnRejected.length === 0, "Expected 0 Luhn rejections");
    },
  },
  {
    name: "Invalid Luhn credit card rejection",
    run() {
      const res = detectPII("Decoy Order IDs: 4532 0158 7621 9047 and 9988 7766 5544 3321");
      const cards = res.detections.filter((d) => d.type === ENTITY_TYPES.CREDIT_CARD);
      assert(cards.length === 0, `Expected 0 valid cards, got ${cards.length}`);
      assert(res.luhnRejected.length === 2, `Expected 2 Luhn rejections, got ${res.luhnRejected.length}`);
    },
  },
  {
    name: "Full Mask redaction mode",
    run() {
      const out = redactText("Email priya@finbank.in PAN ABCDE1234F", REDACTION_MODES.FULL);
      assert(
        out.sanitizedText === "Email [REDACTED_EMAIL] PAN [REDACTED_PAN]",
        `Unexpected full mask: ${out.sanitizedText}`
      );
    },
  },
  {
    name: "Partial Mask redaction mode",
    run() {
      const out = redactText(
        "Card 4532 0158 7621 9046 Aadhaar 4532 8910 2345 Email priya@finbank.in",
        REDACTION_MODES.PARTIAL
      );
      assert(out.sanitizedText.includes("**** **** **** 9046"), "Missing masked card tail");
      assert(out.sanitizedText.includes("XXXX XXXX 2345"), "Missing masked Aadhaar tail");
      assert(out.sanitizedText.includes("pr***@finbank.in"), "Missing partial email mask");
    },
  },
  {
    name: "Consistent pseudonymization across text",
    run() {
      const sample =
        "Mail priya@finbank.in then rahul@acme.in then PRIYA@finbank.in | Phone +91 98765 43210 & +91-9876543210";
      const out = redactText(sample, REDACTION_MODES.PSEUDONYM, new PseudonymRegistry());
      assert(
        out.sanitizedText ===
          "Mail EMAIL_01 then EMAIL_02 then EMAIL_01 | Phone PHONE_01 & PHONE_01",
        `Pseudonym mismatch: ${out.sanitizedText}`
      );
    },
  },
  {
    name: "CSV pseudonym consistency across rows & cells",
    run() {
      const csv = [
        "name,email,pan,notes",
        '"Sharma, Priya",priya@finbank.in,ABCDE1234F,"Backup priya@finbank.in"',
        '"Verma, Rahul",rahul@acme.in,BKZPM8472K,"Escalate to priya@finbank.in"',
      ].join("\n");
      const res = sanitizeCsvDocument(csv, REDACTION_MODES.PSEUDONYM);
      assert(res.rowsSanitized[1][1] === "EMAIL_01", "Row 1 email should be EMAIL_01");
      assert(
        res.rowsSanitized[1][3] === "Backup EMAIL_01",
        `Row 1 note mismatch: ${res.rowsSanitized[1][3]}`
      );
      assert(res.rowsSanitized[2][1] === "EMAIL_02", "Row 2 email should be EMAIL_02");
      assert(
        res.rowsSanitized[2][3] === "Escalate to EMAIL_01",
        `Row 2 note should reuse EMAIL_01: ${res.rowsSanitized[2][3]}`
      );
    },
  },
  {
    name: "TXT export payload integrity",
    run() {
      const out = redactText("IP 10.0.0.1 PAN ABCDE1234F", REDACTION_MODES.PSEUDONYM);
      assert(!out.sanitizedText.includes("10.0.0.1"), "Sanitized TXT leaked IP");
      assert(!out.sanitizedText.includes("ABCDE1234F"), "Sanitized TXT leaked PAN");
      assert(out.sanitizedText === "IP IPV4_01 PAN PAN_01", "Unexpected TXT output");
    },
  },
  {
    name: "CSV export structure & escaped quotes preservation",
    run() {
      const csv = 'id,note\n1,"Said ""hello, world"" from 192.168.1.10"';
      const res = sanitizeCsvDocument(csv, REDACTION_MODES.FULL);
      const reparsed = parseCsv(res.sanitizedText);
      assert(reparsed.length === 2, `Expected 2 rows, got ${reparsed.length}`);
      assert(
        reparsed[1][1] === 'Said "hello, world" from [REDACTED_IPV4]',
        `Unexpected reparsed cell: ${reparsed[1][1]}`
      );
      const serialized = serializeCsv(reparsed);
      assert(serialized.includes('""hello, world""'), "Escaped quotes lost on serialize");
      const risk = assessPrivacyRisk(res.counts);
      assert(risk.level === "LOW", `Expected LOW risk for single IP, got ${risk.level}`);
    },
  },
  {
    name: "Normalized unique entity count across all redaction modes",
    run() {
      const sample =
        "priya@finbank.in PRIYA@finbank.in | +91 98765 43210 +91-9876543210 | 4532 8910 2345 | 4532-8910-2345";
      for (const mode of [REDACTION_MODES.FULL, REDACTION_MODES.PARTIAL, REDACTION_MODES.PSEUDONYM]) {
        const res = redactText(sample, mode, new PseudonymRegistry());
        assert(res.counts.total === 6, `Mode ${mode}: expected 6 total, got ${res.counts.total}`);
        assert(res.uniqueCount === 3, `Mode ${mode}: expected 3 unique, got ${res.uniqueCount}`);
      }
      const csv = "a,b\npriya@finbank.in,PRIYA@finbank.in\n4532 8910 2345,4532-8910-2345";
      const csvFull = sanitizeCsvDocument(csv, REDACTION_MODES.FULL);
      assert(csvFull.counts.total === 4, `CSV full expected 4 total, got ${csvFull.counts.total}`);
      assert(csvFull.uniqueCount === 2, `CSV full expected 2 unique, got ${csvFull.uniqueCount}`);
    },
  },
];

/**
 * Executes all built-in tests and returns summary statistics.
 */
export function runTestSuite() {
  const results = [];
  let passed = 0;

  for (const tc of TEST_CASES) {
    try {
      tc.run();
      passed += 1;
      results.push({ name: tc.name, passed: true, error: null });
    } catch (err) {
      results.push({
        name: tc.name,
        passed: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    total: TEST_CASES.length,
    passed,
    failed: TEST_CASES.length - passed,
    results,
  };
}
