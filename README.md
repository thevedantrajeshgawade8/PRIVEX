# PRIVEX
PRIVEX — Privacy Intelligence &amp; Redaction Engine is a zero-backend, browser-based privacy tool that detects sensitive information, validates findings, explains privacy risks, and securely redacts data — all locally in your browser. No data is uploaded or stored on a server. 🔒

## Key Capabilities
- **100% Client-Side Processing:** Zero backend, zero database, zero external APIs, and strict Content Security Policy (`connect-src 'none'`).
- **PII Detection & Validation:**
  - Email addresses
  - Indian & international phone numbers
  - IPv4 addresses (strict `0–255` octet validation)
  - Indian PAN numbers (`[A-Z]{5}[0-9]{4}[A-Z]` with entity type decoding)
  - Indian Aadhaar numbers (12-digit format + Verhoeff validation metadata)
  - Credit card numbers (**mandatory Luhn mod-10 validation** to block false positives)
- **Three Redaction Modes:** Full Mask, Partial Mask, and Consistent Pseudonymization (`EMAIL_01`, `PHONE_01`, `PAN_01`, `AADHAAR_01`, `CARD_01`, `IPV4_01`) consistent across full text and multi-row CSV documents.
- **Live Diff & Explainable Risk:** Side-by-side highlighted original/sanitized diff, entity counters, Luhn-rejected counter, and transparent point-based risk scoring (`LOW` / `MEDIUM` / `HIGH`).
- **TXT & CSV Workflows:** Upload `.txt`/`.csv`, sanitize cell-by-cell while preserving RFC-4180 CSV structure, copy output, and download sanitized `.txt` or `.csv`.
- **In-Memory Audit Log & Self-Test Suite:** Volatile session log (never storing raw PII) plus a built-in 13-test browser verification suite.

## Run Locally

Because ES6 modules require HTTP serving (not `file://`), start any static HTTP server from the repository root:

```bash
python -m http.server 8765 --bind 127.0.0.1
```

Then open `http://127.0.0.1:8765` in your browser.
