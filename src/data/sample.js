/**
 * Realistic noisy sample payload for 1-click judge demonstrations.
 * Covers all 6 mandatory PII types, repeated entities for pseudonymization,
 * valid Luhn credit card, and decoy numbers/IPs to verify false-positive rejection.
 */

export const NOISY_SAMPLE_TEXT = `[TICKET #INC-4821] Escalation from priya.sharma@finbank.in (backup: priya.sharma@finbank.in)
Assigned analyst: rahul.verma@acme-corp.co.in | Audit CC: priya.sharma@finbank.in
Client Primary Mobile: +91 98765 43210 | Alternate Callback: +91-9876543210
Secondary Branch Desk: 9820112233 | International Support: +1-415-555-0198
Gateway Telemetry: Login from 192.168.14.22 -> Proxy 10.42.8.199 (App Build v2.4.999.12 ignored)
Decoy Invalid IP: 999.300.12.1 (must NOT be detected as IPv4)

--- KYC & Billing Snapshot ---
Taxpayer PAN (Primary): ABCDE1234F
Taxpayer PAN (Verified Repeat): ABCDE1234F | Co-Applicant PAN: BKZPM8472K
Aadhaar Reference: 4532 8910 2345 (re-entered without spaces as 4532-8910-2345)
Verified Payment Card (Visa, Luhn Valid): 4532 0158 7621 9046
Decoy Order Reference (16 digits, Luhn INVALID): 4532 0158 7621 9047
Decoy Shipment Tracking (16 digits, Luhn INVALID): 9988 7766 5544 3321
End of log — notify rahul.verma@acme-corp.co.in once sanitized.`;
