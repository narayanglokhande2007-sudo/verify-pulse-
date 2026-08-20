# VerifyPulse Data Handling and Retention Baseline

**Status:** Product security baseline for a limited pilot; not a substitute for a client-specific data-processing agreement or legal advice.
**Last reviewed:** 2026-08-20
**Contact:** `narayanglokhande2007@gmail.com`

## Product Boundary

VerifyPulse is designed to assess suspicious URLs and scam-related text/messages. It is not designed to receive banking credentials, account balances, OTPs, PINs, passwords, CVVs, card numbers, full KYC documents, Aadhaar/PAN values, transaction records, or unnecessary personal information.

> **Client rule:** A financial client must minimize input before sending it to VerifyPulse. The client remains responsible for deciding whether it has a valid lawful basis, notice, consent, and contractual authority to send any customer information.

## Data Categories and Intended Handling

| Category | Intended use | Current technical handling | Retention boundary |
|---|---|---|---|
| Submitted suspicious URL | Risk analysis | Public scan logic and B2B URL-scan API may process the URL. Query strings/fragments are removed before external AI analysis by the privacy guard. | Do not intentionally store raw URL in B2B audit events. Client must confirm any upstream/browser/server log handling before pilot. |
| Submitted scam text/message | Public risk analysis | External-analysis sanitizer redacts recognised credentials, card-like numbers, Aadhaar-like values, emails, phone numbers, and URL query/fragment values before external analysis. | Do not intentionally log raw text in B2B/reliability event helpers. Raw-request retention is not a contractual guarantee and must be reviewed before production use. |
| B2B API key | Authentication | Key is received in a request header, hashed for comparison, and excluded from B2B audit events. | Never commit, screenshot, email, or log raw keys. Rotate/revoke through a secure client process. |
| B2B tenant/key identifier | Authorization/audit correlation | Safe identifier fields can appear in metadata-only audit events. | Needs central retention/access policy before regulated production use. |
| Correlation ID and safe error code | Incident investigation | Included in B2B/reliability metadata events. | Needs central retention/access policy before regulated production use. |
| Uploaded file | Optional analysis only | Existing backend requires explicit consent signal before external file analysis. | A production client must separately review file storage, external processing, and deletion before enabling file workflows. |

## Current Technical Safeguards

The current privacy guard redacts several high-risk patterns before external AI analysis. It removes labelled OTP/PIN/password values, payment-card-like values, Aadhaar-like values, email addresses, Indian phone numbers, and URL query strings/fragments. This is a risk-reduction control, **not proof that every possible personal-data pattern is detected or removed**.

The B2B audit-event helper is designed to exclude raw scan content, URL, API key, IP address, contact data, credentials, and personal identifiers. The current output is console-based metadata; a regulated deployment needs a central log system with access control and a client-approved retention schedule.

## Retention and Deletion Position

VerifyPulse does not claim “we never store any data” as a universal promise. Infrastructure, platform, browser, provider, or diagnostic layers can have their own logging behavior, and that must be reviewed before a financial client sends real customer information.

For a controlled pilot, the client and VerifyPulse should agree in writing on: the exact input fields; whether real customer content is allowed; allowed purposes; approved external providers; log destinations; retention duration; deletion/return process; access roles; breach notification; and support/escalation contacts. If those items cannot be agreed and evidenced, use test/synthetic inputs only.

## Data-Subject and Client Requests

Requests about personal-data handling, correction, deletion, or a suspected data exposure can be sent to `narayanglokhande2007@gmail.com` with the subject `VerifyPulse Data Request`. Do not include secrets or full sensitive content in the email. A production client should use its own approved security/contact route and should attach client-specific contractual instructions.

## External Providers and Subprocessors

The product can use public threat-data sources and external AI providers. The exact providers used for a scan can vary with availability and configured fallback logic. Before production onboarding, VerifyPulse must provide the client with the current provider/data-source inventory, processing purpose, data-location/transfer information where available, and any required contractual terms. This document does not certify a provider’s compliance status.

## Legal and Compliance Boundary

The Digital Personal Data Protection Act, 2023 requires lawful processing and imposes obligations including reasonable security safeguards, processor contracts, erasure when purpose ends unless retention is required by law, relevant breach intimation, a contact route, and grievance mechanism. Client-specific legal advice is required before a financial client processes real customer data through VerifyPulse. [1]

## Reference

[1]: https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf "Digital Personal Data Protection Act, 2023"
