# VerifyPulse Trust Center — Evidence-Based Content Plan

**Purpose:** Add public trust pages for prospective users and business clients without overstating VerifyPulse capabilities.

## Verified public claims permitted

| Claim | Evidence in current repository |
|---|---|
| VerifyPulse checks submitted links and messages using URL signals, intent signals, historical reputation, current threat-intelligence enrichment, and—when available—AI-assisted analysis. | `api/verify.js`, `lib/url_forensics.js`, `lib/intent_forensics.js`, `lib/historical_reputation.js`, `lib/threat_intelligence.js` |
| Historical reputation lookup is checked before AI analysis for matching URL/domain evidence. | `api/verify.js`, `lib/historical_reputation.js`, historical-index tests |
| A provider outage does not create a SAFE verdict merely because live model analysis is unavailable. | `api/verify.js`, scan-reliability and verdict-contract tests |
| File analysis needs an explicit consent signal before external file analysis begins. | `api/verify.js`, input-controls tests |
| Public scan input has type and size checks, plus a request budget/rate-control layer. | `api/verify.js`, `lib/security_controls.js`, input/request-budget tests |
| The B2B URL scan route uses API-key authentication, access scope checks, CORS allow-listing for browser callers, request correlation IDs, and metadata-only operational events. | `api/v1/scan.js`, `lib/security_controls.js`, `lib/audit_events.js`, B2B access-control tests |
| Important code/data files are integrity-checked against a manifest. | `pipeline/self_healing.py`, integrity monitor and manifest |

## Claims intentionally excluded because proof is absent or capability is paused

- No “100% accurate,” “99.9% accurate,” “military-grade,” “bank-grade,” “RBI-approved/certified,” or “Google-level” claims.
- No promise that every scam is detected or that result alone should block a payment.
- No autonomous live URL-opening/browser-sandbox claim; that feature is not in the live verification path.
- No device intelligence, transaction monitoring, full case management, external uptime SLA, independent penetration-test certification, or production 24/7 support claim.
- No absolute “we never store data” claim. Instead, state the actual documented metadata-only B2B audit behavior and tell users not to submit credentials or unnecessary personal data.
- No claim that external AI providers are continuously available.

## Planned public pages

| Page | Purpose | Dynamic dependency |
|---|---|---|
| `trust.html` | Security and data-practice summary, claim boundaries, known limits, contact route | None |
| `risk-management.html` | How evidence is combined, fail-safe/degraded response, human-review boundary, responsible use | None |
| `status.html` | Live application-status view with a transparent explanation of exactly what the page checks | `/api/status` |
| `pilot.html` | Controlled business-pilot scope, integration boundary, evidence expected before a paid rollout | None |

## Existing public-page corrections required for truthfulness

The legacy `enterprise.html` and `docs.html` pages contain unsupported claims and obsolete endpoint/schema descriptions. Their layouts and navigation will be preserved, but factual copy will be corrected to match the running service and the truthful trust-center pages.

## Navigation plan

- Main mobile About tab: add Trust Center, Risk Management, Status, and Business Pilot links.
- Enterprise and API documentation navigation: add Trust Center, Risk Management, Status, and Business Pilot links.
- Every new trust page: Home, Enterprise/API, Trust Center, Risk Management, Status, and Business Pilot links.
