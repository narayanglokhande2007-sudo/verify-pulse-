# VerifyPulse Vendor and Data-Flow Register

> **Status:** Draft operational register — verify contract terms, processing locations, and current service configuration before customer representation.
>
> **Purpose:** Support bank/fintech vendor due diligence without claiming certifications or contractual protections that have not been independently confirmed.

## 1. Operating rule

A provider may be enabled only when its purpose, configured data category, secret owner, fallback behaviour, incident-contact path, and contractual/privacy review state are recorded here. This register contains no secrets.

## 2. Current service inventory

| Service / provider | Product purpose | Intended data handling | Fallback / resilience | Pre-pilot owner check |
|---|---|---|---|---|
| Vercel | Public web/API hosting and deployment | Application request/response handling under hosting configuration; do not intentionally add raw scan logging. | Roll back to verified deployment; dual domains must be smoke-tested. | Confirm project access, MFA, deployment-log retention, incident contact, and data-processing terms. |
| GitHub | Source control, CI, integrity baselines, daily data commits | Source code, synthetic tests, public threat indicators; no raw customer scans or secrets in repository. | Local trusted clone and immutable verified commit enable recovery. | Confirm organisation access, MFA, branch protection, secret scanning, and incident process. |
| Google Gemini | Configured analysis provider | Only privacy-guarded eligible analysis text may be submitted. | Groq, Anthropic, OpenRouter, then `NEEDS_VERIFICATION`. | Confirm API key ownership, terms, data-use settings, location/retention implications, and incident contact. |
| Groq | Configured fallback analysis provider | Only privacy-guarded eligible analysis text may be submitted. | Other provider routes and local safeguards. | Same review as above. |
| Anthropic | Configured secondary analysis provider | Only privacy-guarded eligible analysis text may be submitted. | Other provider routes and local safeguards. | Same review as above. |
| OpenRouter | Configured secondary analysis routing provider | Only privacy-guarded eligible analysis text may be submitted. | Other provider routes and local safeguards. | Confirm downstream model-routing/data-handling configuration before enterprise use. |
| Google Safe Browsing | URL-reputation evidence when configured | URL reputation check only; no OTP/password/bank value. | Local URL forensics and threat intelligence remain available. | Confirm API key restriction and acceptable-use configuration. |
| URLhaus / OpenPhish | Public threat-indicator feeds | Public threat URLs/indicators only; bounded fetch and expiry metadata. | Existing unexpired snapshot; no raw victim input is fed back. | Confirm feed terms, availability, attribution needs, and refresh monitoring. |

## 3. Required per-vendor review fields

Before an enterprise pilot, the owner must complete the following for each enabled provider:

| Field | Required evidence |
|---|---|
| Business owner | Named person accountable for access and renewal. |
| Data classification | Exact categories that may be sent; explicit prohibited categories. |
| Purpose and necessity | Why the provider is required and approved fallback. |
| Contract / DPA / terms | Link or internal reference, review date, and renewal date. |
| Data location and retention | Provider-confirmed setting or documented uncertainty. Never assume. |
| Security controls | MFA, least privilege, secret storage, role ownership, audit-log access. |
| Incident contact | Support/security contact and escalation path. |
| Offboarding | Key revocation, data deletion request where applicable, and configuration removal. |

## 4. Mandatory provider-risk controls

1. Store secrets only in deployment/environment secret controls or an approved password manager; never in source code, client JavaScript, URLs, screenshots, or issue trackers.
2. Use unique credentials per provider and rotate immediately after suspected exposure.
3. Preserve local deterministic decision safeguards; an external provider must not be the sole control preventing an unsafe `SAFE` verdict.
4. Reassess this register before enabling a new model/provider, storing new data, or signing an enterprise contract.
5. Do not claim data residency, encryption, SOC 2, ISO certification, DPA status, or breach-notification commitments unless the owner has reviewed documented provider evidence.

## 5. Evidence in the repository

```text
verify-pulse-/
├── api/verify.js                       ← bounded provider routing and degraded safe fallback
├── lib/privacy_guard.js                ← sensitive-value screening/redaction
├── lib/request_budget.js               ← request-wide latency budget
├── lib/threat_intelligence.js          ← bounded public-indicator lookups
└── docs/
    ├── PRIVACY_AND_RETENTION_STANDARD.md
    ├── INCIDENT_RESPONSE_AND_BCP_DR_RUNBOOK.md
    └── VENDOR_AND_DATA_FLOW_REGISTER.md
```
