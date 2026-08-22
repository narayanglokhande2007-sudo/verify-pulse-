# VerifyPulse

> **AI-assisted scam-risk checks for suspicious links, messages, and emails in India.**

[Live site](https://www.verify-pulse.com/) · [API documentation](https://www.verify-pulse.com/docs.html) · [Trust Center](https://www.verify-pulse.com/trust.html) · [Service status](https://www.verify-pulse.com/status.html) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

VerifyPulse is an India-focused cybersecurity project that helps people pause before acting on suspicious digital content. It combines scam-risk signals, historical reputation checks, provider-resilient AI analysis, and human-readable safety guidance to support safer decisions around suspicious URLs, messages, and emails.

## Why it exists

Online fraud commonly uses urgency, impersonation, fake KYC updates, malicious links, and requests for money or credentials. VerifyPulse is being built to help users recognise warning signs and take safer next steps before sharing sensitive information or making a payment.

> VerifyPulse provides **risk guidance**, not a guarantee that every result is correct. It is not a substitute for a bank, a regulated financial institution, law enforcement, or emergency reporting channels.

## What VerifyPulse does

| Area | Current approach |
|---|---|
| Scam-risk checks | Analyses suspicious links, text, and supported message-like inputs for scam-risk signals. |
| Evidence layers | Uses URL and message forensics, trusted-domain checks, historical reputation data, and other available signals. |
| Resilient responses | Uses provider fallback and bounded degraded responses so an upstream AI-provider failure does not become a misleading safe result. |
| Privacy controls | Redacts common sensitive values before external AI analysis where the privacy guard applies. |
| Safety guidance | Offers India-relevant guidance for common fraud patterns, including OTP/PIN safety, UPI fraud, phishing, bank impersonation calls, and cyber reporting. |
| Operational transparency | Publishes public status information, a vulnerability-reporting contact, and controlled-pilot risk documentation. |

## Public resources

| Resource | Purpose |
|---|---|
| [Live scanner](https://www.verify-pulse.com/) | Check a suspicious link or message for available risk signals. |
| [Business and pilot information](https://www.verify-pulse.com/enterprise.html) | Understand the controlled-pilot scope for organisations. |
| [API documentation](https://www.verify-pulse.com/docs.html) | Review the current B2B API boundary and integration information. |
| [Trust Center](https://www.verify-pulse.com/trust.html) | Review how VerifyPulse works and its limitations. |
| [Risk Management](https://www.verify-pulse.com/risk-management.html) | Review evidence layers, degraded responses, and responsible-use boundaries. |
| [Service Status](https://www.verify-pulse.com/status.html) | View public service and published-data metadata checks. |
| [Security contact](https://www.verify-pulse.com/.well-known/security.txt) | Report a potential security vulnerability responsibly. |

## Repository guide

| Location | What a visitor will find |
|---|---|
| [`api/`](api/) | Public serverless request routes, including the verification endpoint. |
| [`lib/`](lib/) | Shared privacy, evidence, risk-control, and reliability components. |
| [`tests/`](tests/) | Automated checks for key safety, reliability, and public-UI behaviour. |
| [`docs/`](docs/) | Technical, privacy, pilot, and operational-boundary documentation. |
| [`pipeline/`](pipeline/) | Published-data processing and controlled quality/integrity utilities. |
| [Security policy](SECURITY.md) | Private reporting route and safe research boundaries. |
| [Contributing guide](CONTRIBUTING.md) | How to give responsible feedback or propose a small change. |

This repository is intended to show the real project structure and documented boundaries. It is not a collection of SEO articles, and it does not publish private benchmark data, provider credentials, user submissions, or malicious files.

## High-level flow

```text
Suspicious input
      ↓
Input controls and sensitive-data minimisation
      ↓
Evidence checks: URL/message signals + historical reputation when available
      ↓
Provider-resilient AI analysis and bounded fallbacks
      ↓
Risk result, explanation, and safer next-step guidance
```

The system is designed to be helpful when evidence is strong and honest when evidence is limited. It does not claim to detect every scam, predict future fraud, or replace independent security controls.

## Local development and verification

**Requirements:** Node.js 18 or later.

```bash
git clone https://github.com/narayanglokhande2007-sudo/verify-pulse-.git
cd verify-pulse-
npm ci --ignore-scripts
npm test
```

The test suite covers core verdict behavior, URL and intent forensics, decision calibration, B2B controls, threat intelligence, historical reputation, request budgets, privacy/input controls, PulseCore resilience, public trust pages, service status, and scan reliability.

## Security and responsible disclosure

Please do **not** publish security vulnerabilities in a public issue. Read the repository [Security Policy](SECURITY.md) and use the contact details in [security.txt](https://www.verify-pulse.com/.well-known/security.txt). The current [security operations and incident-response runbook](docs/SECURITY_OPERATIONS_AND_INCIDENT_RESPONSE.md) and [data-handling baseline](docs/DATA_HANDLING_AND_RETENTION_BASELINE.md) explain the controlled-pilot approach.

## Contributing

Thoughtful, responsible feedback is welcome. Read the full [Contributing guide](CONTRIBUTING.md) before proposing a change. The main principles are:

1. Do not weaken privacy controls, input validation, rate controls, evidence boundaries, or fallback safety behavior.
2. Do not add claims of guaranteed scam detection, guaranteed accuracy, or financial-security certification without independently verifiable evidence.
3. Do not include private benchmark data, user inputs, secrets, API keys, or unreviewed suspicious samples in public contributions.
4. Prefer small, testable changes with a clear explanation of the user-safety benefit.

## Project status

VerifyPulse is actively maintained and intended for responsible public use and carefully scoped pilots. It is **not** presented as bank-scale production infrastructure, a certification, or a substitute for independent penetration testing and legal/privacy review.

## Founder

Built by [Narayan Lokhande](https://github.com/narayanglokhande2007-sudo), founder of VerifyPulse.

---

If you believe you are facing cyber fraud in India, do not share OTPs, PINs, passwords, card details, or remote-access permissions. Contact your bank through an official channel and use official reporting routes such as **1930** and [cybercrime.gov.in](https://cybercrime.gov.in/).
