# VerifyPulse Security Operations and Incident Response Baseline

**Owner:** VerifyPulse founder / security contact: `narayanglokhande2007@gmail.com`
**Current coverage statement:** This is a founder-operated best-effort process. It is **not** a 24×7 SOC, a managed detection service, or a contractual response-time SLA.
**Last reviewed:** 2026-08-20

## Purpose and Scope

This runbook applies to the VerifyPulse public website, public verification API, B2B URL-scan API, hosted configuration, repository, scheduled threat-data refreshes, and approved external AI/data providers. It defines what must happen when there is suspected unauthorized access, secret exposure, malicious code change, data exposure, service abuse, a broken deployment, or a materially incorrect scam-risk result caused by a system failure.

> This document is an operating baseline, not a legal determination. A regulated client must review and adapt it to its own incident, data-protection, reporting, and contractual obligations before sharing customer data with VerifyPulse.

## Security Contact and Reporting

Report a suspected VerifyPulse security issue to **narayanglokhande2007@gmail.com** with the subject `VerifyPulse Security Report`. Do not include passwords, API keys, OTPs, PINs, bank credentials, card numbers, or customer personal data in the email. Send a short description, the affected page/API, approximate time in UTC if known, and a safe way to contact the reporter.

The public reporting file is available at `/.well-known/security.txt`. A future enterprise contract should define a named escalation contact, secure evidence-transfer method, and mutually agreed notification process.

## Severity Classification

| Severity | Example | First action |
|---|---|---|
| **SEV-1** | Suspected customer-data exposure, confirmed secret compromise, malicious production-code change, or active compromise | Stop the affected route/service if necessary; preserve evidence; rotate affected credentials; start incident record; notify impacted client contacts according to contract/law. |
| **SEV-2** | B2B API abuse, critical security control unavailable, false SAFE caused by implementation defect, or sustained service failure | Contain the affected feature, revoke/rotate relevant key, preserve correlation IDs/logs, publish accurate status, and investigate. |
| **SEV-3** | Stale threat data, degraded external providers, non-sensitive defect, or isolated user-impact issue | Mark the condition accurately, investigate root cause, and fix before claiming normal service. |
| **SEV-4** | Documentation, UI, or low-risk configuration issue without evidence of exposure | Create a tracked correction and include it in routine review. |

## First 60 Minutes

| Time window | Required action |
|---|---|
| **0–15 minutes** | Record discovery time in UTC, reporter, affected asset, suspected severity, visible symptoms, and the immediate containment decision. Do not copy customer secrets into the incident record. |
| **15–30 minutes** | Preserve correlation IDs, deployment ID/commit, relevant sanitized application logs, provider error codes, and status-page state. Determine whether the affected route should be disabled or limited. |
| **30–60 minutes** | Rotate exposed API/provider keys or disable affected B2B key records, check GitHub/Vercel deployment history, assess whether customer data or a client workflow may be affected, and send an initial factual update to the owner/client contact if contractually required. |

## Containment and Recovery Rules

1. **Secrets:** Revoke or rotate a potentially exposed secret before debugging with it. Do not paste secrets into tickets, commits, test fixtures, screenshots, or chat.
2. **B2B key suspicion:** Mark the relevant scoped registry record as `revoked`, deploy the update, create a replacement key through an approved secure channel, and record the key ID—not the raw key—in the incident record.
3. **Threat-data freshness failure:** Do not call the data healthy. Keep status as degraded, run the bounded refresh plus both freshness gates, and investigate the source health record before changing any threshold.
4. **External AI provider failure:** Preserve provider failure codes and correlation IDs. The scanner must retain the degraded/verification-needed boundary rather than issuing a false SAFE verdict.
5. **Code integrity failure:** Stop automatic deployment of the affected change, compare against the Watchman manifest, use only hash-verified trusted local recovery sources, and perform human review before restoration.
6. **Customer-data concern:** Stop sending further similar data to external providers until the input/data flow is reviewed. Notify the client using the agreed contract path; obtain legal/privacy advice when required.

## Evidence and Logging Standard

The application currently emits privacy-safe B2B and reliability events with correlation IDs and does not intentionally log raw scan content, URLs, API keys, IP addresses, contact data, credentials, or personal identifiers in those events. This is helpful but is **not yet sufficient** for a regulated production customer: a central, access-controlled, time-synchronized log store with an agreed retention policy and alerting must be implemented before a bank-scale launch.

Every production incident record should contain the incident ID, UTC timeline, affected components, affected key/tenant IDs if applicable, correlation IDs, safe error codes, deployment/commit ID, containment actions, customer communication, root cause, corrective action, owner, and closure date. Raw customer content should be referenced only through the client’s approved case system, not copied into VerifyPulse incident notes.

## CERT-In and Client Reporting Boundary

CERT-In directions require entities in scope to report listed cyber incidents within six hours of noticing/becoming aware, designate a point of contact, synchronize ICT clocks, and retain logs securely for a rolling 180 days within India. VerifyPulse’s current code and hosted environment do **not** by themselves prove full compliance with those requirements. A production financial-client deployment must obtain legal/compliance review, establish the appropriate reporting responsibility, maintain the required log evidence, and agree who communicates with the client and authorities. [1]

## Operational Review Cadence

| Cadence | Minimum review |
|---|---|
| Daily automated | Bounded feed refresh, threat snapshot freshness gate, historical-index health gate, and source-health output. |
| Weekly | Review failed source counts, status history, provider error types, unexpected B2B authorization failures, and dependency/security alerts. |
| Monthly | Review active B2B keys, expiry/revocation, allowed origins, access to deployment/repository, dependency audit, and open security findings. |
| Quarterly | Run an incident tabletop exercise, test recovery steps, review third-party provider/data inventory, and update client-facing security documentation. |
| Before production client onboarding | Confirm data-flow, approved inputs, scoped key, shared rate limiting, log/retention controls, incident contacts, privacy terms, and contract requirements. |

## References

[1]: https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf "CERT-In Directions under section 70B of the Information Technology Act, 2000"
