# VerifyPulse Incident Response and BCP/DR Runbook

> **Status:** Draft operational runbook — founder/operations owner approval and a recorded drill are required before claiming tested enterprise readiness.
>
> **Recovery objective:** Restore the last verified production release within approximately **3 minutes** when the hosting platform rollback capability is available.

## 1. Scope

This runbook covers suspected compromise, exposed secret/API key, unauthorised source change, material service degradation, incorrect unsafe verdict behaviour, provider outage, and hosting/deployment failure affecting VerifyPulse.

## 2. Roles

| Role | Current assignment | Responsibility |
|---|---|---|
| Incident Commander | Founder / designated operations owner | Declares severity, coordinates containment, approves external communication. |
| Technical Lead | Founder or delegated maintainer | Investigates code/deployment, performs rollback, preserves evidence. |
| Security/Privacy Contact | Founder until delegated | Assesses data exposure, vendor notifications, and customer impact. |
| Customer Contact | Named per enterprise pilot | Receives agreed incident communications. |

One person may temporarily hold multiple roles for a solo-founder operation; all actions must still be timestamped in the incident record.

## 3. Severity and response target

| Severity | Example | Initial target | Immediate action |
|---|---|---:|---|
| SEV-1 | Confirmed secret exposure, unauthorised deployment, verified personal-data breach, systemic unsafe SAFE verdict | 15 minutes | Contain, revoke credentials, rollback/isolate, notify incident commander. |
| SEV-2 | B2B API unavailable, provider outage incorrectly handled, major detection regression, suspected compromise | 30 minutes | Fail safe to verification state where applicable, investigate, prepare rollback. |
| SEV-3 | Non-critical bug, isolated false-positive/false-negative report, documentation issue | 1 business day | Log, reproduce, add regression test, schedule fix. |

## 4. First 15-minute checklist

1. Record incident ID, time, reporter, affected domain/API, and observed symptom. Do **not** paste raw customer scans, credentials, or sensitive personal data into public tickets or chat.
2. Determine whether the issue affects `www.verify-pulse.com`, `verify-pulse.vercel.app`, B2B API, data pipeline, deployment credentials, or a third-party provider.
3. For suspected credential exposure, revoke/rotate the relevant GitHub, Vercel, provider, or B2B key immediately. Scoped B2B keys must be marked `revoked` or removed from the deployment registry.
4. For a production regression, compare the current deployment to the last verified `main` commit. Use Vercel rollback or redeploy the last verified Git commit after confirming its integrity manifest.
5. Preserve only privacy-safe evidence: deployment IDs, commit hashes, correlation IDs, error class, provider status, and timestamp.

## 5. Recovery procedure

### 5.1 Application/deployment regression

1. Pause further deployments.
2. Identify the last verified GitHub `main` commit and the corresponding Vercel deployment.
3. Verify the critical-file manifest on the trusted local copy.
4. Roll back using the Vercel deployment interface or redeploy the trusted commit.
5. Run the minimum verification set: verdict contract, scan reliability, B2B access-control suite, and one harmless live smoke test.
6. Confirm both production domains serve the same frontend/API behaviour.

### 5.2 Provider outage or upstream degradation

VerifyPulse must return the non-safe `NEEDS_VERIFICATION` state when all providers are unavailable. Do not disable local deterministic safeguards. Capture provider status metadata without logging raw scan content.

### 5.3 Suspected source-code tampering

1. Stop deployment activity and inspect `git status`, GitHub commit history, and integrity-manifest verification.
2. Do not execute untrusted scripts or download replacement files from unverified sources.
3. Use `pipeline/self_healing.py` only with a reviewed local trusted source matching the approved hash baseline.
4. Rotate affected access tokens/secrets before restoring service.

## 6. Communication and closure

For a confirmed enterprise-impacting incident, send the customer the agreed notification containing: incident time window, affected service, known impact, containment action, current status, and next update time. Do not speculate about root cause or disclose another customer’s data.

Close an incident only after the owner documents root cause, corrective actions, tests added, security/privacy implications, and whether a vendor or customer notification was required.

## 7. Drill requirement

Before a bank/fintech production pilot, perform and record a tabletop plus rollback drill at least once. The record must state date, participants, scenario, rollback commit/deployment, measured recovery time, gaps, and follow-up owner. This runbook alone is **not** proof that DR has been tested.

## 8. Existing technical recovery safeguards

```text
verify-pulse-/
├── pipeline/
│   ├── self_healing.py               ← fail-closed hash verification and controlled local restoration
│   ├── integrity_monitor.py          ← protected-file verification
│   └── critical_files_manifest.json  ← approved SHA-256 baseline
├── .github/workflows/
│   └── quality-gate.yml              ← regression and integrity checks on source changes
└── api/verify.js                     ← degraded-provider non-safe fallback behaviour
```
