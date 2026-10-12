# VerifyPulse Enterprise Service Level Agreement (SLA) & Support Policy

**Effective Date:** October 2026  
**Applicability:** VerifyPulse Commercial API (Tier 1: Standard, Tier 2: Pro, Tier 3: Ultra, Tier 4: Enterprise Custom)

> **Status:** This file is a proposed commercial policy template. The commitments below are not active guarantees unless they are accepted in a signed customer contract and the required infrastructure, monitoring, support rota, escalation channels, and service-credit process are operationally verified.

---

## 1. Uptime Commitment

The following are proposed availability targets for core verification and transaction security APIs. Actual commitments require a signed contract and measured production evidence:

| Tier | Monthly Uptime Commitment | Scheduled Maintenance Window | Service Credit Eligibility |
|---|---|---|---|
| **Tier 1 (Standard)** | 99.90% (~43m max downtime/mo) | Standard weekend maintenance | N/A |
| **Tier 2 (Pro)** | 99.95% (~21m max downtime/mo) | Off-peak with 48h notice | 10% invoice credit if < 99.95% |
| **Tier 3 (Ultra)** | 99.99% (~4.3m max downtime/mo) | Zero-downtime rolling deploys | 25% invoice credit if < 99.99% |
| **Tier 4 (Custom/SIs)** | 99.99% (Multi-Region / VPC) | Dedicated VPC scheduled | Custom contractual SLA |

---

## 2. Severity Levels & Incident Response Times

VerifyPulse implements a rigorous incident management matrix based on client operational impact:

| Severity | Definition | Tier 1 Response | Tier 2 Response | Tier 3 (Ultra) Response |
|---|---|---|---|---|
| **P1 - Critical Outage** | Production API down, 100% transactions blocked, or security breach. | < 4 Hours | < 1 Hour | **< 15 Minutes (24/7/365)** |
| **P2 - Major Degradation** | High latency (>500ms), core heuristic engine degraded, or auth failure. | < 8 Hours | < 2 Hours | **< 1 Hour (24/7/365)** |
| **P3 - Minor Issue** | Isolated false positive, UI bug, or dashboard report error. | < 24 Hours | < 8 Hours | **< 4 Hours** |
| **P4 - General Query** | Documentation question, integration guidance, or feature request. | < 48 Hours | < 24 Hours | **< 8 Hours** |

---

## 3. Support Channels & Escalation Matrix

### Tier 1 (Standard)
* **Channel:** Dedicated Support Portal & Email (`support@verify-pulse.com`).
* **Hours:** Business hours (09:00 - 18:00 IST, Mon - Fri).

### Tier 2 (Pro)
* **Channel:** Shared Enterprise Slack / Microsoft Teams channel + Email.
* **Hours:** Extended business hours (08:00 - 22:00 IST, Mon - Sat) with automated on-call routing for P1 incidents.

### Tier 3 (Ultra) & Tier 4 (Enterprise Custom)
* **Channel:** Dedicated 24/7 Private Slack / Teams War Room + Direct Emergency Escalation Phone / WhatsApp Hotline.
* **On-Call Engineering:** 24/7/365 rotation with automated PagerDuty escalation directly to senior platform engineers.
* **Named Technical Account Manager (TAM):** Assigned dedicated engineering liaison for architecture reviews, false positive calibrations, and monthly threat intelligence reviews.
* **Air-Gapped / On-Premise Support:** Remote assisted deployment & quarterly offline index pack delivery for isolated bank deployments.

---

## 4. Disaster Recovery & Redundancy

* **Primary Infrastructure:** AWS Mumbai (`ap-south-1`) with multi-availability-zone redundancy.
* **Failover Engine:** Edge serverless fallback across Vercel Enterprise infrastructure.
* **Data Protection:** Zero-PII ingestion model ensures no customer account data or OTPs are stored at rest, eliminating data breach liabilities.
