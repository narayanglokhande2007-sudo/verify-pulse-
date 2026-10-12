# VerifyPulse Dedicated Cloud & Air-Gapped Banking Architecture

This document specifies the enterprise infrastructure provisioning topologies available for Tier 3 (Ultra) and Tier 4 (Enterprise Custom) subscribers.

---

## 1. Deployment Models

VerifyPulse supports two distinct enterprise hosting topologies designed for regulated financial institutions:

### Option A: Dedicated Isolated VPC (AWS Mumbai / ap-south-1)
* **Single-Tenant VPC:** Deployed within an isolated Virtual Private Cloud with dedicated private subnets.
* **VPC Peering & AWS Direct Connect:** Direct private connection to bank data centers without internet traversal.
* **KMS Hardware Security Modules:** All Redis caches, tenant audit logs, and custom rules are encrypted using dedicated customer-managed AWS KMS keys (CMKs).
* **Data Localization:** 100% of telemetry, API traffic, and logs remain strictly within the Republic of India (AWS Mumbai).

### Option B: Air-Gapped / On-Premise Docker Export (Self-Hosted)
* **Containerized Deployment:** Uses VerifyPulse multi-stage containers defined in `deploy/docker/Dockerfile` and `deploy/docker/docker-compose.yml`.
* **Zero External Dependencies:** Operates entirely within the bank’s internal DMZ without outbound internet access required.
* **Offline Threat Index Ingestion:** VerifyPulse provides encrypted weekly or daily offline shard packs (`shards/*.json`) loaded directly into the local high-speed index.

---

## 2. Security & Compliance Controls

| Control Domain | Implementation Specification | Compliance Mapping |
|---|---|---|
| **Data Ingestion** | Zero-PII Cryptographic Hashes (SHA-256) | DPDP Act 2023 |
| **Transport Encryption** | TLS 1.3 Strict, HSTS Max-Age (63072000s) | RBI Cyber Security Framework |
| **Network Isolation** | Isolated VPC / Docker Bridge, No Public Database Exposure | ISO 27001 Annex A.13 |
| **Access Control** | Scoped API Keys with Tenant-level rate limiting and audit events | SOC 2 Trust Services Criteria |
