# VerifyPulse Six Core Upgrades

**Status:** Implemented and locally validated on 14 August 2026  
**Scope:** Accuracy calibration, deterministic forensics, source-aware intelligence, bounded reliability, input protection, and release safety.  
**Change policy:** Existing features and data were preserved. A pre-upgrade Git tag, `pre-six-core-upgrades-2026-08-14`, provides a fast rollback point.

## Executive Summary

VerifyPulse now uses a stronger evidence-first architecture. It does not rely on a model alone to decide whether a message is fraudulent. It first applies privacy controls, calibrated local rules, URL and brand forensics, current source-attributed intelligence, reputation checks, and only then bounded model-assisted analysis when needed.

> **Important interpretation rule:** The regression results in this document apply only to the versioned synthetic test fixtures in this repository. They do not prove global real-world accuracy and must not be marketed as a guarantee or as “100% detection.”

| Upgrade | What changed | Safety and business value |
|---|---|---|
| **India Benchmark Lab** | Expanded the India fixture suite from 8 to 22 labelled cases, including Hindi, Marathi, Telugu, payment, courier, KYC, DBT, UPI cashback, official-domain, and privacy cases. | Prevents silent regression and explicitly measures safe-message false positives. |
| **Calibrated verdicts** | Added `NEEDS_VERIFICATION` for routine-looking but unauthenticated financial notifications. | Reduces the chance that legitimate DBT, refund, debit, or UPI reference messages are incorrectly called phishing while avoiding an unjustified `SAFE` verdict. |
| **URL, brand, sender, and intent forensics** | Added local URL parsing, bare-link detection, direct-IP checks, short-link checks, IDN checks, URL-credential checks, typo-brand scoring, claimed-brand/domain mismatch checks, and requested-action scoring. | Produces rapid, explainable detection without sending a URL to an external model first. |
| **Source-aware intelligence fusion** | Added a compact published snapshot with normalized indicators, source names, confidence, source corroboration, first/last seen timestamps, and expiry. | A raw community feed line is no longer treated as permanent proof. Current evidence remains attributable and expires automatically. |
| **Latency and abuse hardening** | Added a request-wide latency budget, bounded external provider calls, input-size/type checks, and response decision metadata. | Protects the local fast path and makes timeouts, evidence, and response behaviour observable. |
| **Continuous quality and security gates** | Added pull-request/push regression checks, threat-fusion validation, integrity verification, static analysis, and dependency-update configuration. | Makes it harder for a future code change or agent to silently weaken core controls. |

## New Verdict Semantics

| Verdict | Meaning | Recommended user action |
|---|---|---|
| `SAFE` | No significant risk signal was found and the available evidence supports a low-risk assessment. It is not a sender-authentication guarantee. | Continue normal caution. |
| `NEEDS_VERIFICATION` | The text resembles a routine notification but cannot authenticate the sender or transaction by itself. This is **not** a scam verdict. | Confirm only in the official banking, UPI, or government application/website that the user opens independently. |
| `SUSPICIOUS` | Deterministic social-engineering, URL/brand, or lower-confidence intelligence evidence requires caution. | Do not click, pay, approve, or share sensitive information. Verify independently. |
| `DANGEROUS` | A high-confidence malicious-reputation or corroborated intelligence signal was found. | Do not interact with the link or sender. Report financial fraud through official channels where relevant. |
| `CAUTION` / `CONSENT_REQUIRED` | Privacy controls prevented external processing of credentials or a file without explicit consent. | Remove secrets or provide explicit consent only when appropriate. |

## Benchmark and Validation Evidence

The India regression suite has 22 labelled synthetic fixtures. Its quality gates require scam-alert recall of 100% on the fixture set and a benign-case false-positive rate of 0% on the fixture set. The latest local run passed all 22 fixtures, with 11 of 11 scam cases producing an alert and 0 of 9 benign cases receiving a scam-alert verdict. The suite also validates Google Safe Browsing precedence, trusted official domains, sensitive-input protection, and consent requirements.

The deterministic URL-forensics suite passed all six cases. It covers bare short links, direct-IP links, typo-brand domains, credential-style URL confusion, an official domain, and a benign message with no URL. The source-aware intelligence suite passed its active indicator, expiry, and no-URL scenarios. The request-budget and input-control suites passed. The existing provider reliability suite also passed all five focused resilience scenarios.

A local, dependency-free fast-path benchmark executed 100 deterministic protective decisions. In that local process the measured median was 0.03 ms, the p95 was 0.15 ms, and the p99 was 1.17 ms. These figures measure only the local decision path in the test environment; they are **not** an end-to-end production latency promise.

## Threat Intelligence Operating Model

The daily workflow continues to run the existing data fetcher, then creates `latest_threat_intel.json`. The snapshot is compact, capped, normalized, and expiry-bounded. It currently retrieves selected public URL intelligence sources in a bounded way, while preserving the existing historical feed pipeline. URLhaus publishes malware URL intelligence and OpenPhish publishes phishing intelligence; VerifyPulse records source provenance and expiry rather than treating either as a permanent blocklist. [1] [2]

A fresh snapshot is generated on the daily workflow. The runtime only uses a snapshot whose global expiry is still valid, and it ignores individual indicators past their expiry. If the snapshot cannot be retrieved, VerifyPulse fails safely by continuing its other local and model-assisted evidence layers; it does not convert the absence of intelligence into a `SAFE` verdict.

## Continuous Safety Controls

The repository now includes a `VerifyPulse Quality Gate` workflow for pull requests and pushes to `main`. It runs the deterministic JavaScript suite, the Python intelligence-fusion test, the fail-closed integrity verifier, and CodeQL static analysis. GitHub Actions standard runners and CodeQL analysis are available without charge for public repositories; Dependabot can surface dependency alerts and update pull requests. [3] [4] [5]

The integrity manifest is generated only through an explicit maintainer action. The recovery utility is intentionally fail-closed: it does not download replacement code, delete project data, or rewrite files unless a maintainer explicitly supplies a local trusted source whose hash matches the committed manifest.

## Files Introduced or Updated

```text
verify-pulse-/
├── .github/
│   ├── dependabot.yml                              # NEW: dependency/workflow update checks
│   └── workflows/
│       ├── daily_scam_fetch.yml                    # UPDATED: publishes source-aware snapshot
│       └── quality-gate.yml                        # NEW: tests, integrity, CodeQL
├── api/
│   └── verify.js                                   # UPDATED: calibrated verdicts, forensics, budget, evidence
├── lib/
│   ├── privacy_guard.js                            # UPDATED: avoids treating UPI refs as Aadhaar values
│   ├── request_budget.js                            # NEW: request-wide timeout budget
│   ├── threat_intelligence.js                       # NEW: cached source-aware lookup
│   └── url_forensics.js                             # NEW: local URL/brand/sender/intent analysis
├── pipeline/
│   ├── build_threat_intelligence.py                # NEW: normalizes, scores, expires, and publishes indicators
│   ├── self_healing.py                              # UPDATED: protects new critical modules
│   ├── critical_files_manifest.json                # UPDATED: approved hash baseline
│   ├── test_threat_intelligence.py                 # NEW: fusion unit tests
│   └── daily-data/
│       ├── latest_threat_intel.json                # NEW: generated compact snapshot
│       └── threat_intel_stats.json                 # NEW: non-sensitive generation statistics
├── tests/
│   ├── fixtures/india_scam_regression_cases.json   # UPDATED: 22 labelled fixtures and quality gates
│   ├── run_india_regression.mjs                    # UPDATED: benchmark metrics and gate enforcement
│   ├── run_input_controls.mjs                      # NEW: input and decision-metadata tests
│   ├── run_local_performance.mjs                   # NEW: fast-path benchmark
│   ├── run_request_budget.mjs                      # NEW: budget tests
│   ├── run_threat_intelligence.mjs                 # NEW: cached lookup tests
│   └── run_url_forensics.mjs                       # NEW: local forensic tests
├── docs/
│   └── VERIFYPULSE_SIX_CORE_UPGRADES.md            # NEW: this report
└── package.json                                    # UPDATED: unified quality scripts
```

## Rollback Procedure

The stable pre-upgrade state is preserved locally in Git through `pre-six-core-upgrades-2026-08-14`. If a production issue appears after deployment, revert the upgrade commit or reset to this tag, redeploy, and then investigate using the deterministic suites before trying another release. Do not disable privacy protections, integrity verification, or quality gates to work around a failed test.

## References

[1]: https://urlhaus.abuse.ch/ "URLhaus — Malware URL Exchange"
[2]: https://openphish.com/ "OpenPhish — Phishing Intelligence"
[3]: https://docs.github.com/en/actions/concepts/billing-and-usage "GitHub Actions billing and usage"
[4]: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli "CodeQL CLI documentation"
[5]: https://docs.github.com/code-security/dependabot/dependabot-alerts/configuring-dependabot-alerts "Configuring Dependabot alerts"
