# Phase 2: Explainability and India-Focused Regression Testing

## Purpose

This Phase 2 foundation makes each VerifyPulse result easier to understand without inventing unsupported evidence or accuracy claims. The backend now attaches a structured `explainability` object to scanner results, and the repository includes a labelled regression suite for high-value India-focused edge cases.

> The explainability output is a user-facing explanation, not a proof of fraud, sender authentication, legal determination, or a substitute for verifying through an official channel.

## Explainability Contract

Every normalized scanner result includes an `explainability` object with the following fields.

| Field | Meaning |
|---|---|
| `version` | Explainability schema version, currently `vp-explain-1`. |
| `assessmentType` | `evidence-backed`, `model-assisted`, or `privacy-protection`. |
| `summary` | Concise statement of why the result was produced. |
| `evidence` | Sources and details that actually contributed to the result. |
| `limitations` | Important cautions, including that a safe result does not authenticate a sender. |

The system only identifies Google Safe Browsing as evidence when that lookup was performed. It identifies the trusted-domain registry only for a parsed hostname match and local social-engineering rules only when those deterministic rules fired. Model-based responses are labelled `model-assisted`; no invented confidence weights, domain-age checks, or chain-of-thought content is exposed.

## Regression Fixtures

The fixture file is `tests/fixtures/india_scam_regression_cases.json`. Its entries are synthetic test cases or benign public URLs. They are deliberately separate from `pipeline/daily-data/`.

**Do not** add these fixtures to production feeds, blocklists, threat maps, customer metrics, marketing statistics, or training data. The suite exists only to prevent regressions such as authority-name false-safe results, credential-keyword false positives, missing consent controls, and misleading evidence labels.

Run the suite before merging detection or explainability changes:

```bash
npm run test:india-regression
```

The current suite covers digital-arrest impersonation, UPI collect-request pressure, Income Tax verification-call impersonation, a legitimate anti-fraud advisory, actual OTP handling, a trusted RBI URL, a mocked Safe Browsing reputation match, and file-analysis consent refusal.

## Interpreting Results

A passing suite means only that the current expected behaviour for these labelled cases is preserved. It does **not** prove a percentage accuracy figure, prove performance against competitors, or justify claims such as “scams blocked.” Broader performance claims require a documented benchmark, representative data, independent ground truth, and measured false-positive and false-negative rates.
