import assert from 'node:assert/strict';
import { calibrateDecision } from '../lib/decision_calibration.js';

const cases = [
  {
    id: 'deterministic-risk',
    input: { verdict: 'SUSPICIOUS', confidence: 88, evidenceSources: ['Local multilingual intent forensics'] },
    expected: { riskBand: 'high-risk', decisionBasis: 'evidence-backed', independentVerificationRecommended: true }
  },
  {
    id: 'degraded-verification',
    input: { verdict: 'NEEDS_VERIFICATION', confidence: 0, evidenceSources: ['Service health monitor'] },
    expected: { riskBand: 'verification-required', decisionBasis: 'service-status', independentVerificationRecommended: true }
  },
  {
    id: 'trusted-domain-lower-risk',
    input: { verdict: 'SAFE', confidence: 99, evidenceSources: ['Trusted domain registry'] },
    expected: { riskBand: 'lower-risk', decisionBasis: 'evidence-backed', safeIsNotAuthentication: true }
  },
  {
    id: 'model-assisted-safe',
    input: { verdict: 'SAFE', confidence: 74, evidenceSources: [] },
    expected: { riskBand: 'lower-risk', decisionBasis: 'model-assisted', safeIsNotAuthentication: true }
  },
  {
    id: 'google-no-match-does-not-prove-safe',
    input: { verdict: 'SAFE', confidence: 74, evidenceSources: ['Google Safe Browsing'] },
    expected: { riskBand: 'lower-risk', decisionBasis: 'model-assisted', safeIsNotAuthentication: true }
  },
  {
    id: 'google-web-risk-positive-match-is-evidence',
    input: { verdict: 'DANGEROUS', confidence: 100, evidenceSources: ['Google Web Risk'] },
    expected: { riskBand: 'critical-risk', decisionBasis: 'evidence-backed', independentVerificationRecommended: true }
  }
];

for (const testCase of cases) {
  const result = calibrateDecision(testCase.input);
  for (const [key, value] of Object.entries(testCase.expected)) {
    assert.equal(result[key], value, `${testCase.id}: expected ${key}=${value}.`);
  }
  assert.match(result.confidenceInterpretation, /not proof/i, `${testCase.id}: calibration must state confidence limitation.`);
}

console.table(cases.map((testCase) => ({ id: testCase.id, ...calibrateDecision(testCase.input) })));
console.log(`Decision-calibration suite passed: ${cases.length}/${cases.length} calibration cases.`);
