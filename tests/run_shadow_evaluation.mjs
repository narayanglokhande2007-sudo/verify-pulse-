import assert from 'node:assert/strict';
import { createShadowEvaluation } from '../lib/shadow_evaluation.js';

const riskEvaluation = createShadowEvaluation({
  verdict: 'SUSPICIOUS',
  evidenceSources: ['Local multilingual intent forensics'],
  intentForensics: { highRisk: true, signals: ['upi_receipt_payment_deception'] },
  urlForensics: { highRisk: false, urls: [] }
});
assert.equal(riskEvaluation.mode, 'non-blocking');
assert.equal(riskEvaluation.agreement, true);
assert.equal(riskEvaluation.candidateVerdict, 'SUSPICIOUS');
assert.deepEqual(riskEvaluation.localSignals.intentSignalIds, ['upi_receipt_payment_deception']);
assert.match(riskEvaluation.dataHandling, /no raw scanned content/i);

const degradedEvaluation = createShadowEvaluation({
  verdict: 'NEEDS_VERIFICATION',
  evidenceSources: ['Service health monitor'],
  intentForensics: { highRisk: false, signals: [] },
  urlForensics: { highRisk: false, urls: [] }
});
assert.equal(degradedEvaluation.serviceDegraded, true);
assert.equal(degradedEvaluation.agreement, true);
assert.equal(degradedEvaluation.candidateVerdict, 'NO_LOCAL_OVERRIDE');

console.table([riskEvaluation, degradedEvaluation].map((item) => ({
  servedVerdict: item.servedVerdict,
  candidateVerdict: item.candidateVerdict,
  agreement: item.agreement,
  serviceDegraded: item.serviceDegraded
})));
console.log('Shadow-evaluation suite passed: non-blocking, derived-signal telemetry remains privacy-safe.');
