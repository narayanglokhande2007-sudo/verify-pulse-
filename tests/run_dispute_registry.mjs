// tests/run_dispute_registry.mjs
import assert from 'node:assert/strict';
import { assessDisputeCalibratedDomains, DISPUTE_CALIBRATED_REGISTRY } from '../lib/dispute_registry.js';
import { calibrateDecision } from '../lib/decision_calibration.js';

console.log('='.repeat(70));
console.log('VerifyPulse Dispute Registry & Calibration Test Suite');
console.log('='.repeat(70));

// Test 1: mycontent.academy
const academy = assessDisputeCalibratedDomains('https://mycontent.academy/');
assert.ok(academy, 'mycontent.academy must be matched');
assert.equal(academy.verdict, 'NEEDS_VERIFICATION');
assert.equal(academy.confidence, 0);
assert.equal(academy.disputeMetadata.ticketId, 'VP-REP-2026-1104');
assert.ok(academy.evidenceSources.includes('Domain dispute resolution registry'));
console.log('  [PASS] mycontent.academy calibrated to NEEDS_VERIFICATION');

// Test 2: mycontent.agency
const agency = assessDisputeCalibratedDomains('https://mycontent.agency/');
assert.ok(agency, 'mycontent.agency must be matched');
assert.equal(agency.verdict, 'NEEDS_VERIFICATION');
assert.equal(agency.confidence, 0);
assert.equal(agency.disputeMetadata.ticketId, 'VP-REP-2026-1104');
console.log('  [PASS] mycontent.agency calibrated to NEEDS_VERIFICATION');

// Test 3: Subdomain support
const sub = assessDisputeCalibratedDomains('Check this out: https://portal.mycontent.agency/login');
assert.ok(sub, 'Subdomains of mycontent.agency must also be covered');
assert.equal(sub.verdict, 'NEEDS_VERIFICATION');
console.log('  [PASS] Subdomain portal.mycontent.agency correctly handled');

// Test 4: Unrelated domain must return null
const unrelated = assessDisputeCalibratedDomains('https://example.com/test');
assert.equal(unrelated, null, 'Unrelated domains must return null');
console.log('  [PASS] Unrelated domain returns null (passes through to standard engine)');

// Test 5: Calibration integration
const calibrated = calibrateDecision({
  verdict: academy.verdict,
  confidence: academy.confidence,
  evidenceSources: academy.evidenceSources
});
assert.equal(calibrated.riskBand, 'verification-required');
assert.equal(calibrated.decisionBasis, 'evidence-backed');
assert.equal(calibrated.modelConfidence, 0);
assert.equal(calibrated.independentVerificationRecommended, true);
console.log('  [PASS] Decision Calibration evaluates dispute registry as evidence-backed verification-required');

console.log('='.repeat(70));
console.log('ALL 5 DISPUTE REGISTRY TESTS PASSED!');
console.log('='.repeat(70));
