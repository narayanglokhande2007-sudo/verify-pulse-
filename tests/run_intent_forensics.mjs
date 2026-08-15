import assert from 'node:assert/strict';
import { analyzeIntentForensics, normalizeSecurityText } from '../lib/intent_forensics.js';

const cases = [
  {
    id: 'qr-receipt-deception',
    input: 'Rs 2,000 cashback receive karne ke liye QR scan karo aur UPI PIN enter karo. Offer sirf 5 minutes ke liye valid hai.',
    expectedHighRisk: true,
    expectedSignal: 'upi_receipt_payment_deception'
  },
  {
    id: 'bank-remote-access-trap',
    input: 'Bank helpdesk: transaction reverse karne ke liye AnyDesk install karo aur screen share support call join karo, warna account freeze rahega.',
    expectedHighRisk: true,
    expectedSignal: 'financial_remote_access_trap'
  },
  {
    id: 'zero-width-brand-normalization',
    input: 'S\u200bB\u200bI account will be blocked. Pay Rs 10 verification fee now.',
    expectedHighRisk: true,
    expectedSignal: 'named_financial_block_fee_trap',
    expectedNormalized: true
  },
  {
    id: 'preventive-npci-guidance',
    input: 'Safety reminder: A UPI PIN is entered only to make a payment, not to receive money. Never scan unknown QR codes for cashback or refunds.',
    expectedHighRisk: false
  },
  {
    id: 'preventive-customer-care-guidance',
    input: 'For payment support, find your bank contact details only on its official website. Do not install a screen-sharing app during a financial transaction.',
    expectedHighRisk: false
  }
];

for (const testCase of cases) {
  const result = analyzeIntentForensics(testCase.input);
  assert.equal(result.highRisk, testCase.expectedHighRisk, `${testCase.id}: unexpected high-risk decision.`);
  if (testCase.expectedSignal) assert.ok(result.signals.includes(testCase.expectedSignal), `${testCase.id}: expected signal missing.`);
  if (testCase.expectedNormalized !== undefined) assert.equal(result.normalized, testCase.expectedNormalized, `${testCase.id}: unexpected normalization state.`);
}

assert.equal(normalizeSecurityText('S\u200bB\u200bI'), 'SBI');
console.table(cases.map((testCase) => ({ id: testCase.id, highRisk: analyzeIntentForensics(testCase.input).highRisk })));
console.log(`Intent-forensics suite passed: ${cases.length}/${cases.length} focused cases.`);
