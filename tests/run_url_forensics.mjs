import assert from 'node:assert/strict';
import { analyzeMessageForensics, canonicalizeUrl, extractUrlCandidates } from '../lib/url_forensics.js';

const cases = [
  {
    id: 'bare-short-link-payment-request',
    input: 'HDFC cashback unlock karne ke liye bit.ly/demo-reward par click karke UPI PIN verify karo.',
    expectedHighRisk: true,
    expectedSignal: 'shortened_link'
  },
  {
    id: 'direct-ip-credential-request',
    input: 'SBI security notice: http://198.51.100.10/login par OTP submit karo.',
    expectedHighRisk: true,
    expectedSignal: 'direct_ip_host'
  },
  {
    id: 'brand-typo-host-with-action',
    input: 'HDFC account verification ke liye https://hdfd.example/verify par click karein.',
    expectedHighRisk: true,
    expectedSignal: 'brand_typo_hdfc'
  },
  {
    id: 'credential-style-url-host-confusion',
    input: 'HDFC update ke liye https://hdfcbank.com@evil.example/login par details submit karein.',
    expectedHighRisk: true,
    expectedSignal: 'url_credentials'
  },
  {
    id: 'official-domain-is-not-flagged',
    input: 'HDFC information is available at https://www.hdfcbank.com/.',
    expectedHighRisk: false
  },
  {
    id: 'official-verifypulse-domain-is-not-flagged',
    input: 'VerifyPulse is available at https://www.verify-pulse.com/.',
    expectedHighRisk: false
  },
  {
    id: 'verifypulse-lookalike-with-otp-request',
    input: 'VerifyPulse security notice: https://verify-pulse.com.security-check.example/verify par OTP share karein.',
    expectedHighRisk: true,
    expectedSignal: 'brand_host_mismatch_verifypulse'
  },
  {
    id: 'routine-url-free-notification-is-not-flagged',
    input: 'Your UPI transaction has been completed. Check your official app for details.',
    expectedHighRisk: false
  },
  {
    id: 'jio-style-claim-link-keeps-verification-boundary',
    input: 'You have exclusive Jio coupons. Claim now: https://t.jio/JIOCPN/qlJG1N',
    expectedHighRisk: false,
    expectedSignal: 'brand_host_mismatch_jio'
  }
];

for (const testCase of cases) {
  const result = analyzeMessageForensics(testCase.input);
  assert.equal(result.highRisk, testCase.expectedHighRisk, `${testCase.id}: unexpected high-risk decision`);
  if (testCase.expectedSignal) {
    assert.ok(result.urls.some((entry) => entry.signals.includes(testCase.expectedSignal)), `${testCase.id}: missing ${testCase.expectedSignal}`);
  }
}

assert.deepEqual(extractUrlCandidates('Review bit.ly/demo and https://example.com/path.'), ['bit.ly/demo', 'https://example.com/path']);
assert.equal(canonicalizeUrl('hdfcbank.com@evil.example/login').hostname, 'evil.example');

console.table(cases.map((testCase) => ({ id: testCase.id, highRisk: analyzeMessageForensics(testCase.input).highRisk })));
console.log(`URL forensics suite passed: ${cases.length}/${cases.length} cases.`);
