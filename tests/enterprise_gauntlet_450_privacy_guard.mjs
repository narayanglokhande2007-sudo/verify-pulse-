// tests/enterprise_gauntlet_450_privacy_guard.mjs
// ============================================================================
// VERIFYPULSE 450-CASE HARDEST ENTERPRISE BATTLE GAUNTLET: FEATURE #7
// Module: Enterprise Privacy Guard & Zero-PII Sanitization Rail
// Target: Expose PAN Card Leaks, URL Basic-Auth Passwords, Regional OTPs & VPA Leaks
// ============================================================================

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

import {
  sanitizeForExternalAnalysis,
  hasCredentialLikeData,
  createPrivacyReceipt
} from '../lib/privacy_guard.js';

console.log('='.repeat(72));
console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #7        ');
console.log('   Module: Enterprise Privacy Guard & Zero-PII Sanitization Rail        ');
console.log('   Target: PAN Cards, Basic-Auth URLs, Regional OTPs & DPDP 2023 Shield ');
console.log('   Total Cases: 450 Extreme Adversarial Scenarios                       ');
console.log('='.repeat(72));

let totalTested = 0;
let totalPassed = 0;
let totalFailed = 0;
const failures = [];
const latencies = [];

function recordTest(id, category, passed, error = null, latencyMs = 0) {
  totalTested++;
  latencies.push(latencyMs);
  if (passed) {
    totalPassed++;
  } else {
    totalFailed++;
    failures.push({ id, category, error: error?.message || String(error) });
  }
}

// ============================================================================
// CATEGORY 1: Indian Government IDs (Aadhaar & PAN Numbers) (90 Cases)
// Objective: Ensure 12-digit Aadhaar and 10-character Indian PAN cards are masked.
// ============================================================================
console.log('\n--- [Category 1/5] Indian Government IDs & PAN Card Shield (90 Cases) ---');

const SAMPLE_PANS = [
  'ABCDE1234F', 'BKZPP8912M', 'XYZPA9081K', 'AAAPA0001A', 'ALCPK7761Q',
  'CRWPK2391L', 'DELPR9821B', 'EFLPK4561G', 'GGHPS1234D', 'ZZZPK9999Z'
];

for (let i = 0; i < 90; i++) {
  const testId = `GOVT-ID-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 45) {
      // Aadhaar Card variations (with spaces, hyphens, unspaced, Devanagari context)
      const r1 = 1000 + (i * 11);
      const r2 = 2000 + (i * 13);
      const r3 = 3000 + (i * 17);
      let aadhaarStr;
      if (i % 3 === 0) aadhaarStr = `${r1} ${r2} ${r3}`;
      else if (i % 3 === 1) aadhaarStr = `${r1}-${r2}-${r3}`;
      else aadhaarStr = `${r1}${r2}${r3}`;

      const text = `Your Aadhaar verification pending. UID: ${aadhaarStr}. Complete e-KYC.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(aadhaarStr);
      const passed = !leaked && sanitized.includes('[REDACTED_GOVERNMENT_ID]');
      recordTest(testId, 'Aadhaar ID Sanitization', passed, leaked ? new Error(`Aadhaar number ${aadhaarStr} leaked into sanitized output`) : null, performance.now() - t0);

    } else {
      // Indian PAN Card Numbers (ABCDE1234F) - Standard DPDP Act 2023 requirement
      const pan = SAMPLE_PANS[i % SAMPLE_PANS.length];
      const text = `Loan processing for PAN ${pan} is approved. Verify details immediately.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(pan);
      const passed = !leaked && (sanitized.includes('[REDACTED_GOVERNMENT_ID]') || sanitized.includes('[REDACTED_PAN]'));
      recordTest(testId, 'Indian PAN Card Redaction', passed, leaked ? new Error(`Sensitive Indian PAN ${pan} leaked raw into external analysis`) : null, performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Government ID Sanitization', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 2: Banking Credentials, OTPs, PINs & Regional Alerts (90 Cases)
// Objective: Mask OTPs, PINs, Passwords, Payment Cards & Devanagari labels.
// ============================================================================
console.log('\n--- [Category 2/5] Banking Credentials, Cards & Regional OTPs (90 Cases) ---');

for (let i = 0; i < 90; i++) {
  const testId = `CREDENTIAL-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 30) {
      // Payment Card Numbers (RuPay, Visa, MasterCard: 16 digits)
      const cardNum = `4532 1122 3344 ${1000 + i}`;
      const text = `Debit Card ${cardNum} has been debited with INR 4,999.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(cardNum) || sanitized.includes(cardNum.replace(/\s+/g, ''));
      const passed = !leaked && sanitized.includes('[REDACTED_PAYMENT_NUMBER]');
      recordTest(testId, 'Payment Card Redaction', passed, leaked ? new Error(`Payment Card number ${cardNum} leaked raw`) : null, performance.now() - t0);

    } else if (i < 60) {
      // Standard English OTP & PIN patterns
      const code = 100000 + (i * 123);
      const label = i % 2 === 0 ? 'OTP' : 'UPI PIN';
      const text = `Your ${label} is ${code}. Do not share this with bank executive.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(String(code));
      const passed = !leaked && sanitized.includes('[REDACTED_CREDENTIAL]');
      recordTest(testId, 'Credential & OTP Redaction', passed, leaked ? new Error(`${label} ${code} leaked raw`) : null, performance.now() - t0);

    } else {
      // Regional Devanagari OTP & PIN patterns (e.g. ओटीपी / पिन)
      const code = 200000 + (i * 77);
      const text = `आपका गुप्त ओटीपी ${code} है। किसी से साझा न करें।`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(String(code));
      const passed = !leaked && sanitized.includes('[REDACTED_CREDENTIAL]');
      recordTest(testId, 'Regional Language OTP Redaction', passed, leaked ? new Error(`Devanagari OTP ${code} leaked raw`) : null, performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Credentials & OTPs', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 3: Indian Phone Numbers, Emails & VPA/UPI IDs (90 Cases)
// Objective: Mask Indian mobile numbers (starting 6-9, with +91, 0, spaces) & UPI VPAs.
// ============================================================================
console.log('\n--- [Category 3/5] Mobile Numbers, Emails & UPI Handles (90 Cases) ---');

const UPI_HANDLES = ['@paytm', '@ybl', '@oksbi', '@okhdfcbank', '@upi', '@axl', '@postbank'];

for (let i = 0; i < 90; i++) {
  const testId = `CONTACT-PII-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 30) {
      // Indian Phone Numbers with +91, 0, or spaces
      const rawDigits = `98${10000000 + (i * 777)}`;
      let phoneStr;
      if (i % 3 === 0) phoneStr = `+91 ${rawDigits.slice(0, 5)} ${rawDigits.slice(5)}`;
      else if (i % 3 === 1) phoneStr = `+91-${rawDigits}`;
      else phoneStr = `0${rawDigits}`;

      const text = `Call customer desk at ${phoneStr} immediately to resolve issue.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(rawDigits) || sanitized.includes(phoneStr);
      const passed = !leaked && sanitized.includes('[REDACTED_PHONE]');
      recordTest(testId, 'Indian Mobile Number Redaction', passed, leaked ? new Error(`Phone number ${phoneStr} leaked raw`) : null, performance.now() - t0);

    } else if (i < 60) {
      // Email Addresses
      const email = `officer.test${i}@nbfc-borrower-firm.co.in`;
      const text = `Send your bank statement to ${email} for instant loan disbursal.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(email);
      const passed = !leaked && sanitized.includes('[REDACTED_EMAIL]');
      recordTest(testId, 'Email Address Redaction', passed, leaked ? new Error(`Email ${email} leaked raw`) : null, performance.now() - t0);

    } else {
      // UPI Virtual Payment Address (VPA / UPI ID)
      const handle = UPI_HANDLES[i % UPI_HANDLES.length];
      const vpa = `borrower.account${i}${handle}`;
      const text = `Pay advance fee to UPI handle ${vpa} to release funds.`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const leaked = sanitized.includes(vpa);
      const passed = !leaked && (sanitized.includes('[REDACTED_UPI_ID]') || sanitized.includes('[REDACTED_EMAIL]') || sanitized.includes('[REDACTED_PHONE]'));
      recordTest(testId, 'UPI VPA Handle Redaction', passed, leaked ? new Error(`UPI VPA ${vpa} leaked raw`) : null, performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Contact PII Redaction', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 4: URL Tracking Tokens, Passwords & Query Parameters (90 Cases)
// Objective: Strip Basic Auth (user:pass@host) & URL query/fragment tokens.
// ============================================================================
console.log('\n--- [Category 4/5] URL Embedded Passwords & Query Token Stripping (90 Cases) ---');

for (let i = 0; i < 90; i++) {
  const testId = `URL-PRIVACY-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 45) {
      // Basic Auth embedded inside URL (https://username:secretPassword@domain.com/login)
      const user = `admin${i}`;
      const pass = `SecretPassword${i}!`;
      const host = `phish-bank-${i}.com`;
      const urlWithAuth = `https://${user}:${pass}@${host}/secure/portal`;

      const text = `Click this link to authenticate: ${urlWithAuth}`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const passLeaked = sanitized.includes(pass);
      const hostPreserved = sanitized.includes(host);
      const passed = !passLeaked && hostPreserved;

      recordTest(testId, 'URL Embedded Auth Sanitization', passed, passLeaked ? new Error(`Plaintext password ${pass} leaked from embedded URL`) : null, performance.now() - t0);

    } else {
      // Query parameters & tracking tokens (e.g. ?session_token=...&jwt=...)
      const secretToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_${i}`;
      const host = `loan-approval-portal-${i}.net`;
      const urlWithParams = `https://${host}/verify?auth_token=${secretToken}&user_id=12345#secret_hash_value`;

      const text = `Review agreement here: ${urlWithParams}`;
      const sanitized = sanitizeForExternalAnalysis(text);

      const tokenLeaked = sanitized.includes(secretToken) || sanitized.includes('secret_hash_value');
      const hostPreserved = sanitized.includes(host);
      const passed = !tokenLeaked && hostPreserved;

      recordTest(testId, 'URL Query & Fragment Stripping', passed, tokenLeaked ? new Error(`URL session token leaked into output`) : null, performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'URL Privacy Sanitization', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 5: Educational Whitelist & Cryptographic Privacy Receipts (75 Cases)
// Objective: Never false-alarm on awareness text, verify SHA-256 privacy receipts.
// ============================================================================
console.log('\n--- [Category 5/5] Educational Whitelist & Cryptographic Receipts (90 Cases) ---');

const AWARENESS_MESSAGES = [
  'RBI Kehta Hai: Never share your OTP or UPI PIN with anyone claiming to be bank manager.',
  'Cyber Hygiene Alert: Banks never ask for your password or CVV over call or SMS.',
  'Delhi Police Advisory: Do not scan unknown QR codes or enter your PIN to receive money.',
  'Safety reminder: OTP is only for deducting money, never for receiving lottery prizes.',
  'NPCI Advisory: Please be alert. Never share one-time password or passcode with callers.'
];

for (let i = 0; i < 90; i++) {
  const testId = `RECEIPT-AWARENESS-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 45) {
      // Awareness text MUST NOT be flagged as containing real credentials
      const msg = AWARENESS_MESSAGES[i % AWARENESS_MESSAGES.length];
      const hasCred = hasCredentialLikeData(msg);

      const passed = hasCred === false;
      recordTest(testId, 'Educational Awareness Whitelist', passed, passed ? null : new Error(`Educational safety advisory falsely flagged as credential leak`), performance.now() - t0);

    } else {
      // Cryptographic Privacy Receipt Verification
      const rawInput = `Loan approval for Customer 9876543210. OTP is ${100000 + i}. URL: https://bad.com/pay?token=xyz`;
      const sanitized = sanitizeForExternalAnalysis(rawInput);
      const receipt = createPrivacyReceipt(rawInput, sanitized);

      const expectedHash = crypto.createHash('sha256').update(rawInput).digest('hex');
      const hashMatches = receipt.inputFingerprint === expectedHash;
      const redactedFlagCorrect = receipt.externalAnalysisRedacted === true;
      const policyMatches = receipt.policyVersion === 'vp-privacy-2';

      const passed = hashMatches && redactedFlagCorrect && policyMatches;
      recordTest(testId, 'Cryptographic Privacy Receipt', passed, passed ? null : new Error('Privacy receipt verification mismatch'), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Receipt & Awareness', false, err, performance.now() - t0);
  }
}

// ============================================================================
// SUMMARY AUDIT METRICS
// ============================================================================
console.log('\n' + '='.repeat(72));
console.log('   FEATURE #7 HARDEST GAUNTLET SUMMARY AUDIT METRICS                    ');
console.log('='.repeat(72));
console.log(`Total Cases Tested:      ${totalTested}`);
console.log(`Total Passed:            ${totalPassed} ${totalPassed === totalTested ? '✅' : '⚠️'}`);
console.log(`Total Failed:            ${totalFailed} ${totalFailed === 0 ? '✅' : '❌'}`);
const successRate = ((totalPassed / totalTested) * 100).toFixed(2);
console.log(`Success Rate:            ${successRate}%`);

if (latencies.length > 0) {
  const minL = Math.min(...latencies).toFixed(3);
  const avgL = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3);
  const maxL = Math.max(...latencies).toFixed(3);
  console.log(`\n--- LATENCY BENCHMARK ---`);
  console.log(`Min Latency: ${minL} ms | Avg Latency: ${avgL} ms | Max Latency: ${maxL} ms`);
}

if (failures.length > 0) {
  console.log(`\n❌ FAILURES BREAKDOWN (${failures.length} Failures Exposed):`);
  const catFailures = {};
  failures.forEach(f => {
    catFailures[f.category] = (catFailures[f.category] || 0) + 1;
  });
  for (const [cat, count] of Object.entries(catFailures)) {
    console.log(`  - ${cat}: ${count} failures`);
  }
  console.log('\nSample Failed Cases:');
  failures.slice(0, 10).forEach(f => {
    console.log(`  [${f.id}] (${f.category}): ${f.error}`);
  });
} else {
  console.log('\n🎉 ALL 450 HARDEST TEST CASES PASSED!');
}
console.log('='.repeat(72));

if (totalFailed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
