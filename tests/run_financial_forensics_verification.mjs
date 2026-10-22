// tests/run_financial_forensics_verification.mjs
import assert from 'node:assert/strict';
import { analyzeFinancialThreats } from '../lib/financial_forensics.js';

async function runTests() {
    console.log('--- Starting Financial Forensics Hardening Verification Tests ---');

    // Test 1: Loophole 16 Target Case - Null text with URL array (Used to crash with TypeError!)
    const res1 = analyzeFinancialThreats(null, ['https://scam-site.com/login']);
    assert.equal(res1.hasApkDrop, false);
    assert.deepEqual(res1.upiIds, []);
    assert.deepEqual(res1.phoneNumbers, []);
    assert.deepEqual(res1.ifscCodes, []);
    console.log('   ✓ Test 1: Null text with URL array handled safely (No crash)');

    // Test 2: Undefined text with APK drop URL
    const res2 = analyzeFinancialThreats(undefined, ['https://suspicious-files.com/update_kyc.apk']);
    assert.equal(res2.hasApkDrop, true);
    assert.ok(res2.riskScore >= 80);
    assert.ok(res2.warnings.some(w => w.includes('MALICIOUS_APK_DROP')));
    console.log('   ✓ Test 2: Undefined text with APK URL correctly detects malware drop');

    // Test 3: Null urls with text
    const res3 = analyzeFinancialThreats('Pay immediately to scammer@ybl or call +919876543210', null);
    assert.ok(res3.upiIds.includes('scammer@ybl'));
    assert.ok(res3.phoneNumbers.includes('9876543210'));
    console.log('   ✓ Test 3: Null URLs with text extracts financial identifiers');

    // Test 4: Both text and urls null/empty
    const res4 = analyzeFinancialThreats(null, null);
    assert.equal(res4.riskScore, 0);
    assert.deepEqual(res4.upiIds, []);
    console.log('   ✓ Test 4: Both null returns clean default threat object');

    // Test 5: Full Threat Extraction (UPI, Phone, IFSC, APK)
    const fullText = 'URGENT: Transfer 5000 to fraud@paytm or account IFSC SBIN0001234. Helpline: +91 9988776655. Download app rewards.apk';
    const res5 = analyzeFinancialThreats(fullText, ['https://bank-rewards.apk']);
    assert.ok(res5.upiIds.includes('fraud@paytm'));
    assert.ok(res5.phoneNumbers.includes('9988776655'));
    assert.ok(res5.ifscCodes.includes('SBIN0001234'));
    assert.equal(res5.hasApkDrop, true);
    assert.equal(res5.riskScore, 100, 'Risk score capped at 100');
    console.log('   ✓ Test 5: Full threat extraction and score capping verified');

    console.log('--- ALL FINANCIAL FORENSICS TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
