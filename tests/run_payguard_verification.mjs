// tests/run_payguard_verification.mjs
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import payguardHandler from '../api/payguard.js';

function hash(v) {
    return crypto.createHash('sha256').update(v).digest('hex');
}

function mockRes() {
    return {
        statusCode: 200,
        headers: {},
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        setHeader(name, val) {
            this.headers[name] = val;
            return this;
        },
        json(payload) {
            this.body = payload;
            return this;
        }
    };
}

async function runTests() {
    console.log('--- Starting PayGuard Hardening Verification Tests ---');

    const keyTier2 = 'secret-test-pro-key';
    const keyTier1 = 'secret-test-tier1-key';
    const keyNoScope = 'secret-test-noscope-key';

    process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
        {
            keyId: 'pro-client-payguard',
            tenantId: 'test_nbfc',
            tier: 2,
            sha256: hash(keyTier2),
            scopes: ['b2b:payguard', 'b2b:scan'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'tier1-client-payguard',
            tenantId: 'test_standard',
            tier: 1,
            sha256: hash(keyTier1),
            scopes: ['b2b:scan'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'noscope-client-payguard',
            tenantId: 'test_noscope',
            tier: 2,
            sha256: hash(keyNoScope),
            scopes: ['b2b:other'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        }
    ]);

    const proHeaders = {
        'x-api-key': keyTier2,
        'x-verifypulse-key-id': 'pro-client-payguard',
        'x-forwarded-for': '127.0.0.1'
    };

    // Test 1: Method Check (GET rejected)
    const res1 = mockRes();
    await payguardHandler({ method: 'GET', headers: {} }, res1);
    assert.equal(res1.statusCode, 405);
    console.log('   ✓ Test 1: Method check verified (405 on GET)');

    // Test 2: Unauthenticated Request
    const res2 = mockRes();
    await payguardHandler({ method: 'POST', headers: {} }, res2);
    assert.equal(res2.statusCode, 401);
    assert.equal(res2.body.error, 'UNAUTHORIZED');
    console.log('   ✓ Test 2: Unauthenticated request rejected (401)');

    // Test 3: Insufficient Scope
    const res3 = mockRes();
    await payguardHandler({
        method: 'POST',
        headers: {
            'x-api-key': keyNoScope,
            'x-verifypulse-key-id': 'noscope-client-payguard',
            'x-forwarded-for': '127.0.0.1'
        },
        body: { transactionId: 'tx-1' }
    }, res3);
    assert.equal(res3.statusCode, 403);
    assert.equal(res3.body.error, 'INSUFFICIENT_SCOPE');
    console.log('   ✓ Test 3: Insufficient scope rejected (403)');

    // Test 4: Tier 1 Client Upgrade Required
    const res4 = mockRes();
    await payguardHandler({
        method: 'POST',
        headers: {
            'x-api-key': keyTier1,
            'x-verifypulse-key-id': 'tier1-client-payguard',
            'x-forwarded-for': '127.0.0.1'
        },
        body: { transactionId: 'tx-1' }
    }, res4);
    assert.equal(res4.statusCode, 403);
    assert.equal(res4.body.error, 'UPGRADE_REQUIRED');
    console.log('   ✓ Test 4: Tier 1 upgrade required enforced (403)');

    // Test 5: Loophole 14 Null/Empty Body Safety
    const res5 = mockRes();
    await payguardHandler({
        method: 'POST',
        headers: proHeaders,
        body: null
    }, res5);
    assert.equal(res5.statusCode, 400);
    assert.equal(res5.body.error, 'MISSING_DATA');
    console.log('   ✓ Test 5: Null body safely returns 400 without crashing');

    // Test 6: Missing Identifiers
    const res6 = mockRes();
    await payguardHandler({
        method: 'POST',
        headers: proHeaders,
        body: { transactionId: 'tx-2' }
    }, res6);
    assert.equal(res6.statusCode, 400);
    assert.equal(res6.body.error, 'MISSING_DATA');
    console.log('   ✓ Test 6: Missing receiver identifiers safely handled (400)');

    // Test 7: Known Syndicate Mule UPI Block
    const res7 = mockRes();
    await payguardHandler({
        method: 'POST',
        headers: proHeaders,
        body: {
            transactionId: 'txn-mule-101',
            amount: 49999,
            receiverUpi: 'cbi.cybercell.verify@ybl'
        }
    }, res7);
    assert.equal(res7.statusCode, 200);
    assert.equal(res7.body.action, 'BLOCK');
    assert.ok(res7.body.flags.includes('SCAM_SYNDICATE_GRAPH_MATCH'));
    assert.equal(res7.body.syndicate?.clusterId, 'syn-dl-arrest-01');
    console.log('   ✓ Test 7: Known syndicate mule UPI blocked (action: BLOCK)');

    // Test 8: Benign Clean Transaction
    const res8 = mockRes();
    await payguardHandler({
        method: 'POST',
        headers: proHeaders,
        body: {
            transactionId: 'txn-clean-202',
            amount: 1500,
            receiverUpi: 'merchant.store@oksbi'
        }
    }, res8);
    assert.equal(res8.statusCode, 200);
    assert.equal(res8.body.action, 'ALLOW');
    assert.equal(res8.body.riskScore, 0);
    console.log('   ✓ Test 8: Benign transaction allowed (action: ALLOW)');

    console.log('--- ALL PAYGUARD VERIFICATION TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
