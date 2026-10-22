// tests/run_takedown_verification.mjs
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import takedownHandler from '../api/takedown.js';

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
    console.log('--- Starting Takedown API Hardening Verification Tests ---');

    const keyTier2 = 'secret-test-pro-takedown-key';
    const keyTier1 = 'secret-test-tier1-takedown-key';
    const keyNoScope = 'secret-test-noscope-takedown-key';

    process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
        {
            keyId: 'pro-client-tkd',
            tenantId: 'test_brand_owner',
            tier: 2,
            sha256: hash(keyTier2),
            scopes: ['b2b:takedown', 'b2b:scan'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'tier1-client-tkd',
            tenantId: 'test_tier1_corp',
            tier: 1,
            sha256: hash(keyTier1),
            scopes: ['b2b:scan'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'noscope-client-tkd',
            tenantId: 'test_noscope_corp',
            tier: 2,
            sha256: hash(keyNoScope),
            scopes: ['b2b:payguard'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        }
    ]);

    const proHeaders = {
        'x-api-key': keyTier2,
        'x-verifypulse-key-id': 'pro-client-tkd',
        'x-forwarded-for': '127.0.0.1'
    };

    // Test 1: Method Check (GET rejected)
    const res1 = mockRes();
    await takedownHandler({ method: 'GET', headers: {} }, res1);
    assert.equal(res1.statusCode, 405);
    console.log('   ✓ Test 1: Method check verified (405 on GET)');

    // Test 2: Unauthenticated Request
    const res2 = mockRes();
    await takedownHandler({ method: 'POST', headers: {} }, res2);
    assert.equal(res2.statusCode, 401);
    assert.equal(res2.body.error, 'UNAUTHORIZED');
    console.log('   ✓ Test 2: Unauthenticated request rejected (401)');

    // Test 3: Insufficient Scope
    const res3 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: {
            'x-api-key': keyNoScope,
            'x-verifypulse-key-id': 'noscope-client-tkd',
            'x-forwarded-for': '127.0.0.1'
        },
        body: { url: 'https://fake-site.com' }
    }, res3);
    assert.equal(res3.statusCode, 403);
    assert.equal(res3.body.error, 'INSUFFICIENT_SCOPE');
    console.log('   ✓ Test 3: Insufficient scope rejected (403)');

    // Test 4: Tier 1 Client Upgrade Required
    const res4 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: {
            'x-api-key': keyTier1,
            'x-verifypulse-key-id': 'tier1-client-tkd',
            'x-forwarded-for': '127.0.0.1'
        },
        body: { url: 'https://fake-site.com' }
    }, res4);
    assert.equal(res4.statusCode, 403);
    assert.equal(res4.body.error, 'UPGRADE_REQUIRED');
    console.log('   ✓ Test 4: Tier 1 upgrade required enforced (403)');

    // Test 5: Null/Empty Body Safety (Loophole 17)
    const res5 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: proHeaders,
        body: null
    }, res5);
    assert.equal(res5.statusCode, 400);
    assert.equal(res5.body.error, 'MISSING_DATA');
    console.log('   ✓ Test 5: Null body safely returns 400 without crashing');

    // Test 6: SSRF Protection - Loopback IP Blocked (Loophole 17)
    const res6 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: proHeaders,
        body: { url: 'http://127.0.0.1/admin-secret' }
    }, res6);
    assert.equal(res6.statusCode, 400);
    assert.equal(res6.body.error, 'SSRF_BLOCKED');
    console.log('   ✓ Test 6: Loopback IP target blocked by SSRF guard (400)');

    // Test 7: SSRF Protection - Cloud Metadata IP Blocked (Loophole 17)
    const res7 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: proHeaders,
        body: { url: 'http://169.254.169.254/latest/meta-data' }
    }, res7);
    assert.equal(res7.statusCode, 400);
    assert.equal(res7.body.error, 'SSRF_BLOCKED');
    console.log('   ✓ Test 7: Cloud metadata target blocked by SSRF guard (400)');

    // Test 8: Protocol Validation - Non-HTTP blocked (Loophole 17)
    const res8 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: proHeaders,
        body: { url: 'file:///etc/passwd' }
    }, res8);
    assert.equal(res8.statusCode, 400);
    assert.equal(res8.body.error, 'INVALID_URL');
    console.log('   ✓ Test 8: Non-HTTP scheme blocked (400)');

    // Test 9: Valid Public Phishing URL Takedown Notice Generation
    const res9 = mockRes();
    await takedownHandler({
        method: 'POST',
        headers: proHeaders,
        body: {
            url: 'https://fake-sbi-secure-portal.com/login.html',
            brandName: 'State Bank of India',
            autoDispatch: false
        }
    }, res9);
    assert.equal(res9.statusCode, 200);
    assert.equal(res9.body.domain, 'fake-sbi-secure-portal.com');
    assert.equal(res9.body.status, 'DRAFT_READY_FOR_LEGAL_REVIEW');
    assert.ok(res9.body.evidenceDossier?.evidenceDigestSha256);
    console.log('   ✓ Test 9: Valid public phishing takedown generated cleanly (200)');

    console.log('--- ALL TAKEDOWN VERIFICATION TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
