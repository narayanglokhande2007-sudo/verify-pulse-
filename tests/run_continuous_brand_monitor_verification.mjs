// tests/run_continuous_brand_monitor_verification.mjs
// Verification suite for Loophole 18: Multi-keyword Brand Monitor & Zero-Day Endpoint Hardening

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { executeContinuousBrandScan, registerTenantBrandKeywords, getRegisteredTenantBrandKeywords } from '../lib/continuous_brand_monitor.js';
import zerodayHandler from '../api/zeroday.js';

function hash(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function mockRes() {
    return {
        statusCode: null,
        body: null,
        headers: {},
        setHeader(name, val) { this.headers[name] = val; },
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return body; }
    };
}

async function runTests() {
    console.log('--- Starting Continuous Brand Monitor & Zero-Day Hardening Verification Tests ---');

    // 1. Brand Monitor Engine Tests
    console.log('1. Testing executeContinuousBrandScan null and defensive handling...');
    const emptyScan = await executeContinuousBrandScan();
    assert.equal(emptyScan.status, 'NO_KEYWORDS_REGISTERED');
    assert.equal(emptyScan.totalKeywordsMonitored, 0);
    console.log('   ✓ Empty scan call returns NO_KEYWORDS_REGISTERED without crashing');

    const invalidScan = await executeContinuousBrandScan({
        tenantId: null,
        keywords: null,
        officialDomains: null
    });
    assert.equal(invalidScan.status, 'NO_KEYWORDS_REGISTERED');
    console.log('   ✓ Null inputs handled safely without throwing TypeError');

    // 2. Keyword Registration Tests
    console.log('2. Testing registerTenantBrandKeywords robustness...');
    const nullTenant = registerTenantBrandKeywords(null, ['test']);
    assert.deepEqual(nullTenant, []);
    console.log('   ✓ Null tenantId safely returns empty array');

    const nullKeywords = registerTenantBrandKeywords('demo_corp', null);
    assert.ok(Array.isArray(nullKeywords));
    console.log('   ✓ Null newKeywords handled gracefully');

    const stringKeyword = registerTenantBrandKeywords('demo_corp', 'single_brand_kw');
    assert.ok(stringKeyword.includes('single_brand_kw'));
    console.log('   ✓ Single string keyword correctly converted and registered');

    const registeredList = getRegisteredTenantBrandKeywords('demo_corp');
    assert.ok(registeredList.includes('single_brand_kw'));
    console.log('   ✓ getRegisteredTenantBrandKeywords retrieved registered keywords');

    // 3. API Key & Auth Setup for /api/zeroday tests
    const keyTier1 = 'test-key-zeroday-tier1';
    const keyTier2 = 'test-key-zeroday-tier2';
    const keyTier3 = 'test-key-zeroday-tier3';
    const keyNoScope = 'test-key-zeroday-noscope';

    process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
        {
            keyId: 'client-t1',
            tenantId: 'tier1-corp',
            tier: 1,
            sha256: hash(keyTier1),
            scopes: ['b2b:scan', 'b2b:zeroday'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'client-t2',
            tenantId: 'tier2-corp',
            tier: 2,
            sha256: hash(keyTier2),
            scopes: ['b2b:scan', 'b2b:zeroday'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'client-t3',
            tenantId: 'tier3-corp',
            tier: 3,
            sha256: hash(keyTier3),
            scopes: ['b2b:scan', 'b2b:zeroday'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            keyId: 'client-noscope',
            tenantId: 'noscope-corp',
            tier: 2,
            sha256: hash(keyNoScope),
            scopes: ['b2b:payguard'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        }
    ]);

    const tier2Headers = {
        'x-api-key': keyTier2,
        'x-verifypulse-key-id': 'client-t2'
    };
    const tier3Headers = {
        'x-api-key': keyTier3,
        'x-verifypulse-key-id': 'client-t3'
    };

    // Test 3: Method check (405 on GET)
    console.log('3. Testing HTTP method check...');
    const resMethod = mockRes();
    await zerodayHandler({ method: 'GET', headers: {} }, resMethod);
    assert.equal(resMethod.statusCode, 405);
    console.log('   ✓ GET request rejected with 405');

    // Test 4: Unauthenticated request (401)
    console.log('4. Testing authentication check...');
    const resAuth = mockRes();
    await zerodayHandler({ method: 'POST', headers: {} }, resAuth);
    assert.equal(resAuth.statusCode, 401);
    console.log('   ✓ Unauthenticated request rejected with 401');

    // Test 5: Insufficient Scope check (403)
    console.log('5. Testing scope authorization check...');
    const resScope = mockRes();
    await zerodayHandler({
        method: 'POST',
        headers: { 'x-api-key': keyNoScope, 'x-verifypulse-key-id': 'client-noscope' },
        body: { keyword: 'test' }
    }, resScope);
    assert.equal(resScope.statusCode, 403);
    assert.equal(resScope.body.error, 'INSUFFICIENT_SCOPE');
    console.log('   ✓ Insufficient scope rejected with 403 INSUFFICIENT_SCOPE');

    // Test 6: Tier 1 upgrade required (403)
    console.log('6. Testing tier upgrade enforcement...');
    const resTier1 = mockRes();
    await zerodayHandler({
        method: 'POST',
        headers: { 'x-api-key': keyTier1, 'x-verifypulse-key-id': 'client-t1' },
        body: { keyword: 'test' }
    }, resTier1);
    assert.equal(resTier1.statusCode, 403);
    assert.equal(resTier1.body.error, 'UPGRADE_REQUIRED');
    console.log('   ✓ Tier 1 client rejected with 403 UPGRADE_REQUIRED');

    // Test 7: Null body handling (Loophole 18)
    console.log('7. Testing null body parsing...');
    const resNullBody = mockRes();
    await zerodayHandler({
        method: 'POST',
        headers: tier2Headers,
        body: null
    }, resNullBody);
    assert.equal(resNullBody.statusCode, 400);
    assert.equal(resNullBody.body.error, 'MISSING_DATA');
    console.log('   ✓ Null body safely returns 400 MISSING_DATA without crashing');

    // Test 8: Tier 2 multi-keyword request rejected (exclusive to Tier 3)
    console.log('8. Testing multi-keyword Tier 3 restriction...');
    const resMultiT2 = mockRes();
    await zerodayHandler({
        method: 'POST',
        headers: tier2Headers,
        body: { keywords: ['kw1', 'kw2'] }
    }, resMultiT2);
    assert.equal(resMultiT2.statusCode, 403);
    assert.equal(resMultiT2.body.error, 'UPGRADE_REQUIRED');
    console.log('   ✓ Tier 2 multi-keyword request blocked with 403 UPGRADE_REQUIRED');

    // Test 9: Valid Tier 2 single keyword query responds cleanly
    console.log('9. Testing Tier 2 single keyword zero-day query...');
    const resSingleT2 = mockRes();
    await zerodayHandler({
        method: 'POST',
        headers: tier2Headers,
        body: { keyword: 'fraudshield', officialDomain: 'fraudshield.com' }
    }, resSingleT2);
    assert.equal(resSingleT2.statusCode, 200);
    assert.equal(resSingleT2.body.keywordMonitor, 'fraudshield');
    assert.ok(['ACTIVE_ZERO_DAY_MONITORING', 'STANDBY_NEXT_CYCLE'].includes(resSingleT2.body.status));
    console.log('   ✓ Tier 2 single keyword query returns valid zero-day response (200)');

    console.log('--- ALL CONTINUOUS BRAND MONITOR & ZERO-DAY TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
