// tests/run_dashboard_hardening_verification.mjs
// Verification suite for Dashboard API hardening and multi-format key authentication

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dashboardHandler from '../api/dashboard.js';

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
    console.log('--- Starting Dashboard API Hardening Verification Tests ---');

    // 1. Method check
    console.log('1. Testing HTTP method check (only GET allowed)...');
    const resPost = mockRes();
    await dashboardHandler({ method: 'POST', headers: {} }, resPost);
    assert.equal(resPost.statusCode, 405);
    console.log('   ✓ POST request rejected with 405 Method not allowed');

    // 2. Unauthenticated check
    console.log('2. Testing unauthenticated request rejection...');
    const resAuth = mockRes();
    await dashboardHandler({ method: 'GET', headers: {} }, resAuth);
    assert.equal(resAuth.statusCode, 401);
    console.log('   ✓ Unauthenticated request rejected with 401 UNAUTHORIZED');

    // Setup B2B Registry for tests
    const keySecret = 'secret-client-dash-key';
    const keyId = 'key_dash_client_01';
    process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
        {
            keyId,
            tenantId: 'dashboard_corp',
            tier: 2,
            sha256: hash(keySecret),
            scopes: ['b2b:scan'],
            expiresAt: '2099-01-01T00:00:00.000Z',
            status: 'active'
        }
    ]);

    // 3. Valid standard separate headers
    console.log('3. Testing separate x-api-key and x-verifypulse-key-id headers...');
    const resStd = mockRes();
    await dashboardHandler({
        method: 'GET',
        headers: {
            'x-api-key': keySecret,
            'x-verifypulse-key-id': keyId
        }
    }, resStd);
    assert.equal(resStd.statusCode, 200);
    assert.equal(resStd.body.tenant, 'dashboard_corp');
    assert.equal(resStd.body.tier, 2);
    assert.ok(resStd.body.usage);
    assert.ok(resStd.body.metrics);
    console.log('   ✓ Standard separate headers authenticate successfully (200)');

    // 4. Combined colon-separated format "keyId:apiKey"
    console.log('4. Testing combined "keyId:apiKey" header authentication...');
    const resColon = mockRes();
    await dashboardHandler({
        method: 'GET',
        headers: {
            'x-api-key': `${keyId}:${keySecret}`
        }
    }, resColon);
    assert.equal(resColon.statusCode, 200);
    assert.equal(resColon.body.tenant, 'dashboard_corp');
    console.log('   ✓ Combined "keyId:apiKey" parses and authenticates cleanly (200)');

    // 5. Combined dot-separated format "key_id.apiKey"
    console.log('5. Testing combined "key_id.apiKey" header authentication...');
    const resDot = mockRes();
    await dashboardHandler({
        method: 'GET',
        headers: {
            'x-api-key': `${keyId}.${keySecret}`
        }
    }, resDot);
    assert.equal(resDot.statusCode, 200);
    assert.equal(resDot.body.tenant, 'dashboard_corp');
    console.log('   ✓ Combined "key_id.apiKey" parses and authenticates cleanly (200)');

    console.log('--- ALL DASHBOARD HARDENING TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
