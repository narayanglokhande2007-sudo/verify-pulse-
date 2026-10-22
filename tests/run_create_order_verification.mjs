// tests/run_create_order_verification.mjs
import assert from 'node:assert/strict';
import handler from '../api/create_order.js';

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
    console.log('--- Starting Create Order API Hardening Tests ---');

    // Test 1: Method Not Allowed
    const res1 = mockRes();
    await handler({ method: 'GET', headers: {} }, res1);
    assert.equal(res1.statusCode, 405, 'GET method must return 405');
    assert.equal(res1.body.error, 'Method not allowed');
    console.log('   ✓ Test 1: Method check verified (405 on GET)');

    // Test 2: Null/Empty Body Defense
    const res2 = mockRes();
    await handler({ method: 'POST', headers: { 'x-forwarded-for': '127.0.0.1' }, body: null }, res2);
    assert.equal(res2.statusCode, 400, 'Null body must safely return 400 without crashing');
    assert.equal(res2.body.error, 'Invalid Tier Selected');
    console.log('   ✓ Test 2: Null body safety verified (No crash, safe 400)');

    // Test 3: Invalid Tier Selection
    const res3 = mockRes();
    await handler({ 
        method: 'POST', 
        headers: { 'x-forwarded-for': '127.0.0.1' }, 
        body: { tierId: 'hacker_free_tier', email: 'user@test.com' } 
    }, res3);
    assert.equal(res3.statusCode, 400);
    assert.equal(res3.body.error, 'Invalid Tier Selected');
    console.log('   ✓ Test 3: Invalid tier properly rejected (400)');

    // Test 4: Invalid Email Format
    const res4 = mockRes();
    await handler({ 
        method: 'POST', 
        headers: { 'x-forwarded-for': '127.0.0.1' }, 
        body: { tierId: 'standard', email: 'not-an-email' } 
    }, res4);
    assert.equal(res4.statusCode, 400);
    assert.equal(res4.body.error, 'Invalid Email Format');
    console.log('   ✓ Test 4: Malformed email rejected (400)');

    // Test 5: Successful Order Creation (Standard Tier)
    process.env.NODE_ENV = 'test';
    const res5 = mockRes();
    await handler({ 
        method: 'POST', 
        headers: { 'x-forwarded-for': '127.0.0.1' }, 
        body: { tierId: 'standard', email: 'founder@startup.in', company: 'Startup Tech' } 
    }, res5);
    assert.equal(res5.statusCode, 200);
    assert.equal(res5.body.amount, 2500000);
    assert.equal(res5.body.currency, 'INR');
    assert.equal(res5.body.tierName, 'Tier 1: Standard');
    assert.ok(res5.body.id.startsWith('order_'));
    console.log('   ✓ Test 5: Tier 1 Standard order created cleanly (₹25,000)');

    // Test 6: Successful Order Creation (Pro Tier)
    const res6 = mockRes();
    await handler({ 
        method: 'POST', 
        headers: { 'x-forwarded-for': '127.0.0.1' }, 
        body: { tierId: 'pro', email: 'cto@enterprise.in', company: 'Enterprise Fin' } 
    }, res6);
    assert.equal(res6.statusCode, 200);
    assert.equal(res6.body.amount, 9900000);
    assert.equal(res6.body.currency, 'INR');
    assert.equal(res6.body.tierName, 'Tier 2: Pro');
    assert.ok(res6.body.id.startsWith('order_'));
    console.log('   ✓ Test 6: Tier 2 Pro order created cleanly (₹99,000)');

    // Test 7: Rate Limiting Enforcement
    let rateLimited = false;
    for (let i = 0; i < 20; i++) {
        const resLoop = mockRes();
        await handler({ 
            method: 'POST', 
            headers: { 'x-forwarded-for': '192.168.1.100' }, 
            body: { tierId: 'standard' } 
        }, resLoop);
        if (resLoop.statusCode === 429) {
            rateLimited = true;
            break;
        }
    }
    assert.ok(rateLimited, 'Excessive rapid requests from single IP must trigger 429 rate limit');
    console.log('   ✓ Test 7: Rate limiter verified (429 Rate Limited)');

    console.log('--- ALL CREATE ORDER TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
