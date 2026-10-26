// tests/enterprise_gauntlet_450_billing.mjs
// ============================================================================
// VERIFYPULSE HARDEST ADVERSARIAL GAUNTLET: FEATURE #11
// Module: B2B Billing, Webhooks & Automated Invoicing Rail
// Target: Order Pricing, Webhook HMAC Verification, API Key Provisioning
// Total Cases: 450 Extreme Adversarial Scenarios
// ============================================================================

import { performance } from 'perf_hooks';
import crypto from 'crypto';
import handleCreateOrder from '../lib/billing_order.js';
import handleWebhook, { provisionRedisQuota } from '../lib/billing_webhook.js';
import billingGateway from '../api/billing.js';

console.log('='.repeat(72));
console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #11       ');
console.log('   Module: B2B Billing, Webhooks & Automated Invoicing Rail             ');
console.log('   Target: Order Integrity, HMAC Signatures, Quota Provisioning         ');
console.log('   Total Cases: 450 Extreme Adversarial Scenarios                       ');
console.log('='.repeat(72));

let totalPassed = 0;
let totalFailed = 0;
const failures = [];
const latencies = [];

function recordTest(id, category, passed, error = null, latencyMs = 0) {
  latencies.push(latencyMs);
  if (passed) {
    totalPassed++;
  } else {
    totalFailed++;
    failures.push({ id, category, error: error?.message || String(error) });
  }
}

function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    bodyData: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(key, val) {
      this.headers[key.toLowerCase()] = val;
      return this;
    },
    json(data) {
      this.bodyData = data;
      return this;
    },
    send(data) {
      this.bodyData = data;
      return this;
    }
  };
  return res;
}

// ============================================================================
// CATEGORY 1: Order Initialization & Input Validation (90 Cases)
// Objective: Strict tier amounts (25k & 99k), reject client price tampering.
// ============================================================================
console.log('\n--- [Category 1/5] Order Initialization & Input Validation (90 Cases) ---');

// 1.1: Valid Tier Selections (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `ORDER-VALID-TIER-${i + 1}`;
  const t0 = performance.now();
  const tierId = (i % 2 === 0) ? 'standard' : 'pro';
  const expectedAmount = (tierId === 'standard') ? 2500000 : 9900000;
  const req = {
    method: 'POST',
    body: { tierId, email: `corp${i}@enterprise.co.in`, company: `Enterprise Corp ${i}` },
    headers: { 'x-forwarded-for': `10.50.${i}.1` }
  };
  const res = createMockRes();

  try {
    await handleCreateOrder(req, res);
    const passed = res.statusCode === 200 && res.bodyData?.amount === expectedAmount;
    recordTest(testId, 'Valid Tier Order Creation', passed, passed ? null : new Error(`Expected status 200, amount ${expectedAmount}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Valid Tier Order Creation', false, err, performance.now() - t0);
  }
}

// 1.2: Invalid Tier Selections & Client Tampering (30 cases)
const BAD_TIERS = ['free', 'enterprise_unlimited', 'hacked_tier', '', null, 999, 'zero_cost', 'discount_vip'];
for (let i = 0; i < 30; i++) {
  const testId = `ORDER-INVALID-TIER-${i + 1}`;
  const t0 = performance.now();
  const badTier = BAD_TIERS[i % BAD_TIERS.length];
  const req = {
    method: 'POST',
    body: { tierId: badTier, email: `test${i}@test.com` },
    headers: { 'x-forwarded-for': `10.51.${i}.1` }
  };
  const res = createMockRes();

  try {
    await handleCreateOrder(req, res);
    const passed = res.statusCode === 400 && res.bodyData?.error === 'Invalid Tier Selected';
    recordTest(testId, 'Invalid Tier Rejection', passed, passed ? null : new Error(`Invalid tier ${badTier} was not rejected with 400`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Invalid Tier Rejection', false, err, performance.now() - t0);
  }
}

// 1.3: Email Format Validation (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `ORDER-EMAIL-VALID-${i + 1}`;
  const t0 = performance.now();
  const isInvalid = (i % 2 === 0);
  const email = isInvalid ? `not_an_email_${i}` : `billing.officer${i}@bank.co.in`;
  const req = {
    method: 'POST',
    body: { tierId: 'standard', email, company: 'Safe Corp' },
    headers: { 'x-forwarded-for': `10.52.${i}.1` }
  };
  const res = createMockRes();

  try {
    await handleCreateOrder(req, res);
    const passed = isInvalid
      ? (res.statusCode === 400 && res.bodyData?.error === 'Invalid Email Format')
      : (res.statusCode === 200);
    recordTest(testId, 'Order Email Format Validation', passed, passed ? null : new Error(`Email validation failed for ${email}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Order Email Format Validation', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 2: HTTP Verb Defense & Rate Limiting (90 Cases)
// Objective: Reject non-POST with 405, throttle after 15 requests per minute.
// ============================================================================
console.log('\n--- [Category 2/5] HTTP Verb Defense & Rate Limiting (90 Cases) ---');

// 2.1: HTTP Method Enforcement (30 cases)
const DISALLOWED_METHODS = ['GET', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
for (let i = 0; i < 30; i++) {
  const testId = `HTTP-VERB-405-${i + 1}`;
  const t0 = performance.now();
  const method = DISALLOWED_METHODS[i % DISALLOWED_METHODS.length];
  const req = { method, body: {}, headers: {} };
  const res = createMockRes();

  try {
    await handleCreateOrder(req, res);
    const passed = res.statusCode === 405;
    recordTest(testId, 'Method Not Allowed 405', passed, passed ? null : new Error(`Method ${method} returned ${res.statusCode}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Method Not Allowed 405', false, err, performance.now() - t0);
  }
}

// 2.2: Order Creation Rate Limiting (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `ORDER-RATE-LIMIT-${i + 1}`;
  const t0 = performance.now();
  const ip = `172.30.99.${i + 1}`;
  try {
    let hitRateLimit = false;
    // Make 16 requests from the same IP
    for (let reqCount = 0; reqCount < 16; reqCount++) {
      const req = {
        method: 'POST',
        body: { tierId: 'standard' },
        headers: { 'x-forwarded-for': ip }
      };
      const res = createMockRes();
      await handleCreateOrder(req, res);
      if (res.statusCode === 429 && res.bodyData?.error === 'RATE_LIMITED') {
        hitRateLimit = true;
        break;
      }
    }
    recordTest(testId, 'Order Creation Rate Limiting', hitRateLimit, hitRateLimit ? null : new Error(`Rate limit did not trigger after 15 requests`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Order Creation Rate Limiting', false, err, performance.now() - t0);
  }
}

// 2.3: Rate Limit Headers Verification (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `RATE-HEADERS-${i + 1}`;
  const t0 = performance.now();
  const ip = `172.31.50.${i + 1}`;
  const req = {
    method: 'POST',
    body: { tierId: 'standard' },
    headers: { 'x-forwarded-for': ip }
  };
  const res = createMockRes();

  try {
    await handleCreateOrder(req, res);
    const hasLimit = res.headers['x-ratelimit-limit'] !== undefined;
    const hasRemaining = res.headers['x-ratelimit-remaining'] !== undefined;
    const passed = hasLimit && hasRemaining;
    recordTest(testId, 'Rate Limit Headers', passed, passed ? null : new Error(`Missing rate limit headers`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Rate Limit Headers', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 3: Webhook Cryptographic HMAC-SHA256 Verification (90 Cases)
// Objective: Verify timing-safe HMAC check, reject tampered or forged signatures.
// ============================================================================
console.log('\n--- [Category 3/5] Webhook Cryptographic HMAC Verification (90 Cases) ---');

const WEBHOOK_SECRET = 'whsec_enterprise_razorpay_secret_9876543210';
process.env.RAZORPAY_WEBHOOK_SECRET = WEBHOOK_SECRET;

// 3.1: Legitimate Signed Webhooks (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `WEBHOOK-VALID-SIG-${i + 1}`;
  const t0 = performance.now();
  const payload = {
    event: 'payment.captured',
    payload: {
      payment: {
        entity: {
          id: `pay_${Date.now()}_${i}`,
          amount: 2500000,
          notes: { tier: 'standard', email: `client${i}@nbfc.com`, company: `NBFC ${i}` }
        }
      }
    }
  };
  const bodyString = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(bodyString).digest('hex');

  const req = {
    method: 'POST',
    body: payload,
    headers: { 'x-razorpay-signature': signature }
  };
  const res = createMockRes();

  try {
    await handleWebhook(req, res);
    const passed = res.statusCode === 200 && res.bodyData?.key_provisioned === true;
    recordTest(testId, 'Valid Webhook Signature & Provisioning', passed, passed ? null : new Error(`Expected 200 with key_provisioned=true`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Valid Webhook Signature & Provisioning', false, err, performance.now() - t0);
  }
}

// 3.2: Tampered Payload or Forged Signature (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `WEBHOOK-FORGED-SIG-${i + 1}`;
  const t0 = performance.now();
  const payload = { event: 'payment.captured', payload: { payment: { entity: { amount: 9900000 } } } };
  const forgedSignature = crypto.createHmac('sha256', 'WRONG_SECRET').update(JSON.stringify(payload)).digest('hex');

  const req = {
    method: 'POST',
    body: payload,
    headers: { 'x-razorpay-signature': forgedSignature }
  };
  const res = createMockRes();

  try {
    await handleWebhook(req, res);
    const passed = res.statusCode === 400 && res.bodyData?.error?.includes('Invalid Signature');
    recordTest(testId, 'Forged Signature Rejection', passed, passed ? null : new Error(`Forged signature was accepted!`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Forged Signature Rejection', false, err, performance.now() - t0);
  }
}

// 3.3: Missing or Truncated Signatures (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `WEBHOOK-BAD-SIG-FORMAT-${i + 1}`;
  const t0 = performance.now();
  const badSig = [null, undefined, '', 'abc123short', 'deadbeef'][i % 5];
  const req = {
    method: 'POST',
    body: { event: 'order.paid' },
    headers: { 'x-razorpay-signature': badSig }
  };
  const res = createMockRes();

  try {
    await handleWebhook(req, res);
    const passed = res.statusCode === 400;
    recordTest(testId, 'Bad Signature Format Rejection', passed, passed ? null : new Error(`Bad signature returned ${res.statusCode}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Bad Signature Format Rejection', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 4: Automated API Key Provisioning & Quota Binding (90 Cases)
// Objective: Pro tier -> 1M quota; Standard tier -> 250k quota; vp_live_ format.
// ============================================================================
console.log('\n--- [Category 4/5] Automated API Key Provisioning & Quota Binding (90 Cases) ---');

// 4.1: Standard Tier Quota Provisioning (250,000) (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `PROVISION-STANDARD-${i + 1}`;
  const t0 = performance.now();
  const apiKey = `vp_live_std_test_${i}_${Date.now()}`;
  try {
    await provisionRedisQuota(apiKey, 250000, { tier: 'standard' });
    const store = globalThis.__verifyPulseQuotaStore;
    const entry = store.get(`quota:${apiKey}`);
    const passed = entry?.limit === 250000 && entry?.notes?.tier === 'standard';
    recordTest(testId, 'Standard Tier Quota Provisioning', passed, passed ? null : new Error(`Provisioning failed for standard tier`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Standard Tier Quota Provisioning', false, err, performance.now() - t0);
  }
}

// 4.2: Pro Tier Quota Provisioning (1,000,000) (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `PROVISION-PRO-${i + 1}`;
  const t0 = performance.now();
  const apiKey = `vp_live_pro_test_${i}_${Date.now()}`;
  try {
    await provisionRedisQuota(apiKey, 1000000, { tier: 'pro' });
    const store = globalThis.__verifyPulseQuotaStore;
    const entry = store.get(`quota:${apiKey}`);
    const passed = entry?.limit === 1000000 && entry?.notes?.tier === 'pro';
    recordTest(testId, 'Pro Tier Quota Provisioning', passed, passed ? null : new Error(`Provisioning failed for pro tier`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Pro Tier Quota Provisioning', false, err, performance.now() - t0);
  }
}

// 4.3: Unhandled Event Graceful Ignorance (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `WEBHOOK-UNHANDLED-EVENT-${i + 1}`;
  const t0 = performance.now();
  const unhandledEvent = ['payment.failed', 'refund.processed', 'subscription.cancelled'][i % 3];
  const payload = { event: unhandledEvent, payload: {} };
  const bodyString = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(bodyString).digest('hex');

  const req = { method: 'POST', body: payload, headers: { 'x-razorpay-signature': signature } };
  const res = createMockRes();

  try {
    await handleWebhook(req, res);
    const passed = res.statusCode === 200 && res.bodyData?.status === 'ignored';
    recordTest(testId, 'Unhandled Webhook Event Ignorance', passed, passed ? null : new Error(`Expected { status: 'ignored' }`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Unhandled Webhook Event Ignorance', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 5: Unified Billing Gateway Dispatcher (90 Cases)
// Objective: Test api/billing.js dispatch routing (webhook vs order creation).
// ============================================================================
console.log('\n--- [Category 5/5] Unified Billing Gateway Dispatcher (90 Cases) ---');

// 5.1: Dispatch by query action=webhook (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `GATEWAY-DISPATCH-QUERY-${i + 1}`;
  const t0 = performance.now();
  const payload = { event: 'payment.captured', payload: { payment: { entity: { notes: { tier: 'pro' } } } } };
  const bodyString = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(bodyString).digest('hex');

  const req = {
    method: 'POST',
    query: { action: 'webhook' },
    body: payload,
    headers: { 'x-razorpay-signature': signature }
  };
  const res = createMockRes();

  try {
    await billingGateway(req, res);
    const passed = res.statusCode === 200 && res.bodyData?.key_provisioned === true;
    recordTest(testId, 'Gateway Query Action Webhook Dispatch', passed, passed ? null : new Error(`Failed to route webhook via query`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Gateway Query Action Webhook Dispatch', false, err, performance.now() - t0);
  }
}

// 5.2: Dispatch by signature header detection (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `GATEWAY-DISPATCH-HEADER-${i + 1}`;
  const t0 = performance.now();
  const payload = { event: 'payment.captured', payload: { payment: { entity: { notes: { tier: 'standard' } } } } };
  const bodyString = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(bodyString).digest('hex');

  const req = {
    method: 'POST',
    body: payload,
    headers: { 'x-razorpay-signature': signature }
  };
  const res = createMockRes();

  try {
    await billingGateway(req, res);
    const passed = res.statusCode === 200 && res.bodyData?.key_provisioned === true;
    recordTest(testId, 'Gateway Header-Based Webhook Dispatch', passed, passed ? null : new Error(`Failed to route webhook via header`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Gateway Header-Based Webhook Dispatch', false, err, performance.now() - t0);
  }
}

// 5.3: Dispatch to Order Creation by Default (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `GATEWAY-DISPATCH-ORDER-${i + 1}`;
  const t0 = performance.now();
  const req = {
    method: 'POST',
    body: { tierId: 'standard', email: `test${i}@gateway.com` },
    headers: { 'x-forwarded-for': `10.90.${i}.1` }
  };
  const res = createMockRes();

  try {
    await billingGateway(req, res);
    const passed = res.statusCode === 200 && res.bodyData?.amount === 2500000;
    recordTest(testId, 'Gateway Order Dispatch Default', passed, passed ? null : new Error(`Failed to route order creation`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Gateway Order Dispatch Default', false, err, performance.now() - t0);
  }
}

// Clean up env
delete process.env.RAZORPAY_WEBHOOK_SECRET;

// ============================================================================
// FEATURE #11 HARDEST GAUNTLET SUMMARY AUDIT METRICS
// ============================================================================
console.log('\n' + '='.repeat(72));
console.log('   FEATURE #11 HARDEST GAUNTLET SUMMARY AUDIT METRICS                   ');
console.log('='.repeat(72));
console.log(`Total Cases Tested:      ${totalPassed + totalFailed}`);
console.log(`Total Passed:            ${totalPassed} ${totalFailed === 0 ? '✅' : '⚠️'}`);
console.log(`Total Failed:            ${totalFailed} ${totalFailed === 0 ? '✅' : '❌'}`);
console.log(`Success Rate:            ${((totalPassed / (totalPassed + totalFailed)) * 100).toFixed(2)}%`);

const avgLatency = latencies.reduce((a, b) => a + b, 0) / (latencies.length || 1);
const maxLatency = Math.max(...latencies, 0);
const minLatency = Math.min(...latencies, 0);

console.log('\n--- LATENCY BENCHMARK ---');
console.log(`Min Latency: ${minLatency.toFixed(3)} ms | Avg Latency: ${avgLatency.toFixed(3)} ms | Max Latency: ${maxLatency.toFixed(3)} ms`);

if (failures.length > 0) {
  console.log(`\n❌ FAILURES BREAKDOWN (${failures.length} Failures Exposed):`);
  const catCounts = {};
  for (const f of failures) catCounts[f.category] = (catCounts[f.category] || 0) + 1;
  for (const [cat, cnt] of Object.entries(catCounts)) {
    console.log(`  - ${cat}: ${cnt} failures`);
  }
  console.log('\nSample Failed Cases:');
  for (const f of failures.slice(0, 10)) {
    console.log(`  [${f.id}] (${f.category}): ${f.error}`);
  }
  console.log('='.repeat(72));
  process.exit(1);
} else {
  console.log('\n🎉 ALL 450 HARDEST TEST CASES PASSED!');
  console.log('='.repeat(72));
  process.exit(0);
}
