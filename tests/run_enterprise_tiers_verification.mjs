// tests/run_enterprise_tiers_verification.mjs
// Comprehensive verification test suite for VerifyPulse Enterprise Tiers 1, 2, and 3.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { checkB2BQuota } from '../lib/quota_manager.js';
import { validateB2bApiKey } from '../lib/security_controls.js';
import { querySyndicateGraph } from '../lib/syndicate_graph.js';
import { applyTenantCustomRules } from '../lib/tenant_custom_rules.js';
import { recordTenantScanTelemetry } from '../lib/audit_events.js';
import { AppShield } from '../sdk/app-shield/index.js';
import dashboardHandler from '../api/dashboard.js';
import payguardHandler from '../api/payguard.js';
import takedownHandler from '../api/takedown.js';
import zerodayHandler from '../api/zeroday.js';
import brandProtectionHandler from '../api/brand_protection_api.js';
import verifyHandler from '../api/verify.js';
import billingHandler from '../api/billing.js';

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function mockResponse() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return body; }
  };
}

async function runTests() {
  console.log('--- Starting VerifyPulse Enterprise Tiers Verification ---');

  // TEST 1: Tier 1, 2, 3 Quota Capacities & Dual Metering
  console.log('1. Testing Quota Manager Capacities...');
  const t1 = await checkB2BQuota('test-t1', 1);
  assert.equal(t1.limit, 250000, 'Tier 1 total limit must be 250,000 as advertised');
  assert.equal(t1.aiLimit, 5000, 'Tier 1 AI limit must be 5,000 as advertised');
  assert.equal(t1.allowed, true);

  const t2 = await checkB2BQuota('test-t2', 2);
  assert.equal(t2.limit, 1000000, 'Tier 2 total limit must be 1,000,000 as advertised');
  assert.equal(t2.aiLimit, 25000, 'Tier 2 AI limit must be 25,000 as advertised');
  assert.equal(t2.allowed, true);

  const t3 = await checkB2BQuota('test-t3', 3);
  assert.equal(t3.limit, 5000000, 'Tier 3 total limit must be 5,000,000 as advertised');
  assert.equal(t3.aiLimit, 50000, 'Tier 3 AI limit must be 50,000 as advertised');
  assert.equal(t3.allowed, true);

  // Dual Metering AI scan check
  const t1Ai = await checkB2BQuota('test-t1-ai', 1, { isAiScan: true });
  assert.equal(t1Ai.aiUsed, 1);
  console.log('   ✓ Quota capacities verified (2.5L, 10L, 50L) with dual metering.');

  // TEST 2: B2B Auth Contract Harmonization
  console.log('2. Testing B2B Auth Contract Harmonization...');
  const keyTier2 = 'secret-pro-key';
  process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
    {
      keyId: 'pro-client-01',
      tenantId: 'pro-corp',
      tier: 2,
      sha256: hash(keyTier2),
      scopes: ['b2b:scan', 'b2b:zeroday', 'b2b:payguard', 'b2b:takedown'],
      expiresAt: '2099-01-01T00:00:00.000Z',
      status: 'active'
    }
  ]);

  const reqTier2 = {
    headers: {
      'x-api-key': keyTier2,
      'x-verifypulse-key-id': 'pro-client-01'
    }
  };

  const authTier2 = validateB2bApiKey(reqTier2);
  assert.equal(authTier2.allowed, true);
  assert.equal(authTier2.valid, true, 'authResult.valid must match allowed for backwards compatibility');
  assert.equal(authTier2.tier, 2, 'authResult.tier must correctly report 2');
  console.log('   ✓ B2B auth contract returns both allowed, valid, and correct tier.');

  // TEST 3: Dashboard API Dynamic Tier & Real Metrics
  console.log('3. Testing Co-Pilot Dashboard API with Real Telemetry...');
  recordTenantScanTelemetry('pro-corp', { isThreat: true, valueSaved: 20000 });
  const dashRes = mockResponse();
  await dashboardHandler({ method: 'GET', headers: reqTier2.headers }, dashRes);
  assert.equal(dashRes.statusCode, 200);
  assert.equal(dashRes.body.tier, 2, 'Dashboard must dynamically report tenant tier');
  assert.equal(dashRes.body.usage.total_scans_limit, 1000000);
  assert.equal(dashRes.body.usage.ai_scans_limit, 25000);
  assert.equal(dashRes.body.metrics.telemetry_source, 'LIVE_AUDIT_STREAM');
  const usedBefore = dashRes.body.usage.total_scans_used;
  const dashRes2 = mockResponse();
  await dashboardHandler({ method: 'GET', headers: reqTier2.headers }, dashRes2);
  assert.equal(dashRes2.body.usage.total_scans_used, usedBefore, 'Dashboard view must NOT increment scan quota (peek mode)');
  console.log('   ✓ Dashboard reports dynamic Tier 2 and real live audit telemetry (peek mode verified).');

  // TEST 4: Scam Syndicate Graph Engine & PayGuard
  console.log('4. Testing Scam Syndicate Graph & PayGuard...');
  const graphQuery = await querySyndicateGraph({ upi: 'cbi.cybercell.verify@ybl' });
  assert.equal(graphQuery.found, true);
  assert.equal(graphQuery.clusterId, 'syn-dl-arrest-01');
  assert.ok(graphQuery.connectedNodes.length > 0);

  const payguardRes = mockResponse();
  await payguardHandler({
    method: 'POST',
    headers: reqTier2.headers,
    body: {
      transactionId: 'txn-99128',
      amount: 49999,
      receiverUpi: 'cbi.cybercell.verify@ybl'
    }
  }, payguardRes);

  assert.equal(payguardRes.statusCode, 200);
  assert.equal(payguardRes.body.action, 'BLOCK', 'PayGuard must block known syndicate mule accounts');
  assert.ok(payguardRes.body.flags.includes('SCAM_SYNDICATE_GRAPH_MATCH'));
  assert.equal(payguardRes.body.syndicate.clusterId, 'syn-dl-arrest-01');
  console.log('   ✓ Scam Syndicate Graph successfully blocks clustered mule UPI.');

  // TEST 5: Automated Takedowns Engine with Cryptographic Evidence Dossier
  console.log('5. Testing Automated Takedowns API & Evidence Dossier...');
  const takedownRes = mockResponse();
  await takedownHandler({
    method: 'POST',
    headers: reqTier2.headers,
    body: {
      url: 'https://fake-hdfc-kyc-update.com/login',
      brandName: 'HDFC Bank',
      autoDispatch: true
    }
  }, takedownRes);

  assert.equal(takedownRes.statusCode, 200);
  assert.equal(takedownRes.body.dispatchRequested, true);
  assert.equal(takedownRes.body.autoDispatched, false, 'No delivery receipt must not be reported as dispatched');
  assert.equal(takedownRes.body.status, 'DRAFT_READY_FOR_LEGAL_REVIEW');
  assert.ok(takedownRes.body.trackingId.startsWith('tkd-'));
  assert.ok(takedownRes.body.evidenceDossier);
  assert.ok(takedownRes.body.evidenceDossier.evidenceDigestSha256);
  assert.equal(takedownRes.body.evidenceDossier.protocolStandard, 'RFC 2142 Abuse Mailbox Protocol');
  assert.ok(takedownRes.body.dispatchReceipt);
  assert.equal(takedownRes.body.dispatchReceipt.deliveryStatus, 'NOT_DELIVERED');
  console.log('   ✓ Takedown requests never claim delivery without a successful outbound receipt.');

  // TEST 6: Zero-Day Monitoring Endpoint
  console.log('6. Testing Zero-Day Monitoring API...');
  const zeroDayRes = mockResponse();
  await zerodayHandler({
    method: 'POST',
    headers: reqTier2.headers,
    body: {
      keyword: 'hdfcbank',
      officialDomain: 'hdfcbank.com'
    }
  }, zeroDayRes);

  assert.equal(zeroDayRes.statusCode, 200);
  assert.equal(zeroDayRes.body.keywordMonitor, 'hdfcbank');
  assert.ok(['ACTIVE_ZERO_DAY_MONITORING', 'STANDBY_NEXT_CYCLE'].includes(zeroDayRes.body.status));
  console.log('   ✓ Zero-Day Monitor endpoint responds cleanly without 500 error.');

  // TEST 7: Tenant Custom Rules Engine (Tier 3)
  console.log('7. Testing Tenant Custom Rules Engine...');
  const baseVerdict = { verdict: 'SUSPICIOUS', scamType: 'Unknown', confidence: 60, findings: [] };
  const customVerdict = applyTenantCustomRules(
    'fraudshield',
    3,
    'Visit https://fraudshield-demo.com/verify',
    ['https://fraudshield-demo.com/verify'],
    baseVerdict
  );
  assert.equal(customVerdict.verdict, 'SAFE', 'Tenant whitelist must override false positive');
  assert.equal(customVerdict.scamType, 'Tenant Custom Whitelist');
  console.log('   ✓ Tier 3 Custom Rules properly applied.');

  // TEST 8: App-Shield Client SDK
  console.log('8. Testing App-Shield Client SDK RASP Interceptor...');
  const shield = new AppShield();
  const safeIntent = await shield.interceptPaymentIntent({ amount: 500 }, { isMediaProjectionActive: false });
  assert.equal(safeIntent.allowed, true);

  const blockedIntent = await shield.interceptPaymentIntent({ amount: 500 }, { isMediaProjectionActive: true });
  assert.equal(blockedIntent.allowed, false);
  assert.equal(blockedIntent.reason, 'UNSAFE_ENVIRONMENT');
  assert.equal(blockedIntent.details.screenSharingDetected, true);
  console.log('   ✓ App-Shield RASP successfully intercepts dirty screen-sharing environment.');

  // TEST 9: Tier 3 Continuous Brand Portfolio Monitoring (Multi-Keyword)
  console.log('9. Testing Tier 3 Continuous Brand Portfolio Recon...');
  const keyTier3 = 'secret-ultra-key';
  process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
    ...JSON.parse(process.env.VERIFYPULSE_B2B_KEY_REGISTRY),
    {
      keyId: 'ultra-client-01',
      tenantId: 'fraudshield',
      tier: 3,
      sha256: hash(keyTier3),
      scopes: ['b2b:scan', 'b2b:zeroday', 'b2b:payguard', 'b2b:takedown', 'b2b:continuous_monitor'],
      expiresAt: '2099-01-01T00:00:00.000Z',
      status: 'active'
    }
  ]);
  const reqTier3 = {
    headers: {
      'x-api-key': keyTier3,
      'x-verifypulse-key-id': 'ultra-client-01'
    }
  };
  const batchRes = mockResponse();
  await zerodayHandler({
    method: 'POST',
    headers: reqTier3.headers,
    body: {
      keywords: ['banksecure', 'hdfcbank'],
      officialDomains: ['banksecure.com', 'hdfcbank.com']
    }
  }, batchRes);
  assert.equal(batchRes.statusCode, 200);
  assert.ok(batchRes.body.totalKeywordsMonitored >= 2);
  console.log('   ✓ Tier 3 Continuous Brand Portfolio Recon verified.');

  // TEST 10: Brand Protection Default Handler (Vercel Serverless Route)
  console.log('10. Testing Brand Protection Default Handler Router...');
  const bpRes = mockResponse();
  await brandProtectionHandler({ method: 'GET', url: '/api/brand_protection_api?bank_id=hdfc', query: { bank_id: 'hdfc' } }, bpRes);
  assert.equal(bpRes.statusCode, 200);
  console.log('   ✓ Brand Protection default export router handles requests cleanly.');

  // TEST 11: Automated Cron Brand Recon Trigger
  console.log('11. Testing Automated Cron Brand Recon...');
  const cronRes = mockResponse();
  await zerodayHandler({ method: 'GET', query: { cron: 'continuous_brand_scan' } }, cronRes);
  assert.equal(cronRes.statusCode, 200);
  assert.equal(cronRes.body.status, 'CRON_CONTINUOUS_SCAN_COMPLETED');
  console.log('   ✓ Automated continuous cron schedule triggers background recon.');

  // TEST 12: Tier 3 Custom Rules Live in Master Verification Flow
  console.log('12. Testing Tier 3 Custom Rules in Master Engine (/api/verify)...');
  const verifyRes = mockResponse();
  await verifyHandler({
    method: 'POST',
    headers: reqTier3.headers,
    body: {
      text: 'Visit https://fraudshield-demo.com/verify to check account',
      checkType: 'unified',
      b2bContext: {
        tenantId: 'fraudshield',
        tier: 3,
        keyId: 'ultra-client-01'
      }
    }
  }, verifyRes);
  assert.equal(verifyRes.statusCode, 200);
  assert.equal(verifyRes.body.verdict, 'SAFE', 'Master /api/verify engine must apply Tier 3 tenant custom whitelist');
  assert.equal(verifyRes.body.tenantCustomRulesApplied, true);
  console.log('   ✓ Master verification engine applies Tier 3 tenant custom whitelist.');

  // TEST 13: SaaS Order Creation & Unified Billing Gateway (/api/billing)
  console.log('13. Testing SaaS Subscription Order Creation & Billing Gateway (/api/billing)...');
  const orderRes = mockResponse();
  await billingHandler({
    method: 'POST',
    query: { action: 'create_order' },
    headers: { 'x-forwarded-for': '127.0.0.1' },
    body: { tierId: 'standard', email: 'enterprise@corp.in', company: 'Corp' }
  }, orderRes);
  assert.equal(orderRes.statusCode, 200);
  assert.equal(orderRes.body.amount, 2500000);
  assert.equal(orderRes.body.tierName, 'Tier 1: Standard');
  console.log('   ✓ Unified Billing Gateway handles subscription checkout safely.');

  console.log('--- ALL ENTERPRISE TIERS VERIFIED AND PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
  console.error('FAILED Verification:', err);
  process.exit(1);
});
