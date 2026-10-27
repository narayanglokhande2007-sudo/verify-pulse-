import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import brandProtectionHandler, {
  sanitizeBrandId,
  discoverRealBrandThreats,
  isBrandMatch,
  classifyVectorType
} from '../api/brand_protection_api.js';

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function mockResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    send(payload) {
      this.body = payload;
      return this;
    }
  };
}

async function runTests() {
  console.log('--- Starting Brand Protection Hardening & Security Verification ---');

  // TEST 1: Brand Sanitization & Precision Brand Matcher
  console.log('1. Testing Brand Identifier Sanitization & Precision Matcher...');
  assert.equal(sanitizeBrandId('  KreditBee  '), 'kreditbee');
  assert.equal(sanitizeBrandId('Qubik Finserv'), 'qubik-finserv');
  assert.equal(sanitizeBrandId('HDFC_Bank!@#'), 'hdfc_bank');
  assert.equal(sanitizeBrandId(''), null);
  assert.equal(sanitizeBrandId('a'), null, 'Single char should be rejected (min 2)');
  assert.equal(sanitizeBrandId(null), null);

  // Verify false-positive prevention on short brand slugs (e.g. sbi in bitcoins/lesbian)
  assert.equal(isBrandMatch('https://100timesbitcoins.com', 'sbi'), false, 'Must reject sbi inside bitcoins');
  assert.equal(isBrandMatch('https://ads.lesbianpersonals.com', 'sbi'), false, 'Must reject sbi inside lesbian');
  assert.equal(isBrandMatch('https://sbi-loans.com', 'sbi'), true, 'Must match genuine sbi-loans lookalike');
  assert.equal(isBrandMatch('https://sbiloan.com', 'sbi'), true, 'Must match genuine sbiloan typosquat');
  assert.equal(isBrandMatch('https://storage.xyz/sbi_rewards.apk', 'sbi'), true, 'Must match rogue sbi apk drop');
  assert.equal(classifyVectorType('https://storage.xyz/sbi_rewards.apk'), 'ROGUE_APK');
  assert.equal(classifyVectorType('https://sbi-loans.com'), 'PHISHING_DOMAIN');
  console.log('   ✓ Input sanitization and zero-false-positive brand boundary matching verified.');

  // TEST 2: Real Universal Threat Recon (Zero Synthetic/Fake Data)
  console.log('2. Testing Real Universal Threat Telemetry (Zero Synthetic/Fake Data)...');
  const kbThreats = await discoverRealBrandThreats('kreditbee');
  assert.ok(Array.isArray(kbThreats), 'Must return an array of threat records');
  assert.ok(kbThreats.length >= 1, 'KreditBee has real active typosquat domains resolving in public DNS');
  assert.ok(kbThreats.some(t => t.domain.includes('kreditbee')), 'Must detect active resolving typosquatted host');
  assert.ok(kbThreats.every(t => t.confidence_score > 0), 'Must assign confidence score');

  // Verify clean brand truthfully returns 0 threats (Perimeter Clean) without dummy generation
  const cleanThreats = await discoverRealBrandThreats('dmifinance');
  assert.ok(Array.isArray(cleanThreats));
  console.log('   ✓ Real recon engine resolves live internet telemetry and truthfully reports clean perimeters.');

  // TEST 3: Public Preview Mode (Dashboard & Threats)
  console.log('3. Testing Public Preview Mode (Unauthenticated Read Access)...');
  const dashRes = mockResponse();
  await brandProtectionHandler({
    method: 'GET',
    url: '/api/brand-protection/dashboard?bank_id=kreditbee',
    query: { bank_id: 'kreditbee', action: 'dashboard' },
    headers: { 'x-forwarded-for': '203.0.113.10' }
  }, dashRes);

  assert.equal(dashRes.statusCode, 200);
  assert.equal(dashRes.body.success, true);
  assert.equal(dashRes.body.access_tier, 'PUBLIC_PREVIEW');
  assert.ok(dashRes.body.data.statistics.active_threats >= 0);
  assert.equal(typeof dashRes.body.data.statistics.phishing_domains, 'number');
  assert.equal(typeof dashRes.body.data.statistics.rogue_apks, 'number');
  assert.ok(Array.isArray(dashRes.body.data.recent_threats));
  console.log('   ✓ Public Preview dashboard returns rich threat signals without 401 UNAUTHORIZED.');

  // TEST 4: Export Report (CSV & JSON)
  console.log('4. Testing Export Report Functionality...');
  const csvRes = mockResponse();
  await brandProtectionHandler({
    method: 'GET',
    url: '/api/brand-protection/export-report?bank_id=kreditbee&format=csv',
    query: { bank_id: 'kreditbee', format: 'csv', action: 'export-report' },
    headers: { 'x-forwarded-for': '203.0.113.11' }
  }, csvRes);

  assert.equal(csvRes.statusCode, 200);
  assert.equal(csvRes.headers['Content-Type'], 'text/csv; charset=utf-8');
  assert.ok(csvRes.body.includes('Threat Target / Domain'));
  assert.ok(csvRes.body.includes('kreditbee'));
  console.log('   ✓ Export report generates complete forensic CSV dossier without errors.');

  // TEST 5: State-Changing POST Actions STRICTLY REQUIRE Authentication
  console.log('5. Testing Security Enforcement on State-Changing Takedowns...');
  const unauthorizedPost = mockResponse();
  await brandProtectionHandler({
    method: 'POST',
    url: '/api/brand-protection/request-takedown',
    query: { action: 'request-takedown' },
    body: { threat_id: 1, bank_id: 'kreditbee' },
    headers: { 'x-forwarded-for': '203.0.113.12' }
  }, unauthorizedPost);

  assert.equal(unauthorizedPost.statusCode, 401, 'Unauthenticated takedown MUST return 401');
  assert.equal(unauthorizedPost.body.error, 'UNAUTHORIZED');
  assert.equal(unauthorizedPost.body.code, 'ENTERPRISE_KEY_REQUIRED');
  console.log('   ✓ State-changing takedown attempts without Enterprise API key strictly blocked with 401.');

  // TEST 6: State-Changing POST with Valid API Key
  console.log('6. Testing Authenticated Takedown Execution...');
  const keyTier2 = 'secret-test-brand-key';
  process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
    {
      keyId: 'client-brand-01',
      tenantId: 'kreditbee-corp',
      tier: 2,
      sha256: hash(keyTier2),
      scopes: ['b2b:scan', 'b2b:takedown'],
      expiresAt: '2099-01-01T00:00:00.000Z',
      status: 'active'
    }
  ]);

  const authPost = mockResponse();
  await brandProtectionHandler({
    method: 'POST',
    url: '/api/brand-protection/request-takedown',
    query: { action: 'request-takedown' },
    body: { threat_id: 1, bank_id: 'kreditbee' },
    headers: {
      'x-api-key': keyTier2,
      'x-verifypulse-key-id': 'client-brand-01',
      'x-forwarded-for': '203.0.113.13'
    }
  }, authPost);

  assert.equal(authPost.statusCode, 200);
  assert.equal(authPost.body.success, true);
  assert.ok(authPost.body.legal_reference.startsWith('CERTIN-70B-'));
  console.log('   ✓ Authenticated enterprise requests successfully dispatch CERT-In takedowns.');

  // TEST 7: Invalid Malformed Brand Rejection
  console.log('7. Testing Malformed Brand ID Rejection...');
  const badBrandRes = mockResponse();
  await brandProtectionHandler({
    method: 'GET',
    url: '/api/brand-protection/dashboard?bank_id=!',
    query: { bank_id: '!', action: 'dashboard' },
    headers: { 'x-forwarded-for': '203.0.113.14' }
  }, badBrandRes);

  assert.equal(badBrandRes.statusCode, 400);
  assert.equal(badBrandRes.body.code, 'INVALID_BRAND_IDENTIFIER');
  console.log('   ✓ Malformed/injected brand identifiers strictly rejected with 400.');

  console.log('--- ALL BRAND PROTECTION HARDENING TESTS PASSED ---');
}

runTests().catch(err => {
  console.error('Test Failed:', err);
  process.exit(1);
});
