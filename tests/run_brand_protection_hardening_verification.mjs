import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import brandProtectionHandler, {
  sanitizeBrandId,
  getSyntheticBrandThreats,
  generateDynamicBrandThreats
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

  // TEST 1: Brand Sanitization Helper
  console.log('1. Testing Brand Identifier Sanitization...');
  assert.equal(sanitizeBrandId('  KreditBee  '), 'kreditbee');
  assert.equal(sanitizeBrandId('Qubik Finserv'), 'qubik-finserv');
  assert.equal(sanitizeBrandId('HDFC_Bank!@#'), 'hdfc_bank');
  assert.equal(sanitizeBrandId(''), null);
  assert.equal(sanitizeBrandId('a'), null, 'Single char should be rejected (min 2)');
  assert.equal(sanitizeBrandId(null), null);
  console.log('   ✓ Input sanitization enforces clean alphanumeric slugs.');

  // TEST 2: High-Fidelity Synthetic BFSI Threat Intel
  console.log('2. Testing Synthetic BFSI Threat Telemetry...');
  const kbThreats = getSyntheticBrandThreats('kreditbee');
  assert.ok(kbThreats.length >= 4);
  assert.ok(kbThreats.some(t => t.domain.includes('.apk')), 'KreditBee must include rogue APK vector');
  assert.ok(kbThreats.some(t => t.confidence_score >= 0.9), 'Must include critical severity threat');

  const qubikThreats = getSyntheticBrandThreats('qubik');
  assert.ok(qubikThreats.length >= 3);
  assert.ok(qubikThreats.some(t => t.domain.includes('qubik')));

  const unknownThreats = getSyntheticBrandThreats('bajajfinserv');
  assert.ok(unknownThreats.length >= 3);
  assert.ok(unknownThreats.some(t => t.domain.includes('bajajfinserv')));
  console.log('   ✓ Threat intelligence seamlessly covers both known NBFCs and dynamic brand searches.');

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
  assert.ok(dashRes.body.data.statistics.active_threats > 0);
  assert.ok(dashRes.body.data.recent_threats.length > 0);
  assert.ok(dashRes.body.data.severity_breakdown.CRITICAL > 0);
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
  assert.ok(csvRes.body.includes('kreditbee-instant-loan.xyz/download.apk'));
  assert.ok(csvRes.body.includes('CERT-In Sec 70B Takedown Eligible'));
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
