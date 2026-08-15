import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import b2bScanHandler from '../api/v1/scan.js';

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function response() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return body; },
    end() { return undefined; }
  };
}

async function call({ rawKey, keyId, suffix, registry, legacyHashes, host = 'verify-pulse.test' }) {
  process.env.VERIFYPULSE_B2B_KEY_REGISTRY = registry || '';
  process.env.VERIFYPULSE_B2B_API_KEY_HASHES = legacyHashes || '';
  const res = response();
  await b2bScanHandler({
    method: 'POST',
    headers: {
      host,
      'x-forwarded-proto': 'https',
      'x-forwarded-for': `198.51.100.${suffix}`,
      ...(rawKey ? { 'x-api-key': rawKey } : {}),
      ...(keyId ? { 'x-verifypulse-key-id': keyId } : {})
    },
    body: { url: 'https://example.test/account' },
    socket: {}
  }, res);
  return res;
}

const original = {
  registry: process.env.VERIFYPULSE_B2B_KEY_REGISTRY,
  legacyHashes: process.env.VERIFYPULSE_B2B_API_KEY_HASHES,
  fetch: global.fetch,
  consoleInfo: console.info
};
const auditLines = [];

try {
  console.info = (line) => auditLines.push(String(line));
  global.fetch = async () => ({ ok: true, json: async () => ({ verdict: 'SUSPICIOUS', scamType: 'Fixture', confidence: 88, analysis: 'Fixture result.', whatToDo: [] }) });
  const key = 'enterprise-test-key-1';
  const scopedRegistry = JSON.stringify([{
    keyId: 'iitr-pilot-2026', tenantId: 'iitr', sha256: hash(key), scopes: ['b2b:scan'], expiresAt: '2099-01-01T00:00:00.000Z', status: 'active'
  }]);

  const allowed = await call({ rawKey: key, keyId: 'iitr-pilot-2026', suffix: 51, registry: scopedRegistry });
  assert.equal(allowed.statusCode, 200);
  assert.equal(allowed.body.status, 'SUSPICIOUS');
  assert.ok(allowed.body.correlation_id);
  assert.equal(allowed.headers['X-VerifyPulse-Correlation-Id'], allowed.body.correlation_id);

  const missingScope = await call({ rawKey: key, keyId: 'iitr-pilot-2026', suffix: 52, registry: JSON.stringify([{
    keyId: 'iitr-pilot-2026', tenantId: 'iitr', sha256: hash(key), scopes: ['reports:read'], expiresAt: '2099-01-01T00:00:00.000Z', status: 'active'
  }]) });
  assert.equal(missingScope.statusCode, 403);
  assert.equal(missingScope.body.error, 'B2B_SCOPE_DENIED');

  const revoked = await call({ rawKey: key, keyId: 'iitr-pilot-2026', suffix: 53, registry: JSON.stringify([{
    keyId: 'iitr-pilot-2026', tenantId: 'iitr', sha256: hash(key), scopes: ['b2b:scan'], expiresAt: '2099-01-01T00:00:00.000Z', status: 'revoked'
  }]) });
  assert.equal(revoked.statusCode, 401);
  assert.equal(revoked.body.error, 'B2B_API_KEY_INVALID');

  const expired = await call({ rawKey: key, keyId: 'iitr-pilot-2026', suffix: 54, registry: JSON.stringify([{
    keyId: 'iitr-pilot-2026', tenantId: 'iitr', sha256: hash(key), scopes: ['b2b:scan'], expiresAt: '2020-01-01T00:00:00.000Z', status: 'active'
  }]) });
  assert.equal(expired.statusCode, 401);

  const legacy = await call({ rawKey: key, suffix: 55, legacyHashes: hash(key) });
  assert.equal(legacy.statusCode, 200);
  assert.equal(legacy.body.status, 'SUSPICIOUS');

  assert.ok(auditLines.some((line) => line.includes('verifypulse.b2b_audit')));
  assert.ok(auditLines.some((line) => line.includes('B2B_SCOPE_DENIED')));
  assert.ok(auditLines.every((line) => !line.includes('https://example.test/account')));
  assert.ok(auditLines.every((line) => !line.includes(key)));
} finally {
  global.fetch = original.fetch;
  console.info = original.consoleInfo;
  if (original.registry === undefined) delete process.env.VERIFYPULSE_B2B_KEY_REGISTRY; else process.env.VERIFYPULSE_B2B_KEY_REGISTRY = original.registry;
  if (original.legacyHashes === undefined) delete process.env.VERIFYPULSE_B2B_API_KEY_HASHES; else process.env.VERIFYPULSE_B2B_API_KEY_HASHES = original.legacyHashes;
}

console.log('B2B access-control suite passed: scoped lifecycle, correlation, legacy compatibility, and privacy-safe audit events verified.');
