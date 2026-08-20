import assert from 'node:assert/strict';
import handler from '../api/status.js';

function invoke(method = 'GET') {
  const headers = {};
  let statusCode = 200;
  let body;
  const res = {
    setHeader(name, value) { headers[name.toLowerCase()] = value; },
    status(code) { statusCode = code; return this; },
    json(value) { body = value; return this; }
  };
  handler({ method }, res);
  return { statusCode, headers, body };
}

const getResult = invoke('GET');
assert.equal(getResult.statusCode, 200, 'GET /api/status must return 200');
assert.equal(getResult.headers['cache-control'], 'no-store', 'Status response must not be cached as a health guarantee');
assert.ok(Array.isArray(getResult.body?.checks), 'Status response must include checks');
assert.equal(getResult.body.checks.find(check => check.id === 'public_api')?.state, 'operational', 'Status endpoint must report itself as operational when it responds');
assert.equal(getResult.body.checks.find(check => check.id === 'external_ai_providers')?.state, 'not_monitored', 'Status endpoint must not pretend to probe external AI providers');
assert.match(getResult.body.checks.find(check => check.id === 'external_ai_providers')?.detail || '', /does not probe|does not.*promise/i, 'Provider limitation must be explicit');
assert.ok(getResult.body.limitations?.some(item => /does not mean every scan/i.test(item)), 'Status limitations must disclose scan-result boundary');

const postResult = invoke('POST');
assert.equal(postResult.statusCode, 405, 'Non-GET /api/status must return 405');
assert.equal(postResult.body?.error, 'METHOD_NOT_ALLOWED', 'Non-GET response must be explicit');

console.log('Public status endpoint checks: PASS');
