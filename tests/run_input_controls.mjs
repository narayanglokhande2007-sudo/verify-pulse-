import assert from 'node:assert/strict';
import verifyHandler from '../api/verify.js';

function response() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return body; },
  };
}

async function call(body, suffix) {
  const res = response();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': `198.51.100.${suffix}` },
    body,
    socket: {}
  }, res);
  return res;
}

const unsupported = await call({ text: 'hello', checkType: 'unknown' }, 31);
assert.equal(unsupported.statusCode, 400);
assert.equal(unsupported.body.error, 'UNSUPPORTED_CHECK_TYPE');

const tooLarge = await call({ text: 'a'.repeat(12_001), checkType: 'unified' }, 32);
assert.equal(tooLarge.statusCode, 413);
assert.equal(tooLarge.body.error, 'INPUT_TOO_LARGE');

const invalidFile = await call({ text: 'Please analyse this file', checkType: 'unified', fileData: { mimeType: 'application/pdf', base64: 'data' } }, 33);
assert.equal(invalidFile.statusCode, 400);
assert.equal(invalidFile.body.error, 'INVALID_FILE_INPUT');

const localRisk = await call({
  text: 'RBI notice: account freeze hoga. Rs 10 verification collect request approve karo within 10 minutes.',
  checkType: 'unified'
}, 34);
assert.equal(localRisk.statusCode, 200);
assert.equal(localRisk.body.verdict, 'SUSPICIOUS');
assert.equal(localRisk.body.decisionMetadata.version, 'vp-decision-1');
assert.equal(typeof localRisk.body.decisionMetadata.elapsedMs, 'number');
assert.ok(localRisk.body.requestId);

console.log('Input-controls suite passed: validation limits and decision metadata verified.');
