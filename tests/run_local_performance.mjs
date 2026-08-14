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

const durations = [];
for (let index = 0; index < 100; index += 1) {
  const res = response();
  const startedAt = performance.now();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': `198.51.101.${index + 1}` },
    body: {
      text: 'RBI notice: your account will be frozen. Pay Rs 10 verification fee through a UPI collect request within 10 minutes and share your OTP.',
      checkType: 'unified'
    },
    socket: {}
  }, res);
  durations.push(performance.now() - startedAt);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verdict, 'SUSPICIOUS');
}

durations.sort((left, right) => left - right);
const percentile = (value) => durations[Math.min(durations.length - 1, Math.ceil(durations.length * value) - 1)];
const metrics = {
  samples: durations.length,
  averageMs: Number((durations.reduce((sum, value) => sum + value, 0) / durations.length).toFixed(2)),
  p50Ms: Number(percentile(0.50).toFixed(2)),
  p95Ms: Number(percentile(0.95).toFixed(2)),
  p99Ms: Number(percentile(0.99).toFixed(2)),
};

assert.ok(metrics.p95Ms < 100, `Local fast-path p95 latency ${metrics.p95Ms}ms exceeds the 100ms regression guard.`);
console.table([metrics]);
console.log('Local performance suite passed: deterministic protective fast path remains below the 100ms p95 regression guard.');
