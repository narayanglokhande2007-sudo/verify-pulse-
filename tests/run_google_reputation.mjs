import assert from 'node:assert/strict';
import verifyHandler from '../api/verify.js';
import { resetProviderCircuits } from '../lib/scan_reliability.js';

function createResponse() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return body; },
    end() { return this; }
  };
}

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const originalFetch = global.fetch;
const originalEnv = {
  GOOGLE_WEB_RISK_API_KEY: process.env.GOOGLE_WEB_RISK_API_KEY,
  SAFE_BROWSING_API_KEY: process.env.SAFE_BROWSING_API_KEY,
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  GROQ_API_KEY: process.env.GROQ_API_KEY,
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY
};

process.env.GOOGLE_WEB_RISK_API_KEY = 'fixture-web-risk-key';
delete process.env.SAFE_BROWSING_API_KEY;
delete process.env.GEMINI_API_KEY;
delete process.env.GROQ_API_KEY;
delete process.env.ANTHROPIC_API_KEY;
delete process.env.OPENROUTER_API_KEY;

global.fetch = async (url) => {
  const target = String(url);
  if (target.includes('webrisk.googleapis.com/v1/uris:search')) {
    return jsonResponse(200, { threat: { threatTypes: ['SOCIAL_ENGINEERING'] } });
  }
  if (target.includes('raw.githubusercontent.com')) return jsonResponse(503, { error: 'fixture feed unavailable' });
  throw new Error(`Unexpected fixture-network request: ${target}`);
};

try {
  resetProviderCircuits();
  const response = createResponse();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': '198.51.100.251' },
    body: { text: 'https://malicious-fixture.example/login', checkType: 'url' },
    socket: {}
  }, response);

  assert.equal(response.statusCode, 200);
  assert.equal(response.body?.verdict, 'DANGEROUS');
  assert.ok(response.body?.evidenceSources.includes('Google Web Risk'));
  assert.equal(response.body?.decisionCalibration?.decisionBasis, 'evidence-backed');
  assert.match(response.body?.analysis || '', /Google Web Risk/i);
} finally {
  global.fetch = originalFetch;
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}

console.log('Google reputation suite passed: configured Web Risk threat match returns evidence-backed DANGEROUS.');
