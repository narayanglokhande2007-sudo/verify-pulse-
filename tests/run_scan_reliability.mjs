import assert from 'node:assert/strict';
import crypto from 'node:crypto';
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

async function scan({ text, checkType = 'scam', address }) {
  const response = createResponse();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': address },
    body: { text, checkType },
    socket: {}
  }, response);
  return response;
}

const originalFetch = global.fetch;
const originalEnv = {
  GROQ_API_KEY: process.env.GROQ_API_KEY,
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  SAFE_BROWSING_API_KEY: process.env.SAFE_BROWSING_API_KEY,
};
process.env.GROQ_API_KEY = 'fixture-groq-key';
process.env.GEMINI_API_KEY = 'fixture-gemini-key';
process.env.OPENROUTER_API_KEY = 'fixture-openrouter-key';
process.env.ANTHROPIC_API_KEY = 'fixture-anthropic-key';
process.env.SAFE_BROWSING_API_KEY = 'fixture-safe-browsing-key';

const HISTORICAL_TEST_URL = 'https://historical-fixture.example.test/';
const HISTORICAL_TEST_HASH = crypto.createHash('sha256').update(HISTORICAL_TEST_URL, 'utf8').digest('hex');
let mode = 'all-providers-fail';
global.fetch = async (url) => {
  const target = String(url);
  if (mode === 'historical-match' && target.includes('verify-pulse.com/pipeline/daily-data/historical-reputation-index')) {
    if (target.endsWith('/manifest.json')) {
      return jsonResponse(200, {
        schemaVersion: 'vp-historical-reputation-index-1', generatedAt: '2026-08-17T00:00:00.000Z',
        shardPrefixLength: 3, uniqueIndexedKeys: 1, sourceCount: 1, shardCount: 4096,
        sourceCatalog: [{ id: 0, name: 'OpenPhish', confidence: 90, qualityTier: 'verified', category: 'phishing-url' }]
      });
    }
    const prefix = target.match(/\/shards\/([a-f0-9]{3})\.json$/)?.[1];
    if (prefix) return jsonResponse(200, { v: 1, p: prefix, r: HISTORICAL_TEST_HASH.startsWith(prefix) ? [[HISTORICAL_TEST_HASH, 'u', [0], 1717200000, 1717286400]] : [] });
  }
  if (target.includes('raw.githubusercontent.com')) return jsonResponse(503, { error: 'temporarily unavailable' });
  if (target.includes('safebrowsing.googleapis.com')) return jsonResponse(200, {});
  if (target.includes('api.groq.com')) return jsonResponse(429, { error: { message: 'rate limited' } });
  if (target.includes('generativelanguage.googleapis.com')) return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  if (target.includes('api.anthropic.com')) {
    if (mode === 'anthropic-success') {
      return jsonResponse(200, {
        content: [{ type: 'text', text: JSON.stringify({
          verdict: 'SAFE', scamType: 'Benign reminder', confidence: 83,
          analysis: 'No high-risk signal is present in this synthetic reminder.', findings: [], whatToDo: ['Use official channels for sensitive actions.']
        }) }]
      });
    }
    return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  }
  if (target.includes('openrouter.ai')) {
    if (mode === 'openrouter-success') {
      return jsonResponse(200, {
        choices: [{ message: { content: JSON.stringify({
          verdict: 'SAFE', scamType: 'Benign reminder', confidence: 82,
          analysis: 'No high-risk signal is present in this synthetic reminder.', findings: [], whatToDo: ['Use official channels for sensitive actions.']
        }) } }]
      });
    }
    return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  }
  throw new Error(`Unexpected fixture-network request: ${target}`);
};

const results = [];
try {
  const localFallback = await scan({
    text: 'Urgent offer: WhatsApp se abhi reward-update.apk download and install karo, warna benefit expire ho jayega.',
    address: '198.51.100.201'
  });
  assert.equal(localFallback.statusCode, 200);
  assert.equal(localFallback.body?.verdict, 'SUSPICIOUS');
  assert.ok(localFallback.body.evidenceSources.includes('Local high-confidence fallback rules'));
  assert.equal(localFallback.body.explainability.assessmentType, 'evidence-backed');
  assert.ok(localFallback.headers['X-VerifyPulse-Request-Id']);
  results.push({ case: 'local high-confidence fallback', status: localFallback.statusCode, verdict: localFallback.body.verdict });

  resetProviderCircuits();
  const unavailable = await scan({
    text: 'Your neighbourhood library will close at 5 PM today for maintenance.',
    address: '198.51.100.202'
  });
  assert.equal(unavailable.statusCode, 200);
  assert.equal(unavailable.body?.verdict, 'NEEDS_VERIFICATION');
  assert.equal(unavailable.body?.explainability.assessmentType, 'service-status');
  assert.equal(unavailable.body?.serviceStatus, 'degraded');
  assert.ok(unavailable.body?.failedProviders.some((entry) => entry.errorCode === 'provider_rate_limited'));
  assert.ok(unavailable.headers['X-VerifyPulse-Request-Id']);
  results.push({ case: 'degraded verification response', status: unavailable.statusCode, verdict: unavailable.body.verdict });

  resetProviderCircuits();
  mode = 'historical-match';
  const historicalMatch = await scan({
    text: HISTORICAL_TEST_URL,
    checkType: 'url',
    address: '198.51.100.207'
  });
  assert.equal(historicalMatch.statusCode, 200);
  assert.equal(historicalMatch.body?.verdict, 'DANGEROUS');
  assert.ok(historicalMatch.body?.evidenceSources.includes('Historical multi-source threat reputation'));
  assert.equal(historicalMatch.body?.explainability.assessmentType, 'evidence-backed');
  assert.match(historicalMatch.body?.explainability.summary || '', /exact retained historical threat-reputation match/i);
  assert.ok(historicalMatch.body?.explainability.evidence.some((entry) => entry.source === 'Historical multi-source threat reputation' && entry.type === 'exact-historical-reputation-match'));
  assert.equal(historicalMatch.body?.explainability.evidence.some((entry) => /No deterministic reputation match/i.test(entry.detail || '')), false);
  results.push({ case: 'historical reputation explanation', status: historicalMatch.statusCode, verdict: historicalMatch.body.verdict });

  resetProviderCircuits();
  mode = 'anthropic-success';
  const anthropicFallback = await scan({
    text: 'Your neighbourhood library will close at 5 PM today for maintenance.',
    address: '198.51.100.203'
  });
  assert.equal(anthropicFallback.statusCode, 200);
  assert.equal(anthropicFallback.body?.verdict, 'SAFE');
  assert.equal(anthropicFallback.body?.explainability.assessmentType, 'model-assisted');
  assert.ok(anthropicFallback.headers['X-VerifyPulse-Request-Id']);
  results.push({ case: 'configured Anthropic fallback', status: anthropicFallback.statusCode, verdict: anthropicFallback.body.verdict });

  resetProviderCircuits();
  mode = 'openrouter-success';
  const secondaryFallback = await scan({
    text: 'Your neighbourhood library will close at 5 PM today for maintenance.',
    address: '198.51.100.204'
  });
  assert.equal(secondaryFallback.statusCode, 200);
  assert.equal(secondaryFallback.body?.verdict, 'SAFE');
  assert.equal(secondaryFallback.body?.explainability.assessmentType, 'model-assisted');
  assert.ok(secondaryFallback.headers['X-VerifyPulse-Request-Id']);
  results.push({ case: 'independent OpenRouter fallback', status: secondaryFallback.statusCode, verdict: secondaryFallback.body.verdict });

  resetProviderCircuits();
  mode = 'all-providers-fail';
  await scan({ text: 'Community office closes at 5 PM today.', address: '198.51.100.205' });
  const circuitProtected = await scan({ text: 'Community office closes at 5 PM today.', address: '198.51.100.206' });
  assert.equal(circuitProtected.statusCode, 200);
  assert.equal(circuitProtected.body?.verdict, 'NEEDS_VERIFICATION');
  assert.equal(circuitProtected.body?.serviceStatus, 'degraded');
  assert.ok(circuitProtected.body?.failedProviders.some((entry) => entry.errorCode === 'provider_circuit_open'));
  results.push({ case: 'circuit breaker returns verification state', status: circuitProtected.statusCode, verdict: circuitProtected.body.verdict });
} finally {
  global.fetch = originalFetch;
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}

console.table(results);
console.log(`Scan reliability suite passed: ${results.length}/6 focused reliability cases.`);
