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
    json(body) { this.body = body; return body; }
  };
}

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

async function chat(text, address) {
  const response = createResponse();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': address },
    body: { checkType: 'chatbot', text },
    socket: {}
  }, response);
  return response;
}

const originalFetch = global.fetch;
const originalEnv = Object.fromEntries(['GROQ_API_KEY', 'GEMINI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENROUTER_API_KEY'].map((key) => [key, process.env[key]]));
for (const key of Object.keys(originalEnv)) process.env[key] = `fixture-${key.toLowerCase()}`;

let mode = 'gemini-success';
const calls = [];
global.fetch = async (url) => {
  const target = String(url);
  calls.push(target);
  if (target.includes('generativelanguage.googleapis.com')) {
    if (mode === 'gemini-success') return jsonResponse(200, { candidates: [{ content: { parts: [{ text: 'Gemini PulseCore reply.' }] } }] });
    return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  }
  if (target.includes('api.groq.com')) {
    if (mode === 'groq-fallback-success') return jsonResponse(200, { choices: [{ message: { content: 'Groq fallback PulseCore reply.' } }] });
    return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  }
  if (target.includes('api.anthropic.com')) return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  if (target.includes('openrouter.ai')) return jsonResponse(503, { error: { message: 'upstream unavailable' } });
  throw new Error(`Unexpected fixture URL: ${target}`);
};

const results = [];
try {
  resetProviderCircuits();
  mode = 'gemini-success';
  const primary = await chat('Mujhe phishing se bachne ke tips batao.', '198.51.100.251');
  assert.equal(primary.statusCode, 200);
  assert.equal(primary.body?.reply, 'Gemini PulseCore reply.');
  assert.equal(primary.body?.replyStatus, 'available');
  assert.equal(primary.body?.replyProvider, 'gemini');
  results.push({ case: 'primary Gemini reply', status: primary.statusCode, provider: primary.body.replyProvider });

  resetProviderCircuits();
  calls.length = 0;
  mode = 'groq-fallback-success';
  const fallback = await chat('UPI fraud se kaise bache?', '198.51.100.252');
  assert.equal(fallback.statusCode, 200);
  assert.equal(fallback.body?.reply, 'Groq fallback PulseCore reply.');
  assert.equal(fallback.body?.replyStatus, 'available');
  assert.equal(fallback.body?.replyProvider, 'groq');
  assert.ok(calls.some((url) => url.includes('generativelanguage.googleapis.com')));
  assert.ok(calls.some((url) => url.includes('api.groq.com')));
  results.push({ case: 'Groq fallback reply', status: fallback.statusCode, provider: fallback.body.replyProvider });

  resetProviderCircuits();
  mode = 'all-providers-fail';
  const unavailable = await chat('Net banking safe kaise rakhu?', '198.51.100.253');
  assert.equal(unavailable.statusCode, 200);
  assert.equal(unavailable.body?.replyStatus, 'temporarily_unavailable');
  assert.match(unavailable.body?.reply || '', /temporarily unavailable/i);
  assert.equal(/facing high traffic/i.test(unavailable.body?.reply || ''), false);
  assert.ok(Array.isArray(unavailable.body?.failedProviders));
  results.push({ case: 'all-provider degraded reply', status: unavailable.statusCode, provider: 'none' });
} finally {
  global.fetch = originalFetch;
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  resetProviderCircuits();
}

console.table(results);
console.log(`PulseCore reliability suite passed: ${results.length}/3 chat-routing cases.`);
