import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import verifyHandler from '../api/verify.js';
import { resetProviderCircuits } from '../lib/scan_reliability.js';

const source = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const functionStart = source.indexOf('function getVerdictPresentation(verdict)');
const functionEnd = source.indexOf('function displayEnhancedResult(containerId, data)');
assert.ok(functionStart >= 0 && functionEnd > functionStart, 'Verdict-presentation function must exist in index.html.');
const sandbox = { window: {} };
vm.runInNewContext(`${source.slice(functionStart, functionEnd)}\nthis.getVerdictPresentation = getVerdictPresentation;`, sandbox);

const getPresentation = sandbox.getVerdictPresentation;
assert.equal(getPresentation('SAFE').color, '#22c55e');
assert.equal(getPresentation('DANGEROUS').color, '#ef4444');
assert.equal(getPresentation('SUSPICIOUS').color, '#f59e0b');
const verificationPresentation = getPresentation('NEEDS_VERIFICATION');
assert.equal(verificationPresentation.color, '#2563eb');
assert.equal(verificationPresentation.icon, '🔎');
assert.equal(verificationPresentation.label, 'Needs Verification');
assert.equal(JSON.stringify(verificationPresentation.defaultSteps), JSON.stringify(['This is not a SAFE result.', 'Verify the sender or transaction in the official app or website you open yourself.']));
assert.equal(getPresentation('SERVICE_UNAVAILABLE').color, '#64748b');
assert.equal(getPresentation('unrecognised provider label').label, 'Needs Verification');
assert.notEqual(getPresentation('unrecognised provider label').color, '#22c55e');

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

const originalFetch = global.fetch;
const originalEnv = {
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  GROQ_API_KEY: process.env.GROQ_API_KEY,
  ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
  SAFE_BROWSING_API_KEY: process.env.SAFE_BROWSING_API_KEY,
};

try {
  process.env.GROQ_API_KEY = 'fixture-groq-key';
  delete process.env.GEMINI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.OPENROUTER_API_KEY;
  delete process.env.SAFE_BROWSING_API_KEY;
  resetProviderCircuits();
  global.fetch = async (url) => {
    if (String(url).includes('api.groq.com')) {
      return { ok: true, json: async () => ({ choices: [{ message: { content: JSON.stringify({ verdict: 'Potential Scam', scamType: 'Synthetic fixture', confidence: 71, analysis: 'Synthetic provider response.', findings: [], whatToDo: [] }) } }] }) };
    }
    if (String(url).includes('raw.githubusercontent.com')) return { ok: false, json: async () => ({}) };
    throw new Error(`Unexpected fixture URL: ${url}`);
  };
  const res = response();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': '198.51.100.240' },
    body: { text: 'The neighbourhood library opens tomorrow.', checkType: 'unified' },
    socket: {}
  }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verdict, 'SUSPICIOUS');
  assert.equal(res.body.explainability.assessmentType, 'model-assisted');
  assert.equal(res.body.decisionCalibration.decisionBasis, 'model-assisted');
  assert.equal(res.body.shadowEvaluation.mode, 'non-blocking');
  assert.equal(res.body.enterpriseEvidence.decisionBasis, 'model-assisted');
  assert.match(res.body.enterpriseEvidence.privacyStatement, /raw scanned content/i);

  const camouflageRes = response();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': '198.51.100.241' },
    body: { text: 'SBI account will be frozen. Pay a verification fee immediately at https://www.sbi.co.in/', checkType: 'unified' },
    socket: {}
  }, camouflageRes);
  assert.equal(camouflageRes.statusCode, 200);
  assert.equal(camouflageRes.body.verdict, 'SUSPICIOUS');
  assert.equal(camouflageRes.body.scamType, 'High-Confidence Social Engineering Risk');
  assert.equal(camouflageRes.body.explainability.assessmentType, 'evidence-backed');
  assert.ok(camouflageRes.body.findings.some((finding) => finding.includes('named bank')));
  assert.ok(camouflageRes.body.evidenceSources.includes('Local high-confidence fallback rules'));
  assert.equal(camouflageRes.body.decisionCalibration.decisionBasis, 'evidence-backed');
  assert.equal(camouflageRes.body.shadowEvaluation.mode, 'non-blocking');
  assert.equal(camouflageRes.body.enterpriseEvidence.riskBand, 'high-risk');
  assert.notEqual(camouflageRes.body.verdict, 'SAFE');
} finally {
  global.fetch = originalFetch;
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  resetProviderCircuits();
}

console.log('Verdict-contract suite passed: UI mapping and backend provider normalization are fail-safe.');
