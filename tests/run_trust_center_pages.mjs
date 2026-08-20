import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');

const requiredPages = ['trust.html', 'risk-management.html', 'status.html', 'pilot.html'];
for (const page of requiredPages) {
  assert.equal(fs.existsSync(path.join(root, page)), true, `${page} must exist`);
  const html = read(page);
  assert.match(html, /trust-center\.css/, `${page} must use the shared trust-page style`);
  assert.match(html, /href="trust\.html"/, `${page} must link to Trust Center`);
  assert.match(html, /href="risk-management\.html"/, `${page} must link to Risk Management`);
  assert.match(html, /href="status\.html"/, `${page} must link to Status`);
  assert.match(html, /href="pilot\.html"/, `${page} must link to Pilot`);
}

const trust = read('trust.html');
assert.match(trust, /not an external security certification/i, 'Trust Center must state certification limitation');
assert.match(trust, /does not guarantee/i, 'Trust Center must state decision limitation');
assert.doesNotMatch(trust, /military-grade|RBI-approved|100% accurate|99\.9% accurate/i, 'Trust Center must not overclaim');

const risk = read('risk-management.html');
assert.match(risk, /not a live browser detonation sandbox/i, 'Risk page must disclose inactive browser sandbox boundary');
assert.match(risk, /not a payment-blocking engine/i, 'Risk page must disclose payment-decision boundary');
assert.match(risk, /No evidence is not treated as SAFE/i, 'Risk page must describe degraded safety behavior');

const status = read('status.html');
assert.match(status, /fetch\('\/api\/status'/, 'Status page must fetch the public status endpoint');
assert.match(status, /not promise external AI-provider availability/i, 'Status page must state provider-monitoring limitation');

const statusApi = read('api/status.js');
assert.match(statusApi, /external_ai_providers/, 'Status API must expose external-provider transparency state');
assert.match(statusApi, /not_monitored/, 'Status API must avoid pretending external providers are live-probed');
assert.match(statusApi, /older than 48 hours/i, 'Status API must surface stale published metadata');

const docs = read('docs.html');
assert.match(docs, /\/api\/v1\/scan/, 'Docs must show actual B2B scan route');
assert.match(docs, /X-API-Key/, 'Docs must show current API-key route');
assert.doesNotMatch(docs, /https:\/\/verify-pulse\.vercel\.app\/api\/verify|90-day memory decay|1\.3M\+ records|guaranteeing zero-day detection/i, 'Docs must not retain obsolete/unproven claims');

const enterprise = read('enterprise.html');
assert.match(enterprise, /controlled pilot/i, 'Enterprise page must direct clients to controlled pilots');
assert.doesNotMatch(enterprise, /99\.9% accuracy|Ghost Agent Sandboxing|Autonomous Scam Hunter|Sub-50ms|Zero PII Retention/i, 'Enterprise page must not retain unsupported capability claims');

const index = read('index.html');
assert.match(index, /Trust & Business Information/, 'Main mobile page must expose trust information');
assert.match(index, /trust\.html/, 'Main mobile page must link to Trust Center');
assert.doesNotMatch(index, /1M calls\/month|Priority 24\/7 AI Security Support|<b>Unlimited<\/b> automated AI scans/i, 'Main mobile page must not advertise unavailable capacity or support');

console.log('Trust Center page checks: PASS');
