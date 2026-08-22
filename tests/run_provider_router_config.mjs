import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [verifySource, requestBudgetSource, vercelConfigSource] = await Promise.all([
  readFile(new URL('../api/verify.js', import.meta.url), 'utf8'),
  readFile(new URL('../lib/request_budget.js', import.meta.url), 'utf8'),
  readFile(new URL('../vercel.json', import.meta.url), 'utf8')
]);

const vercelConfig = JSON.parse(vercelConfigSource);

assert.match(verifySource, /const GROQ_MODEL = process\.env\.GROQ_MODEL \|\| 'openai\/gpt-oss-120b';/);
assert.doesNotMatch(verifySource, /model:\s*['\"]llama-3\.3-70b-versatile['\"]/);
assert.match(verifySource, /capMs: 2400/);
assert.match(verifySource, /capMs: 2200/);
assert.match(requestBudgetSource, /VERIFYPULSE_SCAN_BUDGET_MS, 8500, 9000/);
assert.equal(vercelConfig.functions?.['api/verify.js']?.maxDuration, 10);

console.log('Provider-router configuration suite passed: active Groq model and accuracy-first Vercel budget verified.');
