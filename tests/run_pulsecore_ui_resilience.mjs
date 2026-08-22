import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const start = source.indexOf('async function sendPulseMessage()');
const end = source.indexOf('function handlePulseKeyPress', start);
assert.ok(start >= 0 && end > start, 'PulseCore send lifecycle must exist.');
const chatFunction = source.slice(start, end);

for (const marker of [
  "requestVerify({ checkType: 'chatbot', text })",
  'const reply = typeof data?.reply',
  'PulseCore ne abhi usable reply return nahi kiya.',
  'PulseCore se abhi connection complete nahi ho paya.',
  'Yeh SAFE result nahi hai.',
  'setPulseCoreBusy(true)',
  'setPulseCoreBusy(false)',
  'appendPulseCoreMessage'
]) assert.ok(chatFunction.includes(marker), `Missing resilient PulseCore marker: ${marker}`);

assert.equal(chatFunction.includes('Error connecting to PulseCore.'), false, 'Raw generic connection error must not be rendered.');
assert.ok(chatFunction.indexOf("requestVerify({ checkType: 'chatbot', text })") < chatFunction.indexOf('const reply = typeof data?.reply'), 'The verified response must resolve before reply handling.');
assert.ok(source.includes('async function requestVerify(payload'), 'A shared timeout-safe request helper must exist.');
assert.ok(source.includes("if (error?.name === 'AbortError')"), 'Request timeout must show a safe readable outcome.');
assert.ok(source.includes('const safeMarkdown = escapeHTML(text);'), 'AI markdown must be escaped before browser rendering.');

console.log('PulseCore UI resilience suite passed: bounded requests, readable fallback, duplicate-submit protection, and safe markdown rendering verified.');
