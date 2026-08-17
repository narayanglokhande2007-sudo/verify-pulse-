import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const start = source.indexOf('async function sendPulseMessage()');
const end = source.indexOf('function handlePulseKeyPress', start);
assert.ok(start >= 0 && end > start, 'PulseCore send lifecycle must exist.');
const chatFunction = source.slice(start, end);

for (const marker of [
  'const rawBody = await res.text();',
  'JSON.parse(rawBody)',
  'PulseCore se abhi complete response nahi mila.',
  'PulseCore ne abhi usable reply return nahi kiya.',
  'PulseCore se abhi connection complete nahi ho paya.',
  'Yeh SAFE result nahi hai.'
]) assert.ok(chatFunction.includes(marker), `Missing resilient PulseCore marker: ${marker}`);

assert.equal(chatFunction.includes('Error connecting to PulseCore.'), false, 'Raw generic connection error must not be rendered.');
assert.ok(chatFunction.indexOf('const rawBody = await res.text();') < chatFunction.indexOf('const reply = typeof data?.reply'), 'Response body must be parsed defensively before reply handling.');

console.log('PulseCore UI resilience suite passed: JSON, non-JSON, missing-reply, and network-error paths remain readable.');
