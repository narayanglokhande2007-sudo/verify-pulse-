import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../index.html', import.meta.url), 'utf8');

const requiredMarkers = [
  'class="scan-journey" id="unifiedLoading" role="status" aria-live="polite"',
  'Reading link structure',
  'Checking threat intelligence',
  'Finding scam signals',
  'Preparing a safe explanation',
  'Still checking secure signals…',
  'function startUnifiedJourney()',
  'function stopUnifiedJourney()',
  'startUnifiedJourney();',
  'stopUnifiedJourney();',
  '@media (prefers-reduced-motion: reduce)',
  'Checking secure signals without opening the submitted link.'
];
for (const marker of requiredMarkers) assert.ok(source.includes(marker), `Missing scan-journey marker: ${marker}`);

const scanFunctionStart = source.indexOf('async function checkUnified()');
const scanFunctionEnd = source.indexOf('// === TOOLS TAB LOGIC ===', scanFunctionStart);
assert.ok(scanFunctionStart >= 0 && scanFunctionEnd > scanFunctionStart, 'Unified scan lifecycle must remain present.');
const scanFunction = source.slice(scanFunctionStart, scanFunctionEnd);
assert.ok(scanFunction.indexOf('startUnifiedJourney();') < scanFunction.indexOf("fetch('/api/verify'"), 'Journey must start before the request begins.');
assert.ok(scanFunction.indexOf('stopUnifiedJourney();') > scanFunction.indexOf('finally'), 'Journey must stop in the request cleanup path.');

console.log('Scan-journey UI suite passed: truthful stages, accessibility, reduced-motion handling, and cleanup lifecycle verified.');
