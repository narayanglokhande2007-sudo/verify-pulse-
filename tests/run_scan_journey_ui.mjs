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
  'Checking secure signals without opening the submitted link.',
  '<span class="desktop-brand-scanline"></span>',
  'desktopBrandScanSweep',
  'desktopBrandActiveHalo'
];
for (const marker of requiredMarkers) assert.ok(source.includes(marker), `Missing scan-journey marker: ${marker}`);

const scanFunctionStart = source.indexOf('async function checkUnified()');
const scanFunctionEnd = source.indexOf('// === TOOLS TAB LOGIC ===', scanFunctionStart);
assert.ok(scanFunctionStart >= 0 && scanFunctionEnd > scanFunctionStart, 'Unified scan lifecycle must remain present.');
const scanFunction = source.slice(scanFunctionStart, scanFunctionEnd);
assert.ok(scanFunction.indexOf('startUnifiedJourney();') < scanFunction.indexOf('requestVerify(payload)'), 'Journey must start before the request begins.');
assert.ok(scanFunction.indexOf('stopUnifiedJourney();') > scanFunction.indexOf('finally'), 'Journey must stop in the request cleanup path.');

const desktopMotionStart = source.indexOf('@media (min-width: 768px)');
const desktopMotionEnd = source.indexOf('/* Mobile corner navigation:', desktopMotionStart);
assert.ok(desktopMotionStart >= 0 && desktopMotionEnd > desktopMotionStart, 'Desktop motion scope must remain inside the desktop breakpoint.');
const desktopMotion = source.slice(desktopMotionStart, desktopMotionEnd);
for (const marker of ['desktop-brand-scanline', '@media (prefers-reduced-motion: no-preference)', 'desktopBrandHalo', 'desktopBrandScanSweep', 'desktopBrandActiveHalo', 'desktopShieldScan']) {
  assert.ok(desktopMotion.includes(marker), `Missing desktop shield-motion marker: ${marker}`);
}
assert.ok(!desktopMotion.includes('desktopBrandOrbit'), 'Legacy full-orbit desktop shield animation must not return.');
assert.ok(!desktopMotion.includes('rotate(180deg)'), 'Desktop shield must remain upright while scanning.');
const styleEnd = source.indexOf('</style>');
const cssOutsideDesktopMotion = source.slice(0, desktopMotionStart) + source.slice(desktopMotionEnd, styleEnd);
assert.ok(!cssOutsideDesktopMotion.includes('desktop-brand-scanline'), 'Desktop shield scan-line CSS must not leak into mobile styles.');

console.log('Scan-journey UI suite passed: truthful stages, desktop-only shield motion, reduced-motion handling, and cleanup lifecycle verified.');
