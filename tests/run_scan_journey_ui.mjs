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
  '<span class="desktop-brand-shield-ghost"></span>',
  '<span class="desktop-brand-shield-wave"></span>',
  '<img class="desktop-scan-shield" src="desktop-verify-pulse-shield.webp" alt="">',
  'desktopBrandScanSweep',
  'desktopBrandShieldWave',
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
for (const marker of ['desktop-brand-scanline', 'desktop-brand-shield-ghost', 'desktop-brand-shield-wave', 'desktop-scan-shield', '@media (prefers-reduced-motion: no-preference)', 'desktopBrandHalo', 'desktopBrandShieldWave', 'desktopBrandScanSweep', 'desktopBrandActiveHalo']) {
  assert.ok(desktopMotion.includes(marker), `Missing desktop shield-effect marker: ${marker}`);
}
assert.ok(!desktopMotion.includes('desktopBrandOrbit'), 'Legacy full-orbit desktop shield animation must not return.');
assert.ok(!desktopMotion.includes('desktopBrandFloat'), 'The shield image itself must remain static.');
assert.ok(!desktopMotion.includes('desktopShieldScan'), 'The shield image must not receive scan-state animation.');
assert.ok(desktopMotion.includes('animation: none !important; transform: none !important;'), 'The desktop shield visual must explicitly remain static.');
assert.ok(source.includes('desktop-verify-pulse-shield.webp'), 'The original VerifyPulse circuit-shield asset must remain wired to the desktop visual.');
assert.ok(desktopMotion.includes('clip-path: polygon(50% 13%'), 'The desktop logo must be cropped to the shield mark rather than display as a square image card.');
assert.ok(!desktopMotion.includes('border-radius: 30px'), 'The desktop circuit mark must not render as an image card.');
assert.ok(desktopMotion.includes('animation: desktopBrandHalo 2.2s'), 'Idle scan effect must use the compact reference-inspired timing.');
assert.ok(desktopMotion.includes('animation-duration: 1.6s'), 'Active scan effect must use the faster reference-inspired timing.');
assert.ok(!desktopMotion.includes('rotate(180deg)'), 'Desktop shield must remain upright while scanning.');
const styleEnd = source.indexOf('</style>');
const cssOutsideDesktopMotion = source.slice(0, desktopMotionStart) + source.slice(desktopMotionEnd, styleEnd);
assert.ok(!cssOutsideDesktopMotion.includes('desktop-brand-scanline'), 'Desktop shield scan-line CSS must not leak into mobile styles.');
assert.ok(!cssOutsideDesktopMotion.includes('desktop-brand-shield-ghost'), 'Desktop shield-ghost CSS must not leak into mobile styles.');
assert.ok(!cssOutsideDesktopMotion.includes('desktop-brand-shield-wave'), 'Desktop shield-wave CSS must not leak into mobile styles.');
assert.ok(!cssOutsideDesktopMotion.includes('desktop-scan-shield'), 'Desktop vector shield CSS must not leak into mobile styles.');

console.log('Scan-journey UI suite passed: truthful stages, desktop-only shield motion, reduced-motion handling, and cleanup lifecycle verified.');
