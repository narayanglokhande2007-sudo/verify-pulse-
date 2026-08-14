import assert from 'node:assert/strict';
import { lookupThreatIntelligence, resetThreatIntelligenceCache } from '../lib/threat_intelligence.js';

const originalFetch = global.fetch;
const future = '2099-01-01T00:00:00.000Z';
const past = '2020-01-01T00:00:00.000Z';

try {
  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      schemaVersion: 'vp-threat-intel-1',
      generatedAt: '2026-08-14T12:00:00.000Z',
      expiresAt: future,
      indicators: [
        {
          indicator: 'https://fraud.example/login',
          indicatorType: 'url',
          hostname: 'fraud.example',
          confidence: 95,
          sourceCount: 2,
          sources: ['URLhaus', 'PhishTank'],
          categories: ['malware-url', 'phishing-url'],
          expiresAt: future
        },
        {
          indicator: 'expired.example',
          indicatorType: 'domain',
          hostname: 'expired.example',
          confidence: 99,
          sourceCount: 3,
          sources: ['URLhaus'],
          categories: ['malware-url'],
          expiresAt: past
        }
      ]
    })
  });

  resetThreatIntelligenceCache();
  const urlMatch = await lookupThreatIntelligence('Check https://fraud.example/login?session=secret');
  assert.equal(urlMatch.checked, true);
  assert.equal(urlMatch.matched, true);
  assert.equal(urlMatch.matches[0].confidence, 95);
  assert.deepEqual(urlMatch.matches[0].sources, ['URLhaus', 'PhishTank']);

  const expiredMiss = await lookupThreatIntelligence('https://expired.example/path');
  assert.equal(expiredMiss.checked, true);
  assert.equal(expiredMiss.matched, false);

  const noUrl = await lookupThreatIntelligence('This is only plain text.');
  assert.equal(noUrl.checked, false);
  assert.equal(noUrl.matched, false);

  console.log('Threat-intelligence lookup suite passed: active source-aware URL match, expired indicator rejection, and no-URL fast path.');
} finally {
  global.fetch = originalFetch;
  resetThreatIntelligenceCache();
}
