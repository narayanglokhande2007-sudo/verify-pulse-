import assert from 'node:assert/strict';
import {
  buildHistoricalLookupKeys,
  hashHistoricalKey,
  lookupHistoricalReputation,
  resetHistoricalReputationCache
} from '../lib/historical_reputation.js';

const TEST_URL = 'https://historical-fixture.example.test/login';
const TEST_HOST = 'historical-fixture.example.test';
const urlHash = hashHistoricalKey(TEST_URL);
const domainHash = hashHistoricalKey(TEST_HOST);

function response(payload) {
  return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
}

function manifest() {
  return {
    schemaVersion: 'vp-historical-reputation-index-1',
    generatedAt: '2026-08-17T00:00:00.000Z',
    shardPrefixLength: 3,
    uniqueIndexedKeys: 2,
    sourceCount: 2,
    shardCount: 4096,
    sourceCatalog: [
      { id: 0, name: 'OpenPhish', confidence: 90, qualityTier: 'verified', category: 'phishing-url' },
      { id: 1, name: 'Phishing.Database', confidence: 82, qualityTier: 'community', category: 'phishing-url' }
    ]
  };
}

function shardPayload(prefix) {
  const records = [];
  if (urlHash.startsWith(prefix)) records.push([urlHash, 'u', [0, 1], 1717200000, 1717286400]);
  if (domainHash.startsWith(prefix)) records.push([domainHash, 'd', [0], 1717200000, 1717286400]);
  return { v: 1, p: prefix, r: records };
}

async function withMockFetch(mock, operation) {
  const original = globalThis.fetch;
  globalThis.fetch = mock;
  try {
    return await operation();
  } finally {
    globalThis.fetch = original;
    resetHistoricalReputationCache();
  }
}

async function testExactMatchAndEvidence() {
  const calls = [];
  await withMockFetch(async (url) => {
    calls.push(String(url));
    if (String(url).endsWith('/manifest.json')) return response(manifest());
    const prefix = String(url).match(/\/shards\/([a-f0-9]{3})\.json$/)?.[1];
    if (prefix) return response(shardPayload(prefix));
    return new Response('not found', { status: 404 });
  }, async () => {
    const result = await lookupHistoricalReputation(`Please check ${TEST_URL}?tracking=removed`);
    assert.equal(result.matched, true);
    assert.equal(result.checked, true);
    assert.equal(result.matches[0].indicatorType, 'url');
    assert.equal(result.matches[0].confidence, 95);
    assert.deepEqual(result.matches[0].sources, ['OpenPhish', 'Phishing.Database']);
    assert.ok(calls.some((url) => url.endsWith('/manifest.json')));
    assert.ok(calls.some((url) => url.includes(`/shards/${urlHash.slice(0, 3)}.json`)));
  });
}

async function testNoFalseMatch() {
  await withMockFetch(async (url) => {
    if (String(url).endsWith('/manifest.json')) return response(manifest());
    const prefix = String(url).match(/\/shards\/([a-f0-9]{3})\.json$/)?.[1];
    if (prefix) return response({ v: 1, p: prefix, r: [] });
    return new Response('not found', { status: 404 });
  }, async () => {
    const result = await lookupHistoricalReputation('https://not-in-history.example.test/path');
    assert.equal(result.matched, false);
    assert.equal(result.checked, true);
  });
}

async function testSafeOutage() {
  await withMockFetch(async () => { throw new Error('offline'); }, async () => {
    const result = await lookupHistoricalReputation(TEST_URL);
    assert.equal(result.matched, false);
    assert.equal(result.checked, false);
  });
}

function testCanonicalLookupKeys() {
  const keys = buildHistoricalLookupKeys('https://HISTORICAL-FIXTURE.example.test:443/login?token=private');
  assert.ok(keys.some((entry) => entry.type === 'u' && entry.hash === urlHash));
  assert.ok(keys.some((entry) => entry.type === 'd' && entry.hash === domainHash));
}

await testExactMatchAndEvidence();
await testNoFalseMatch();
await testSafeOutage();
testCanonicalLookupKeys();
console.log('Historical reputation suite passed: exact source-backed match, no false match, canonical keys, and safe outage behavior verified.');
