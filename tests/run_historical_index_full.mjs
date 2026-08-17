import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { canonicalizeUrl } from '../lib/url_forensics.js';
import { lookupHistoricalReputation, resetHistoricalReputationCache } from '../lib/historical_reputation.js';

const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'pipeline', 'daily-data');
const INDEX_DIR = path.join(DATA_DIR, 'historical-reputation-index');
const RAW_FILES = ['india_scams.jsonl', 'global_scams.jsonl', 'all_scams_master.jsonl'];

function hash(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

async function findRetainedUrl() {
  for (const name of RAW_FILES) {
    const content = await fs.readFile(path.join(DATA_DIR, name), 'utf8');
    for (const line of content.split('\n')) {
      try {
        const item = JSON.parse(line);
        const candidate = canonicalizeUrl(item?.url || item?.indicator);
        if (candidate && !candidate.hasCredentials) return `${candidate.protocol}//${candidate.hostname}${candidate.port ? `:${candidate.port}` : ''}${candidate.pathname || '/'}`;
      } catch {
        // Skip malformed historical line.
      }
    }
  }
  throw new Error('No usable retained historical URL found for index integration test.');
}

const originalFetch = globalThis.fetch;
const requestedPaths = [];
try {
  const retainedUrl = await findRetainedUrl();
  globalThis.fetch = async (url) => {
    const value = String(url);
    const relative = value.match(/historical-reputation-index\/(manifest\.json|shards\/[a-f0-9]{3}\.json)$/)?.[1];
    if (!relative) return new Response('not found', { status: 404 });
    requestedPaths.push(relative);
    const file = path.join(INDEX_DIR, relative);
    const body = await fs.readFile(file, 'utf8');
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  };

  resetHistoricalReputationCache();
  const startedAt = performance.now();
  const result = await lookupHistoricalReputation(retainedUrl);
  const durationMs = performance.now() - startedAt;
  assert.equal(result.matched, true);
  assert.equal(result.checked, true);
  assert.ok(result.matches.length >= 1);
  assert.ok(requestedPaths.includes('manifest.json'));
  assert.ok(requestedPaths.some((item) => item.startsWith('shards/')));
  assert.ok(durationMs < 250, `Local indexed lookup took ${durationMs.toFixed(1)} ms, expected under 250 ms.`);

  const coldRequests = requestedPaths.length;
  const cachedStartedAt = performance.now();
  const cachedResult = await lookupHistoricalReputation(retainedUrl);
  const cachedDurationMs = performance.now() - cachedStartedAt;
  assert.equal(cachedResult.matched, true);
  assert.equal(requestedPaths.length, coldRequests);
  assert.ok(cachedDurationMs < 30, `Cached indexed lookup took ${cachedDurationMs.toFixed(1)} ms, expected under 30 ms.`);

  // Do not print the retained indicator itself: only aggregate timing/evidence.
  console.log(`Historical full-index integration passed: exact retained-record match, ${result.matches[0].sourceCount} recorded source(s), local cold-path ${durationMs.toFixed(1)} ms, cached path ${cachedDurationMs.toFixed(1)} ms.`);
} finally {
  globalThis.fetch = originalFetch;
  resetHistoricalReputationCache();
}
