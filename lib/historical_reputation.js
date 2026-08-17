// lib/historical_reputation.js
// Fast exact reputation lookup over VerifyPulse's retained multi-source history.
// It fetches only hash-addressed index shards, never raw historical URL files.

import crypto from 'node:crypto';
import { canonicalizeUrl, extractUrlCandidates } from './url_forensics.js';
import { fetchJsonWithTimeout } from './scan_reliability.js';

const RAW_BASE_URL = 'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/historical-reputation-index';
const MANIFEST_URL = `${RAW_BASE_URL}/manifest.json`;
const SCHEMA_VERSION = 'vp-historical-reputation-index-1';
const MANIFEST_CACHE_TTL_MS = 10 * 60_000;
const SHARD_CACHE_TTL_MS = 10 * 60_000;
const MAX_SHARD_CACHE_ENTRIES = 96;
const MAX_CANDIDATES = 3;
const MAX_DOMAIN_KEYS_PER_CANDIDATE = 2;
const MAX_SHARD_RECORDS = 12_000;
const INDEX_SHARD_PREFIX_LENGTH = 3;

const manifestCache = { value: null, expiresAt: 0 };
const shardCache = new Map();

function parseTimestamp(value) {
  const timestamp = Date.parse(String(value || ''));
  return Number.isFinite(timestamp) ? timestamp : null;
}

export function hashHistoricalKey(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function canonicalUrlKey(candidate) {
  return `${candidate.protocol}//${candidate.hostname}${candidate.port ? `:${candidate.port}` : ''}${candidate.pathname || '/'}`;
}

function domainCandidates(hostname) {
  const labels = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  if (labels.length < 2) return [];
  const values = [labels.join('.')];
  // Check the registrable-looking parent too (for example www.bad.example → bad.example).
  if (labels.length > 2) values.push(labels.slice(1).join('.'));
  return [...new Set(values)].slice(0, MAX_DOMAIN_KEYS_PER_CANDIDATE);
}

export function buildHistoricalLookupKeys(text) {
  const candidates = extractUrlCandidates(text).map(canonicalizeUrl).filter(Boolean).slice(0, MAX_CANDIDATES);
  const entries = [];
  const seen = new Set();
  for (const candidate of candidates) {
    const urlValue = canonicalUrlKey(candidate);
    const urlHash = hashHistoricalKey(urlValue);
    const urlEntry = { hash: urlHash, type: 'u', hostname: candidate.hostname, matchedValueType: 'url' };
    if (!seen.has(`u:${urlHash}`)) {
      seen.add(`u:${urlHash}`);
      entries.push(urlEntry);
    }
    for (const domain of domainCandidates(candidate.hostname)) {
      const domainHash = hashHistoricalKey(domain);
      if (seen.has(`d:${domainHash}`)) continue;
      seen.add(`d:${domainHash}`);
      entries.push({ hash: domainHash, type: 'd', hostname: candidate.hostname, matchedValueType: 'domain' });
    }
  }
  return entries;
}

function validManifest(payload) {
  return Boolean(
    payload
      && payload.schemaVersion === SCHEMA_VERSION
      && Number.isInteger(payload.shardPrefixLength)
      && payload.shardPrefixLength === INDEX_SHARD_PREFIX_LENGTH
      && Array.isArray(payload.sourceCatalog)
      && payload.sourceCatalog.length <= 64
      && Number.isInteger(payload.uniqueIndexedKeys)
      && payload.uniqueIndexedKeys > 0
  );
}

function validShard(payload, prefix) {
  return Boolean(
    payload
      && payload.v === 1
      && payload.p === prefix
      && Array.isArray(payload.r)
      && payload.r.length <= MAX_SHARD_RECORDS
  );
}

async function getManifest() {
  if (manifestCache.value && Date.now() < manifestCache.expiresAt) return manifestCache.value;
  try {
    const payload = await fetchJsonWithTimeout(MANIFEST_URL, {}, { provider: 'historical_reputation_manifest', timeoutMs: 550 });
    if (!validManifest(payload)) return null;
    manifestCache.value = payload;
    manifestCache.expiresAt = Date.now() + MANIFEST_CACHE_TTL_MS;
    return payload;
  } catch {
    return null;
  }
}

function trimShardCache() {
  while (shardCache.size > MAX_SHARD_CACHE_ENTRIES) {
    const oldestKey = shardCache.keys().next().value;
    shardCache.delete(oldestKey);
  }
}

async function getShard(prefix) {
  const cached = shardCache.get(prefix);
  if (cached && Date.now() < cached.expiresAt) {
    // LRU-style refresh prevents popular shards from being evicted first.
    shardCache.delete(prefix);
    shardCache.set(prefix, cached);
    return cached.value;
  }
  const url = `${RAW_BASE_URL}/shards/${prefix}.json`;
  try {
    const payload = await fetchJsonWithTimeout(url, {}, { provider: 'historical_reputation_shard', timeoutMs: 600 });
    if (!validShard(payload, prefix)) return null;
    const index = new Map();
    for (const record of payload.r) {
      if (!Array.isArray(record) || record.length !== 5) continue;
      const [hash, type] = record;
      if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash) || !['u', 'd'].includes(type)) continue;
      index.set(`${type}:${hash}`, record);
    }
    shardCache.set(prefix, { value: index, expiresAt: Date.now() + SHARD_CACHE_TTL_MS });
    trimShardCache();
    return index;
  } catch {
    return null;
  }
}

function sourceEvidence(sourceIds, catalog) {
  const sources = [];
  for (const id of Array.isArray(sourceIds) ? sourceIds : []) {
    const source = catalog.find((entry) => entry?.id === id);
    if (!source) continue;
    sources.push({
      name: String(source.name || 'Recorded threat feed'),
      confidence: Number(source.confidence) || 0,
      qualityTier: String(source.qualityTier || 'unclassified'),
      category: String(source.category || 'suspicious-indicator')
    });
  }
  const uniqueByName = [...new Map(sources.map((source) => [source.name, source])).values()];
  return uniqueByName.sort((left, right) => right.confidence - left.confidence).slice(0, 6);
}

function makeMatch(lookupEntry, record, manifest) {
  const [, type, sourceIds, firstSeenEpoch, lastSeenEpoch] = record;
  const sources = sourceEvidence(sourceIds, manifest.sourceCatalog);
  const confidence = Math.min(99, Math.max(65, Math.max(...sources.map((source) => source.confidence), 65) + Math.min(10, 5 * Math.max(0, sources.length - 1))));
  const qualityTier = sources.some((source) => source.qualityTier === 'verified')
    ? 'verified'
    : sources.some((source) => source.qualityTier === 'established-community')
      ? 'established-community'
      : sources.some((source) => source.qualityTier === 'community')
        ? 'community'
        : 'unclassified';
  return {
    hostname: lookupEntry.hostname,
    indicatorType: type === 'u' ? 'url' : 'domain',
    matchedValueType: lookupEntry.matchedValueType,
    confidence,
    sourceCount: sources.length,
    qualityTier,
    sources: sources.map((source) => source.name),
    categories: [...new Set(sources.map((source) => source.category))].slice(0, 4),
    firstSeen: firstSeenEpoch ? new Date(firstSeenEpoch * 1000).toISOString() : null,
    lastSeen: lastSeenEpoch ? new Date(lastSeenEpoch * 1000).toISOString() : null,
    indexGeneratedAt: manifest.generatedAt
  };
}

export async function lookupHistoricalReputation(text) {
  const lookupEntries = buildHistoricalLookupKeys(text);
  if (lookupEntries.length === 0) return { matched: false, checked: false, matches: [] };
  // The current index format fixes a three-character shard prefix. Start the
  // manifest and shard reads together on a cold serverless request so the
  // historical check adds one bounded network wait instead of two sequential waits.
  const neededPrefixes = [...new Set(lookupEntries.map((entry) => entry.hash.slice(0, INDEX_SHARD_PREFIX_LENGTH)))];
  const [manifest, shardPairs] = await Promise.all([
    getManifest(),
    Promise.all(neededPrefixes.map(async (prefix) => [prefix, await getShard(prefix)]))
  ]);
  if (!manifest) return { matched: false, checked: false, matches: [] };
  const shards = new Map(shardPairs);
  const unavailableShards = neededPrefixes.filter((prefix) => !shards.get(prefix));
  const matches = [];
  const seen = new Set();

  for (const entry of lookupEntries) {
    const shard = shards.get(entry.hash.slice(0, manifest.shardPrefixLength));
    const record = shard?.get(`${entry.type}:${entry.hash}`);
    if (!record) continue;
    const match = makeMatch(entry, record, manifest);
    const key = `${match.indicatorType}:${entry.hash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push(match);
  }

  matches.sort((left, right) => right.confidence - left.confidence || right.sourceCount - left.sourceCount);
  return {
    matched: matches.length > 0,
    checked: unavailableShards.length === 0,
    generatedAt: manifest.generatedAt,
    index: {
      uniqueKeys: manifest.uniqueIndexedKeys,
      sourceCount: manifest.sourceCount,
      shardCount: manifest.shardCount,
      unavailableShardCount: unavailableShards.length
    },
    matches: matches.slice(0, 3)
  };
}

export function resetHistoricalReputationCache() {
  manifestCache.value = null;
  manifestCache.expiresAt = 0;
  shardCache.clear();
}
