// lib/historical_reputation.js
// Fast exact reputation lookup over VerifyPulse's retained multi-source history.
// It fetches only hash-addressed index shards, never raw historical URL files.

import crypto from 'node:crypto';
import { canonicalizeUrl, extractUrlCandidates } from './url_forensics.js';
import { fetchJsonWithTimeout } from './scan_reliability.js';

const INDEX_BASE_URLS = [
  // First-party static delivery avoids depending on an external mirror when
  // the VerifyPulse deployment itself is healthy.
  'https://www.verify-pulse.com/pipeline/daily-data/historical-reputation-index',
  // Independent public mirrors protect the lookup if first-party static
  // delivery has a temporary deployment/CDN issue.
  'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/historical-reputation-index',
  'https://cdn.jsdelivr.net/gh/narayanglokhande2007-sudo/verify-pulse-@main/pipeline/daily-data/historical-reputation-index'
];
const SCHEMA_VERSION = 'vp-historical-reputation-index-1';
const MANIFEST_CACHE_TTL_MS = 10 * 60_000;
const SHARD_CACHE_TTL_MS = 10 * 60_000;
const STALE_CACHE_GRACE_MS = 6 * 60 * 60_000;
const MAX_SHARD_CACHE_ENTRIES = 96;
const MAX_CANDIDATES = 3;
const MAX_DOMAIN_KEYS_PER_CANDIDATE = 2;
const MAX_SHARD_RECORDS = 12_000;
const INDEX_SHARD_PREFIX_LENGTH = 3;
const INDEX_CIRCUIT_BACKOFF_MS = 20_000;

const manifestCache = { value: null, freshUntil: 0, staleUntil: 0, origin: null };
const shardCache = new Map();
const indexCircuit = { openUntil: 0, lastReason: null };
const runtimeHealth = {
  lastSuccessAt: null,
  lastFailureAt: null,
  lastFailureReason: null,
  lastOrigin: null,
  staleCacheUses: 0,
  fallbackOriginUses: 0
};

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

function cacheEntry(value, ttlMs, origin) {
  const now = Date.now();
  return { value, freshUntil: now + ttlMs, staleUntil: now + ttlMs + STALE_CACHE_GRACE_MS, origin };
}

function noteSuccess(origin, { stale = false, fallback = false } = {}) {
  // A real network success closes the circuit. A stale-cache recovery keeps
  // the circuit open briefly so repeated scans do not hammer unavailable hosts.
  if (!stale) {
    indexCircuit.openUntil = 0;
    indexCircuit.lastReason = null;
  }
  runtimeHealth.lastSuccessAt = new Date().toISOString();
  runtimeHealth.lastOrigin = origin || runtimeHealth.lastOrigin;
  if (stale) runtimeHealth.staleCacheUses += 1;
  if (fallback) runtimeHealth.fallbackOriginUses += 1;
}

function noteFailure(reason) {
  runtimeHealth.lastFailureAt = new Date().toISOString();
  runtimeHealth.lastFailureReason = String(reason || 'historical_index_unavailable').slice(0, 120);
}

async function fetchFromOrigins(relativePath, provider, timeoutMs, validate) {
  if (indexCircuit.openUntil > Date.now()) return null;
  let lastReason = 'historical_index_unavailable';
  for (let index = 0; index < INDEX_BASE_URLS.length; index += 1) {
    const origin = INDEX_BASE_URLS[index];
    try {
      const payload = await fetchJsonWithTimeout(`${origin}/${relativePath}`, {}, { provider, timeoutMs });
      if (!validate(payload)) {
        lastReason = 'historical_index_invalid_payload';
        continue;
      }
      noteSuccess(origin, { fallback: index > 0 });
      return { value: payload, origin, mode: index === 0 ? 'primary_network' : 'fallback_network' };
    } catch (error) {
      lastReason = error?.code || 'historical_index_network_error';
    }
  }
  indexCircuit.openUntil = Date.now() + INDEX_CIRCUIT_BACKOFF_MS;
  indexCircuit.lastReason = lastReason;
  noteFailure(lastReason);
  return null;
}

async function getManifest() {
  const now = Date.now();
  if (manifestCache.value && now < manifestCache.freshUntil) {
    return { value: manifestCache.value, origin: manifestCache.origin, mode: 'fresh_cache' };
  }
  const network = await fetchFromOrigins('manifest.json', 'historical_reputation_manifest', 550, validManifest);
  if (network) {
    Object.assign(manifestCache, cacheEntry(network.value, MANIFEST_CACHE_TTL_MS, network.origin));
    return network;
  }
  if (manifestCache.value && now < manifestCache.staleUntil) {
    noteSuccess(manifestCache.origin, { stale: true });
    return { value: manifestCache.value, origin: manifestCache.origin, mode: 'stale_cache' };
  }
  return null;
}

function trimShardCache() {
  while (shardCache.size > MAX_SHARD_CACHE_ENTRIES) {
    const oldestKey = shardCache.keys().next().value;
    shardCache.delete(oldestKey);
  }
}

function parseShard(payload) {
  const index = new Map();
  for (const record of payload.r) {
    if (!Array.isArray(record) || record.length !== 5) continue;
    const [hash, type] = record;
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash) || !['u', 'd'].includes(type)) continue;
    index.set(`${type}:${hash}`, record);
  }
  return index;
}

async function getShard(prefix) {
  const now = Date.now();
  const cached = shardCache.get(prefix);
  if (cached && now < cached.freshUntil) {
    // LRU-style refresh prevents popular shards from being evicted first.
    shardCache.delete(prefix);
    shardCache.set(prefix, cached);
    return { value: cached.value, origin: cached.origin, mode: 'fresh_cache' };
  }
  const network = await fetchFromOrigins(`shards/${prefix}.json`, 'historical_reputation_shard', 600, (payload) => validShard(payload, prefix));
  if (network) {
    const parsed = parseShard(network.value);
    const entry = cacheEntry(parsed, SHARD_CACHE_TTL_MS, network.origin);
    shardCache.set(prefix, entry);
    trimShardCache();
    return { value: parsed, origin: network.origin, mode: network.mode };
  }
  if (cached && now < cached.staleUntil) {
    shardCache.delete(prefix);
    shardCache.set(prefix, cached);
    noteSuccess(cached.origin, { stale: true });
    return { value: cached.value, origin: cached.origin, mode: 'stale_cache' };
  }
  return null;
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

function availabilityFrom(modes, unavailableShardCount) {
  if (unavailableShardCount > 0) return 'partial_unavailable';
  if (modes.includes('stale_cache')) return 'degraded_stale_cache';
  if (modes.includes('fallback_network')) return 'available_fallback_origin';
  return 'available';
}

export async function lookupHistoricalReputation(text) {
  const lookupEntries = buildHistoricalLookupKeys(text);
  if (lookupEntries.length === 0) return { matched: false, checked: false, availability: 'not_applicable', matches: [] };
  // The index format fixes a three-character prefix. Start manifest and shard
  // reads together, so a cold scan has only one bounded network wait.
  const neededPrefixes = [...new Set(lookupEntries.map((entry) => entry.hash.slice(0, INDEX_SHARD_PREFIX_LENGTH)))];
  const [manifestResult, shardPairs] = await Promise.all([
    getManifest(),
    Promise.all(neededPrefixes.map(async (prefix) => [prefix, await getShard(prefix)]))
  ]);
  if (!manifestResult) {
    return { matched: false, checked: false, availability: 'unavailable', matches: [] };
  }

  const manifest = manifestResult.value;
  const shards = new Map(shardPairs);
  const unavailableShards = neededPrefixes.filter((prefix) => !shards.get(prefix));
  const matches = [];
  const seen = new Set();

  for (const entry of lookupEntries) {
    const shardResult = shards.get(entry.hash.slice(0, manifest.shardPrefixLength));
    const record = shardResult?.value?.get(`${entry.type}:${entry.hash}`);
    if (!record) continue;
    const match = makeMatch(entry, record, manifest);
    const key = `${match.indicatorType}:${entry.hash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push(match);
  }

  matches.sort((left, right) => right.confidence - left.confidence || right.sourceCount - left.sourceCount);
  const modes = [manifestResult.mode, ...[...shards.values()].filter(Boolean).map((result) => result.mode)];
  return {
    matched: matches.length > 0,
    checked: unavailableShards.length === 0,
    availability: availabilityFrom(modes, unavailableShards.length),
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

export function getHistoricalReputationRuntimeHealth() {
  const now = Date.now();
  return {
    state: manifestCache.value && now < manifestCache.staleUntil ? 'ready_or_cached' : 'cold_or_unavailable',
    cache: {
      manifestFresh: Boolean(manifestCache.value && now < manifestCache.freshUntil),
      manifestStaleAvailable: Boolean(manifestCache.value && now < manifestCache.staleUntil),
      cachedShardCount: shardCache.size
    },
    circuit: {
      open: indexCircuit.openUntil > now,
      retryAfterMs: Math.max(0, indexCircuit.openUntil - now),
      lastReason: indexCircuit.lastReason
    },
    ...runtimeHealth
  };
}

export function resetHistoricalReputationCache() {
  manifestCache.value = null;
  manifestCache.freshUntil = 0;
  manifestCache.staleUntil = 0;
  manifestCache.origin = null;
  shardCache.clear();
  indexCircuit.openUntil = 0;
  indexCircuit.lastReason = null;
  runtimeHealth.lastSuccessAt = null;
  runtimeHealth.lastFailureAt = null;
  runtimeHealth.lastFailureReason = null;
  runtimeHealth.lastOrigin = null;
  runtimeHealth.staleCacheUses = 0;
  runtimeHealth.fallbackOriginUses = 0;
}
