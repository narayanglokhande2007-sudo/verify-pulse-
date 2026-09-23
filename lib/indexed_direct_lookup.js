// lib/indexed_direct_lookup.js
// Ultra-Fast B2B Direct Indexed Volume Lookup
// Bypasses all HTTP network calls by reading the hash shards directly from local SSD.
// Includes in-memory caching and Blue-Green safe reading.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildHistoricalLookupKeys } from './historical_reputation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Target the local data volume built by Python pipeline
const INDEX_DIR = path.join(__dirname, '..', 'pipeline', 'daily-data', 'historical-reputation-index');
const MANIFEST_PATH = path.join(INDEX_DIR, 'manifest.json');

// RAM Cache for Zero-Latency Lookups
let memoryCache = {
    manifest: null,
    manifestLoadedAt: 0,
    shards: new Map() // prefix -> shard data
};

const CACHE_TTL_MS = 5 * 60 * 1000; // Refresh cache every 5 minutes safely
const MAX_SHARD_CACHE_ENTRIES = 500;

/**
 * Safely loads manifest from local disk
 */
async function getLocalManifest() {
    const now = Date.now();
    if (memoryCache.manifest && (now - memoryCache.manifestLoadedAt < CACHE_TTL_MS)) {
        return memoryCache.manifest;
    }

    try {
        const raw = await fs.readFile(MANIFEST_PATH, 'utf-8');
        const manifest = JSON.parse(raw);
        memoryCache.manifest = manifest;
        memoryCache.manifestLoadedAt = now;
        return manifest;
    } catch (error) {
        console.error('[Direct Indexed Volume] Failed to load local manifest:', error.message);
        return null;
    }
}

/**
 * Safely loads shard from local disk with LRU cache
 */
async function getLocalShard(prefix) {
    const cached = memoryCache.shards.get(prefix);
    if (cached) {
        // LRU bump
        memoryCache.shards.delete(prefix);
        memoryCache.shards.set(prefix, cached);
        return cached;
    }

    try {
        const shardPath = path.join(INDEX_DIR, 'shards', `${prefix}.json`);
        const raw = await fs.readFile(shardPath, 'utf-8');
        const payload = JSON.parse(raw);
        
        // Convert to optimized Map for O(1) matching
        const shardMap = new Map();
        for (const record of payload.r) {
            const [hash, type] = record;
            shardMap.set(`${type}:${hash}`, record);
        }

        memoryCache.shards.set(prefix, shardMap);

        // Prevent memory leak (trim cache)
        if (memoryCache.shards.size > MAX_SHARD_CACHE_ENTRIES) {
            const oldest = memoryCache.shards.keys().next().value;
            memoryCache.shards.delete(oldest);
        }

        return shardMap;
    } catch (error) {
        // Shard doesn't exist (means URL is completely unknown)
        if (error.code !== 'ENOENT') {
            console.error(`[Direct Indexed Volume] Error reading shard ${prefix}:`, error.message);
        }
        return null;
    }
}

/**
 * Main B2B Entrypoint: Fast Direct Indexed Lookup
 * Time Complexity: O(1), Latency: < 1ms
 */
export async function directLocalLookup(urlText) {
    const startTime = Date.now();
    
    // Step 1: Normalize URL (Rule: 12-step plan, Point 4)
    const lookupEntries = buildHistoricalLookupKeys(urlText);
    if (lookupEntries.length === 0) {
        return { matched: false, lookup_time_ms: Date.now() - startTime };
    }

    // Step 2: Ensure Volume is mounted (Read Manifest)
    const manifest = await getLocalManifest();
    if (!manifest) {
        return { matched: false, error: "volume_offline", lookup_time_ms: Date.now() - startTime };
    }

    // Step 3: Fast Disk/RAM check for unique hashes
    const neededPrefixes = [...new Set(lookupEntries.map(entry => entry.hash.slice(0, manifest.shardPrefixLength)))];
    
    const shards = new Map();
    for (const prefix of neededPrefixes) {
        shards.set(prefix, await getLocalShard(prefix));
    }

    // Step 4: Verify against loaded dictionary
    const matches = [];
    const seen = new Set();

    for (const entry of lookupEntries) {
        const shardMap = shards.get(entry.hash.slice(0, manifest.shardPrefixLength));
        if (!shardMap) continue;

        const record = shardMap.get(`${entry.type}:${entry.hash}`);
        if (record) {
            // MATCH FOUND IN DIRECT VOLUME!
            const [, type, sourceIds, firstSeenEpoch, lastSeenEpoch] = record;
            const key = `${type}:${entry.hash}`;
            
            if (!seen.has(key)) {
                seen.add(key);
                
                // Decode Source evidence
                const sources = [];
                for (const id of sourceIds) {
                    const sourceInfo = manifest.sourceCatalog.find(s => s.id === id);
                    if (sourceInfo) sources.push(sourceInfo.name);
                }

                matches.push({
                    indicatorType: type === 'u' ? 'url' : 'domain',
                    hostname: entry.hostname,
                    sourceCount: sources.length,
                    sources: sources,
                    confidence: 95, // High confidence for indexed match
                    firstSeen: firstSeenEpoch ? new Date(firstSeenEpoch * 1000).toISOString() : null,
                    lastSeen: lastSeenEpoch ? new Date(lastSeenEpoch * 1000).toISOString() : null
                });
            }
        }
    }

    // Sort to keep highest confidence first
    matches.sort((a, b) => b.confidence - a.confidence || b.sourceCount - a.sourceCount);

    return {
        matched: matches.length > 0,
        matches: matches,
        lookup_time_ms: Date.now() - startTime,
        data_source: "direct_indexed_volume"
    };
}
