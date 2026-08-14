// lib/threat_intelligence.js
// Cached, fail-safe lookup for the generated VerifyPulse threat-intelligence snapshot.

import { canonicalizeUrl, extractUrlCandidates } from './url_forensics.js';
import { fetchJsonWithTimeout } from './scan_reliability.js';

const SNAPSHOT_URL = 'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/latest_threat_intel.json';
const CACHE_TTL_MS = 60_000;
const MAX_INDICATORS = 5_000;
const snapshotCache = { snapshot: null, expiresAt: 0 };

function parseTimestamp(value) {
  const timestamp = Date.parse(String(value || ''));
  return Number.isFinite(timestamp) ? timestamp : null;
}

function validSnapshot(payload) {
  if (!payload || payload.schemaVersion !== 'vp-threat-intel-1' || !Array.isArray(payload.indicators)) return false;
  if (payload.indicators.length > MAX_INDICATORS) return false;
  const expiry = parseTimestamp(payload.expiresAt);
  return Boolean(expiry && expiry > Date.now());
}

async function getSnapshot() {
  if (snapshotCache.snapshot && Date.now() < snapshotCache.expiresAt) return snapshotCache.snapshot;
  try {
    const payload = await fetchJsonWithTimeout(SNAPSHOT_URL, {}, { provider: 'verify_pulse_threat_intel', timeoutMs: 900 });
    if (!validSnapshot(payload)) return null;
    snapshotCache.snapshot = payload;
    snapshotCache.expiresAt = Date.now() + CACHE_TTL_MS;
    return payload;
  } catch {
    // Threat-intelligence outages never create an unsafe SAFE verdict.
    return null;
  }
}

function indicatorMatches(candidate, indicator) {
  if (!indicator || !candidate) return false;
  const indicatorExpiry = parseTimestamp(indicator.expiresAt);
  if (!indicatorExpiry || indicatorExpiry <= Date.now()) return false;
  if (indicator.indicatorType === 'url') {
    const canonicalCandidate = `${candidate.protocol}//${candidate.hostname}${candidate.port ? `:${candidate.port}` : ''}${candidate.pathname || '/'}`;
    return canonicalCandidate === indicator.indicator;
  }
  if (indicator.indicatorType === 'domain') {
    const domain = String(indicator.hostname || indicator.indicator || '').toLowerCase();
    return candidate.hostname === domain || candidate.hostname.endsWith(`.${domain}`);
  }
  return false;
}

export async function lookupThreatIntelligence(text) {
  const candidates = extractUrlCandidates(text).map(canonicalizeUrl).filter(Boolean);
  if (candidates.length === 0) return { matched: false, checked: false, matches: [] };
  const snapshot = await getSnapshot();
  if (!snapshot) return { matched: false, checked: false, matches: [] };

  const matches = [];
  for (const candidate of candidates) {
    for (const indicator of snapshot.indicators) {
      if (!indicatorMatches(candidate, indicator)) continue;
      matches.push({
        hostname: candidate.hostname,
        indicatorType: indicator.indicatorType,
        confidence: Number(indicator.confidence) || 0,
        sourceCount: Number(indicator.sourceCount) || 0,
        sources: Array.isArray(indicator.sources) ? indicator.sources.slice(0, 4) : [],
        categories: Array.isArray(indicator.categories) ? indicator.categories.slice(0, 4) : [],
        expiresAt: indicator.expiresAt
      });
    }
  }

  matches.sort((left, right) => right.confidence - left.confidence || right.sourceCount - left.sourceCount);
  return {
    matched: matches.length > 0,
    checked: true,
    generatedAt: snapshot.generatedAt,
    matches: matches.slice(0, 3)
  };
}

export function resetThreatIntelligenceCache() {
  snapshotCache.snapshot = null;
  snapshotCache.expiresAt = 0;
}
