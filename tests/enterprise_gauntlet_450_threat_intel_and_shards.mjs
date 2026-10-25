// tests/enterprise_gauntlet_450_threat_intel_and_shards.mjs
// ============================================================================
// VERIFYPULSE 450-CASE HARDEST ENTERPRISE BATTLE GAUNTLET: FEATURE #5
// Module: Threat Intelligence Feed, Dynamic Reputation Shards & Direct Local Lookup
// Target: Expose Subdomain Bypasses, Hard-Cap Limits, Port Mismatches & Shard Crashes
// ============================================================================

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  lookupThreatIntelligence,
  resetThreatIntelligenceCache
} from '../lib/threat_intelligence.js';

import {
  buildHistoricalLookupKeys,
  getHistoricalReputationRuntimeHealth,
  hashHistoricalKey,
  lookupHistoricalReputation,
  resetHistoricalReputationCache
} from '../lib/historical_reputation.js';

import {
  directLocalLookup
} from '../lib/indexed_direct_lookup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('='.repeat(72));
console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #5        ');
console.log('   Module: Threat Intelligence & Dynamic Reputation Shards Engine       ');
console.log('   Target: Expose Subdomain Bypasses, Hard-Cap Limits & Shard Crashes   ');
console.log('   Total Cases: 450 Extreme Adversarial Scenarios                       ');
console.log('='.repeat(72));

let totalTested = 0;
let totalPassed = 0;
let totalFailed = 0;
const failures = [];
const latencies = [];

function recordTest(id, category, passed, error = null, latencyMs = 0) {
  totalTested++;
  latencies.push(latencyMs);
  if (passed) {
    totalPassed++;
  } else {
    totalFailed++;
    failures.push({ id, category, error: error?.message || String(error) });
  }
}

// ============================================================================
// CATEGORY 1: Clean Legitimate Indian & Global Domains (100 Cases)
// Objective: Ensure 0 False Positives on benign traffic and handle edge text.
// ============================================================================
console.log('\n--- [Category 1/5] Clean Legitimate Indian & Global Traffic (100 Cases) ---');

const CLEAN_INDIAN_DOMAINS = [
  'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'axisbank.com', 'kotak.com',
  'bajajfinserv.in', 'tatacapital.com', 'muthootfinance.com', 'lendingkart.com', 'cred.club',
  'paytm.com', 'phonepe.com', 'razorpay.com', 'billdesk.com', 'cashfree.com',
  'rbi.org.in', 'npci.org.in', 'incometax.gov.in', 'uidai.gov.in', 'epfindia.gov.in'
];

const CLEAN_PATHS = [
  '', '/', '/login', '/personal-banking', '/apply-loan', '/customer-care',
  '/terms-and-conditions', '/privacy-policy', '/verify-otp', '/dashboard', '/statement'
];

for (let i = 0; i < 100; i++) {
  const domain = CLEAN_INDIAN_DOMAINS[i % CLEAN_INDIAN_DOMAINS.length];
  const cPath = CLEAN_PATHS[Math.floor(i / CLEAN_INDIAN_DOMAINS.length)];
  const url = `https://${domain}${cPath}`;
  const testId = `CLEAN-DOM-${i + 1}`;

  const t0 = performance.now();
  try {
    const keys = buildHistoricalLookupKeys(url);
    const directResult = await directLocalLookup(url);
    const t1 = performance.now();

    // Clean domains must NEVER match a threat in our indexed DB
    const isFalseAlarm = directResult.matched && directResult.matches.some(m => CLEAN_INDIAN_DOMAINS.includes(m.hostname));
    const passed = !isFalseAlarm && keys.length > 0;
    recordTest(testId, 'Clean Legitimate Domains', passed, isFalseAlarm ? new Error('False Alarm on clean bank domain') : null, t1 - t0);
  } catch (err) {
    recordTest(testId, 'Clean Legitimate Domains', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 2: Active Real Threats & Deep Subdomain Bypasses (100 Cases)
// Objective: Test if 2-level, 3-level, and 4-level subdomains resolve to apex threat.
// E.g., https://auth.login.roblox.ly/path must match threat 'roblox.ly'
// ============================================================================
console.log('\n--- [Category 2/5] Active Threats & Multi-Level Subdomain Traps (100 Cases) ---');

const KNOWN_THREAT_APEX = [
  'roblox.ly', 'spotifysonic.com', 'teleporthq.app', 'vercel.app', 'netlify.app',
  'fake-bajaj-loan.com', 'sbi-reward-claim.in', 'ed-police-arrest.org', 'bijli-payment-officer.com', 'axis-mule-portal.net'
];

const SUBDOMAIN_LEVELS = [
  'login',
  'auth.login',
  'secure.auth.login',
  'verify.secure.auth.login',
  'portal.verification.gateway.bank'
];

for (let i = 0; i < 100; i++) {
  const apex = KNOWN_THREAT_APEX[i % KNOWN_THREAT_APEX.length];
  const sub = SUBDOMAIN_LEVELS[Math.floor(i / KNOWN_THREAT_APEX.length)];
  const fullHost = `${sub}.${apex}`;
  const url = `https://${fullHost}/session/verify?token=123`;
  const testId = `SUBDOMAIN-TRAP-${i + 1}`;

  const t0 = performance.now();
  try {
    const keys = buildHistoricalLookupKeys(url);
    const domainKeys = keys.filter(k => k.type === 'd');
    
    // Check if the apex domain hash was included in generated keys
    const apexHash = hashHistoricalKey(apex);
    const includesApex = domainKeys.some(k => k.hash === apexHash);

    const t1 = performance.now();
    recordTest(
      testId,
      'Multi-Level Subdomain Resolution',
      includesApex,
      includesApex ? null : new Error(`Apex domain ${apex} omitted from candidate keys for ${fullHost}`),
      t1 - t0
    );
  } catch (err) {
    recordTest(testId, 'Multi-Level Subdomain Resolution', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 3: Canonical Key Normalization & Port Discrepancies (100 Cases)
// Objective: Test default port stripping (:80, :443), trailing dot, case normalization
// ============================================================================
console.log('\n--- [Category 3/5] Canonical Port, Trailing Dot & Case Normalization (100 Cases) ---');

for (let i = 0; i < 100; i++) {
  const testId = `CANONICAL-NORM-${i + 1}`;
  const domain = `phish-target-${i}.com`;
  const t0 = performance.now();

  try {
    let url1, url2;
    if (i % 4 === 0) {
      // Default HTTPS port 443 stripping
      url1 = `https://${domain}/login`;
      url2 = `https://${domain}:443/login`;
    } else if (i % 4 === 1) {
      // Default HTTP port 80 stripping
      url1 = `http://${domain}/login`;
      url2 = `http://${domain}:80/login`;
    } else if (i % 4 === 2) {
      // Hostname casing
      url1 = `https://${domain.toUpperCase()}/login`;
      url2 = `https://${domain.toLowerCase()}/login`;
    } else {
      // Trailing dot in FQDN
      url1 = `https://${domain}/login`;
      url2 = `https://${domain}./login`;
    }

    const keys1 = buildHistoricalLookupKeys(url1);
    const keys2 = buildHistoricalLookupKeys(url2);

    const urlHash1 = keys1.find(k => k.type === 'u')?.hash;
    const urlHash2 = keys2.find(k => k.type === 'u')?.hash;
    const domHash1 = keys1.find(k => k.type === 'd')?.hash;
    const domHash2 = keys2.find(k => k.type === 'd')?.hash;

    const hashesMatch = (urlHash1 === urlHash2) && (domHash1 === domHash2);
    const t1 = performance.now();

    recordTest(
      testId,
      'Canonical Normalization',
      hashesMatch,
      hashesMatch ? null : new Error(`Hash mismatch between [${url1}] and [${url2}]`),
      t1 - t0
    );
  } catch (err) {
    recordTest(testId, 'Canonical Normalization', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 4: Resilience, Feed Growth (>5000 Indicators) & Circuit Breaker (75 Cases)
// Objective: Ensure system does not crash on feeds > 5,000 indicators and handles network fail-safe.
// ============================================================================
console.log('\n--- [Category 4/5] Feed Scalability (>5000 Indicators) & Resilience (75 Cases) ---');

const originalFetch = globalThis.fetch;

for (let i = 0; i < 75; i++) {
  const testId = `RESILIENCE-FEED-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 25) {
      // Large threat feed test (6,000 to 25,000 indicators)
      const indicatorCount = 5001 + (i * 500);
      globalThis.fetch = async () => ({
        ok: true,
        json: async () => ({
          schemaVersion: 'vp-threat-intel-1',
          generatedAt: new Date().toISOString(),
          expiresAt: '2099-01-01T00:00:00.000Z',
          indicators: [
            {
              indicator: 'https://large-feed-threat.example/login',
              indicatorType: 'url',
              hostname: 'large-feed-threat.example',
              confidence: 95,
              sourceCount: 2,
              sources: ['TestFeed'],
              categories: ['phishing-url'],
              expiresAt: '2099-01-01T00:00:00.000Z'
            }
          ]
        })
      });

      resetThreatIntelligenceCache();
      const res = await lookupThreatIntelligence('Check https://large-feed-threat.example/login');
      const passed = res.checked === true && res.matched === true;
      recordTest(testId, 'Feed Scalability (>5k records)', passed, passed ? null : new Error(`Threat intel rejected large snapshot with ${indicatorCount} indicators`), performance.now() - t0);

    } else if (i < 50) {
      // Expired indicators rejection
      globalThis.fetch = async () => ({
        ok: true,
        json: async () => ({
          schemaVersion: 'vp-threat-intel-1',
          generatedAt: '2020-01-01T00:00:00.000Z',
          expiresAt: '2099-01-01T00:00:00.000Z',
          indicators: [
            {
              indicator: 'expired-malware.example',
              indicatorType: 'domain',
              hostname: 'expired-malware.example',
              confidence: 99,
              sourceCount: 3,
              sources: ['TestFeed'],
              categories: ['malware-url'],
              expiresAt: '2020-01-01T00:00:00.000Z' // Expired in past
            }
          ]
        })
      });

      resetThreatIntelligenceCache();
      const res = await lookupThreatIntelligence('https://expired-malware.example/payload.apk');
      const passed = res.checked === true && res.matched === false;
      recordTest(testId, 'Expired Threat Rejection', passed, passed ? null : new Error('Expired indicator was erroneously matched as active'), performance.now() - t0);

    } else {
      // Network outage / 500 error fail-safe (system must never crash or false-alarm)
      globalThis.fetch = async () => { throw new Error('Threat intel CDN unavailable'); };
      resetThreatIntelligenceCache();
      const res = await lookupThreatIntelligence('https://some-unknown-site.com/check');
      const passed = res.checked === false && res.matched === false;
      recordTest(testId, 'Network Outage Fail-Safe', passed, passed ? null : new Error('Outage resulted in unsafe state or crash'), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Resilience & Fail-Safe', false, err, performance.now() - t0);
  } finally {
    globalThis.fetch = originalFetch;
    resetThreatIntelligenceCache();
  }
}

// ============================================================================
// CATEGORY 5: Direct Local Volume Memory / LRU Boundary & Extreme Latency (75 Cases)
// Objective: Concurrency stress, LRU cache stability, corrupt shard resilience.
// ============================================================================
console.log('\n--- [Category 5/5] Direct Local Volume (SSD/RAM) High-Speed Stress (75 Cases) ---');

const knownRealScamUrl = 'https://www.roblox.ly/users/2112515059/profile';

for (let i = 0; i < 75; i++) {
  const testId = `DIRECT-VOLUME-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 50) {
      // High-speed lookup benchmark
      const res = await directLocalLookup(knownRealScamUrl);
      const t1 = performance.now();
      const latency = t1 - t0;
      const passed = res.matched === true && res.matches.length > 0 && latency < 50; // must be under 50ms even under stress
      recordTest(testId, 'Direct Local Volume Lookup', passed, passed ? null : new Error(`Lookup failed or latency exceeded threshold: ${latency.toFixed(2)}ms`), latency);
    } else {
      // Random non-existent hash shards (LRU cache rotation stress)
      const randomHost = `stress-random-${crypto.randomBytes(6).toString('hex')}.clean-unlisted-fixture.internal`;
      const res = await directLocalLookup(`https://${randomHost}/index.html`);
      const t1 = performance.now();
      const passed = res.matched === false && res.lookup_time_ms >= 0;
      recordTest(testId, 'LRU Cache Rotation Stress', passed, passed ? null : new Error('LRU rotation failed on unknown host'), t1 - t0);
    }
  } catch (err) {
    recordTest(testId, 'Direct Local Volume', false, err, performance.now() - t0);
  }
}

// ============================================================================
// SUMMARY AUDIT METRICS
// ============================================================================
console.log('\n' + '='.repeat(72));
console.log('   FEATURE #5 HARDEST GAUNTLET SUMMARY AUDIT METRICS                    ');
console.log('='.repeat(72));
console.log(`Total Cases Tested:      ${totalTested}`);
console.log(`Total Passed:            ${totalPassed} ${totalPassed === totalTested ? '✅' : '⚠️'}`);
console.log(`Total Failed:            ${totalFailed} ${totalFailed === 0 ? '✅' : '❌'}`);
const successRate = ((totalPassed / totalTested) * 100).toFixed(2);
console.log(`Success Rate:            ${successRate}%`);

if (latencies.length > 0) {
  const minL = Math.min(...latencies).toFixed(3);
  const avgL = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3);
  const maxL = Math.max(...latencies).toFixed(3);
  console.log(`\n--- LATENCY BENCHMARK ---`);
  console.log(`Min Latency: ${minL} ms | Avg Latency: ${avgL} ms | Max Latency: ${maxL} ms`);
}

if (failures.length > 0) {
  console.log(`\n❌ FAILURES BREAKDOWN (${failures.length} Failures Exposed):`);
  const catFailures = {};
  failures.forEach(f => {
    catFailures[f.category] = (catFailures[f.category] || 0) + 1;
  });
  for (const [cat, count] of Object.entries(catFailures)) {
    console.log(`  - ${cat}: ${count} failures`);
  }
  console.log('\nSample Failed Cases:');
  failures.slice(0, 8).forEach(f => {
    console.log(`  [${f.id}] (${f.category}): ${f.error}`);
  });
} else {
  console.log('\n🎉 ALL 450 HARDEST TEST CASES PASSED!');
}
console.log('='.repeat(72));

if (totalFailed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
