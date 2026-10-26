// tests/enterprise_gauntlet_450_brand_monitor_and_zeroday.mjs
// ============================================================================
// VERIFYPULSE 450-CASE HARDEST ENTERPRISE BATTLE GAUNTLET: FEATURE #6
// Module: Continuous Brand Monitor & Zero-Day Certificate Transparency (CT) Engine
// Target: Expose Official Domain False Positives, Future-Date Bypasses, Tier Leaks & Fallbacks
// ============================================================================

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

import {
  executeContinuousBrandScan,
  registerTenantBrandKeywords,
  getRegisteredTenantBrandKeywords
} from '../lib/continuous_brand_monitor.js';

import zerodayHandler from '../api/zeroday.js';

console.log('='.repeat(72));
console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #6        ');
console.log('   Module: Continuous Brand Monitor & Zero-Day CT Engine                ');
console.log('   Target: Real-World Phishing, Bank Whitelisting, Tier Gates & DoH     ');
console.log('   Total Cases: 450 Extreme Adversarial Scenarios                       ');
console.log('='.repeat(72));

function hash(v) {
  return crypto.createHash('sha256').update(v).digest('hex');
}

const keyTier3 = 'vp_test_tier3_ultra_key_333';
const keyTier2 = 'vp_test_tier2_pro_key_222';
const keyTier1 = 'vp_test_tier1_starter_key_111';
const keyNoScope = 'vp_test_noscope_key_000';

process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
  {
    keyId: 'ultra-corp',
    tenantId: 'enterprise_bank_ultra',
    tier: 3,
    sha256: hash(keyTier3),
    scopes: ['b2b:zeroday', 'b2b:scan'],
    expiresAt: '2099-01-01T00:00:00.000Z',
    status: 'active'
  },
  {
    keyId: 'pro-corp',
    tenantId: 'enterprise_bank_pro',
    tier: 2,
    sha256: hash(keyTier2),
    scopes: ['b2b:zeroday', 'b2b:scan'],
    expiresAt: '2099-01-01T00:00:00.000Z',
    status: 'active'
  },
  {
    keyId: 'starter-corp',
    tenantId: 'starter_bank',
    tier: 1,
    sha256: hash(keyTier1),
    scopes: ['b2b:scan'],
    expiresAt: '2099-01-01T00:00:00.000Z',
    status: 'active'
  },
  {
    keyId: 'noscope-corp',
    tenantId: 'noscope_bank',
    tier: 2,
    sha256: hash(keyNoScope),
    scopes: ['b2b:payguard'],
    expiresAt: '2099-01-01T00:00:00.000Z',
    status: 'active'
  }
]);

function getProHeaders(suffix = 1) {
  return {
    'x-api-key': keyTier2,
    'x-verifypulse-key-id': 'pro-corp',
    'x-forwarded-for': `198.51.100.${(suffix % 200) + 1}`
  };
}

function getUltraHeaders(suffix = 1) {
  return {
    'x-api-key': keyTier3,
    'x-verifypulse-key-id': 'ultra-corp',
    'x-forwarded-for': `198.51.101.${(suffix % 200) + 1}`
  };
}

function getStarterHeaders(suffix = 1) {
  return {
    'x-api-key': keyTier1,
    'x-verifypulse-key-id': 'starter-corp',
    'x-forwarded-for': `198.51.102.${(suffix % 200) + 1}`
  };
}

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

function createMockExchange(body = {}, headers = {}, query = {}, method = 'POST') {
  let statusCode = 200;
  let responseData = null;
  const responseHeaders = {};

  const req = {
    method,
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Enterprise-CISO-BattleTester/2.0',
      'x-forwarded-for': '127.0.0.1',
      ...headers
    },
    query,
    body
  };

  const res = {
    setHeader(key, val) {
      responseHeaders[key.toLowerCase()] = val;
      return res;
    },
    status(code) {
      statusCode = code;
      return res;
    },
    json(data) {
      responseData = data;
      return res;
    },
    end() {
      return res;
    }
  };

  return { req, res, getResult: () => ({ statusCode, responseData, responseHeaders }) };
}

// ============================================================================
// CATEGORY 1: Official Domain Whitelist & Zero False-Positive Shield (90 Cases)
// Objective: Prove bank official domains AND ALL their subdomains NEVER flag as threats.
// ============================================================================
console.log('\n--- [Category 1/5] Official Domain Whitelisting & Subdomain Shield (90 Cases) ---');

const BANK_PORTFOLIOS = [
  {
    brand: 'hdfc',
    official: 'hdfcbank.com',
    subdomains: ['netbanking.hdfcbank.com', 'mycards.hdfcbank.com', 'loans.hdfcbank.com', 'api.hdfcbank.com', 'corporate.hdfcbank.com', 'retail.netbanking.hdfcbank.com']
  },
  {
    brand: 'sbi',
    official: 'sbi.co.in',
    subdomains: ['onlinesbi.sbi.co.in', 'retail.onlinesbi.sbi.co.in', 'yonobusiness.sbi.co.in', 'corp.sbi.co.in', 'merchant.sbi.co.in', 'netbanking.sbi.co.in']
  },
  {
    brand: 'icici',
    official: 'icicibank.com',
    subdomains: ['infinity.icicibank.com', 'corporate.icicibank.com', 'loanportal.icicibank.com', 'api.icicibank.com', 'secure.icicibank.com', 'imobile.icicibank.com']
  },
  {
    brand: 'bajaj',
    official: 'bajajfinserv.in',
    subdomains: ['customer-portal.bajajfinserv.in', 'experia.bajajfinserv.in', 'cards.bajajfinserv.in', 'pay.bajajfinserv.in', 'emi.bajajfinserv.in', 'auth.bajajfinserv.in']
  },
  {
    brand: 'kreditbee',
    official: 'kreditbee.in',
    subdomains: ['api.kreditbee.in', 'auth.kreditbee.in', 'app.kreditbee.in', 'disbursal.kreditbee.in', 'portal.kreditbee.in', 'docs.kreditbee.in']
  }
];

const originalFetch = globalThis.fetch;

for (let i = 0; i < 90; i++) {
  const testId = `OFFICIAL-SHIELD-${i + 1}`;
  const bank = BANK_PORTFOLIOS[i % BANK_PORTFOLIOS.length];
  const testedSubdomain = bank.subdomains[i % bank.subdomains.length];
  const t0 = performance.now();

  try {
    // Mock CT Log response containing official subdomains alongside a real rogue phishing domain
    const mockCtData = [
      {
        name_value: `${testedSubdomain}\n*.${testedSubdomain}`,
        not_before: new Date().toISOString(),
        issuer_name: "DigiCert Global Root CA"
      },
      {
        name_value: `fake-${bank.brand}-kyc-update-${i}.com`,
        not_before: new Date().toISOString(),
        issuer_name: "Let's Encrypt"
      }
    ];

    globalThis.fetch = async (url) => {
      const uStr = String(url);
      if (uStr.includes('crt.sh')) {
        return {
          ok: true,
          json: async () => mockCtData
        };
      }
      if (uStr.includes('dns.google')) {
        return {
          ok: true,
          json: async () => ({ Answer: [{ type: 1, data: '104.21.5.12' }] })
        };
      }
      throw new Error(`Unexpected fetch URL: ${uStr}`);
    };

    if (i % 2 === 0) {
      // Test 1: lib/continuous_brand_monitor.js
      const report = await executeContinuousBrandScan({
        tenantId: `tenant_${bank.brand}_${i}`,
        keywords: [bank.brand],
        officialDomains: [bank.official]
      });

      const flaggedOfficial = (report.threats || []).some(
        (t) => t.domain === bank.official || t.domain === testedSubdomain || t.domain.endsWith(`.${bank.official}`)
      );
      const caughtRogue = (report.threats || []).some((t) => t.domain.includes(`fake-${bank.brand}`));
      const passed = !flaggedOfficial && caughtRogue;
      recordTest(testId, 'Continuous Brand Monitor Whitelisting', passed, flaggedOfficial ? new Error(`Official subdomain ${testedSubdomain} erroneously flagged as threat`) : null, performance.now() - t0);
    } else {
      // Test 2: api/zeroday.js endpoint
      const exchange = createMockExchange(
        { keyword: bank.brand, officialDomain: bank.official },
        getProHeaders(i)
      );
      await zerodayHandler(exchange.req, exchange.res);
      const res = exchange.getResult();

      const flaggedOfficial = (res.responseData?.suspiciousDomains || []).some(
        (d) => d === bank.official || d === testedSubdomain || d.endsWith(`.${bank.official}`)
      );
      const caughtRogue = (res.responseData?.suspiciousDomains || []).some((d) => d.includes(`fake-${bank.brand}`));
      const passed = res.statusCode === 200 && !flaggedOfficial && caughtRogue;
      recordTest(testId, 'ZeroDay API Official Subdomain Isolation', passed, flaggedOfficial ? new Error(`api/zeroday.js leaked official subdomain ${testedSubdomain} into suspiciousDomains`) : (res.statusCode !== 200 ? new Error(`HTTP ${res.statusCode}`) : null), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Official Domain Isolation', false, err, performance.now() - t0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ============================================================================
// CATEGORY 2: Real-World Zero-Day Phishing & Keyword Combos (90 Cases)
// Objective: Catch multiline SANs, wildcards, punycode, brand combos within 72h window.
// ============================================================================
console.log('\n--- [Category 2/5] Real-World Zero-Day Phishing & Keyword Combos (90 Cases) ---');

const ROGUE_PATTERNS = [
  'sbi-kyc-pan-link', 'hdfc-netbanking-login-auth', 'bajaj-instant-card-disbursal',
  'icici-reward-cashback-claim', 'kreditbee-instant-loan-portal', 'muthoot-gold-loan-disbursal',
  'axis-bank-mule-verification', 'tatacapital-preapproved-clearance', 'paytm-kyc-unblock-desk'
];

for (let i = 0; i < 90; i++) {
  const testId = `ROGUE-CT-${i + 1}`;
  const pattern = ROGUE_PATTERNS[i % ROGUE_PATTERNS.length];
  const t0 = performance.now();

  try {
    const rogueDomain = `${pattern}-${i}.com`;
    const rogueWildcard = `*.sub.${pattern}-${i}.org`;
    const now = new Date();
    const certDate = new Date(now.getTime() - ((i % 70) * 60 * 60 * 1000)).toISOString(); // within 70 hours

    globalThis.fetch = async (url) => {
      const uStr = String(url);
      if (uStr.includes('crt.sh')) {
        return {
          ok: true,
          json: async () => [
            {
              name_value: `${rogueDomain}\n${rogueWildcard}`,
              not_before: certDate,
              issuer_name: "Let's Encrypt Authority X3"
            }
          ]
        };
      }
      if (uStr.includes('dns.google')) {
        return {
          ok: true,
          json: async () => ({ Answer: [{ type: 1, data: '185.199.108.153' }] })
        };
      }
      throw new Error(`Unexpected fetch URL: ${uStr}`);
    };

    const exchange = createMockExchange(
      { keyword: pattern.split('-')[0], officialDomain: 'cleanbank.com' },
      getProHeaders(i + 50)
    );
    await zerodayHandler(exchange.req, exchange.res);
    const res = exchange.getResult();

    const domains = res.responseData?.suspiciousDomains || [];
    const foundRogue = domains.some((d) => d === rogueDomain || d.includes(pattern));
    const passed = res.statusCode === 200 && foundRogue && domains.length > 0;

    recordTest(testId, 'Rogue Zero-Day Detection', passed, passed ? null : new Error(`Failed to catch rogue zero-day domain ${rogueDomain} (status ${res.statusCode})`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Rogue Zero-Day Detection', false, err, performance.now() - t0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ============================================================================
// CATEGORY 3: Future-Dated, Expired & Stale Certificate Filtering (90 Cases)
// Objective: Certs >72h old or future-dated (>2h in future) MUST BE REJECTED.
// ============================================================================
console.log('\n--- [Category 3/5] Future-Dated & Expired Certificate Filtering (90 Cases) ---');

for (let i = 0; i < 90; i++) {
  const testId = `TIME-WINDOW-${i + 1}`;
  const t0 = performance.now();

  try {
    const now = new Date();
    let certDate;
    let shouldBeAccepted = false;

    if (i < 30) {
      // Stale / Old certificates (75 to 500 hours old) -> MUST BE REJECTED
      const hoursAgo = 75 + (i * 10);
      certDate = new Date(now.getTime() - (hoursAgo * 60 * 60 * 1000)).toISOString();
      shouldBeAccepted = false;
    } else if (i < 60) {
      // Future-dated certificates (> 5 hours in future) -> MUST BE REJECTED
      const hoursFuture = 5 + (i * 2);
      certDate = new Date(now.getTime() + (hoursFuture * 60 * 60 * 1000)).toISOString();
      shouldBeAccepted = false;
    } else {
      // Valid fresh certificates (1 to 48 hours old) -> MUST BE ACCEPTED
      const hoursAgo = 1 + (i % 48);
      certDate = new Date(now.getTime() - (hoursAgo * 60 * 60 * 1000)).toISOString();
      shouldBeAccepted = true;
    }

    const testDomain = `timing-test-${i}.net`;

    globalThis.fetch = async (url) => {
      const uStr = String(url);
      if (uStr.includes('crt.sh')) {
        return {
          ok: true,
          json: async () => [
            {
              name_value: testDomain,
              not_before: certDate,
              issuer_name: "Let's Encrypt"
            }
          ]
        };
      }
      return { ok: true, json: async () => ({ Answer: [] }) };
    };

    const report = await executeContinuousBrandScan({
      tenantId: `timing_test_tenant_${i}`,
      keywords: ['timing'],
      officialDomains: ['clean-official.com']
    });

    const wasCaught = (report.threats || []).some((t) => t.domain === testDomain);
    const passed = shouldBeAccepted ? wasCaught : !wasCaught;

    const errMsg = shouldBeAccepted
      ? `Fresh certificate (${certDate}) was improperly omitted`
      : `Stale or future certificate (${certDate}) was improperly accepted as zero-day!`;

    recordTest(testId, 'Certificate Time-Window Enforcement', passed, passed ? null : new Error(errMsg), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Certificate Time-Window Enforcement', false, err, performance.now() - t0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ============================================================================
// CATEGORY 4: B2B Security, Tier Gatekeeping, Scopes & Quotas (90 Cases)
// Objective: Validate 401 unauth, 403 Tier 1, 403 Tier 2 multi-keyword, 400 empty body.
// ============================================================================
console.log('\n--- [Category 4/5] B2B Security, Tier Gatekeeping & Quotas (90 Cases) ---');

for (let i = 0; i < 90; i++) {
  const testId = `SECURITY-TIER-${i + 1}`;
  const t0 = performance.now();

  try {
    let exchange;
    let expectedStatus;

    if (i < 20) {
      // Unauthenticated request (no API key)
      exchange = createMockExchange({ keyword: 'sbi' }, { 'x-forwarded-for': `198.51.103.${i + 1}` });
      expectedStatus = 401;
    } else if (i < 40) {
      // Tier 1 API key trying to use Zero-Day Monitor
      exchange = createMockExchange(
        { keyword: 'sbi' },
        getStarterHeaders(i + 10)
      );
      expectedStatus = 403;
    } else if (i < 60) {
      // Missing keyword payload
      exchange = createMockExchange(
        {},
        getProHeaders(i + 20)
      );
      expectedStatus = 400;
    } else if (i < 75) {
      // Tier 2 attempting multi-keyword batch (Exclusive to Tier 3)
      exchange = createMockExchange(
        { keywords: ['hdfc', 'sbi', 'icici'] },
        getProHeaders(i + 30)
      );
      expectedStatus = 403;
    } else {
      // Wrong HTTP method (GET instead of POST)
      exchange = createMockExchange({}, getProHeaders(i + 40), {}, 'GET');
      expectedStatus = 405;
    }

    await zerodayHandler(exchange.req, exchange.res);
    const res = exchange.getResult();
    const passed = res.statusCode === expectedStatus;

    recordTest(
      testId,
      'B2B Security & Tier Enforcement',
      passed,
      passed ? null : new Error(`Expected HTTP ${expectedStatus} but got ${res.statusCode}`),
      performance.now() - t0
    );
  } catch (err) {
    recordTest(testId, 'B2B Security & Tier Enforcement', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 5: Automated 24/7 Cron, Upstream Fallback & Portfolio Registry (90 Cases)
// Objective: Verify Vercel Cron header, Bearer secret, crt.sh timeout fallback, tenant registry.
// ============================================================================
console.log('\n--- [Category 5/5] Automated Cron, Upstream Fallback & Portfolios (90 Cases) ---');

for (let i = 0; i < 90; i++) {
  const testId = `CRON-FALLBACK-${i + 1}`;
  const t0 = performance.now();

  try {
    if (i < 30) {
      // Automated Vercel Cron Header Trigger
      globalThis.fetch = async () => ({
        ok: true,
        json: async () => []
      });

      const exchange = createMockExchange({}, { 'x-vercel-cron': '1' });
      await zerodayHandler(exchange.req, exchange.res);
      const res = exchange.getResult();

      const passed = res.statusCode === 200 && res.responseData?.status === 'CRON_CONTINUOUS_SCAN_COMPLETED';
      recordTest(testId, 'Automated 24/7 Vercel Cron', passed, passed ? null : new Error('Vercel Cron trigger failed'), performance.now() - t0);

    } else if (i < 60) {
      // Upstream crt.sh Outage / 502 / Network Hang -> Structured Fallback
      globalThis.fetch = async () => {
        throw new Error('502 Bad Gateway: crt.sh upstream overloaded');
      };

      const exchange = createMockExchange(
        { keyword: `hdfcbank_${i}` },
        getProHeaders(i + 100)
      );
      await zerodayHandler(exchange.req, exchange.res);
      const res = exchange.getResult();

      // System must gracefully fallback to STANDBY_NEXT_CYCLE without a 500 crash
      const passed = res.statusCode === 200 && res.responseData?.status === 'STANDBY_NEXT_CYCLE';
      recordTest(testId, 'Upstream CT Outage Fallback', passed, passed ? null : new Error(`Expected STANDBY_NEXT_CYCLE but got ${res.statusCode} or status ${res.responseData?.status}`), performance.now() - t0);

    } else {
      // Tenant Brand Portfolio Registry Isolation
      const tenantId = `isolated_enterprise_bank_${i}`;
      registerTenantBrandKeywords(tenantId, ['brand-alpha', 'brand-beta']);
      const retrieved = getRegisteredTenantBrandKeywords(tenantId);

      const passed = retrieved.includes('brand-alpha') && retrieved.includes('brand-beta') && retrieved.length === 2;
      recordTest(testId, 'Tenant Brand Registry Isolation', passed, passed ? null : new Error('Tenant brand portfolio registration mismatch'), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Cron & Fallback Resilience', false, err, performance.now() - t0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ============================================================================
// SUMMARY AUDIT METRICS
// ============================================================================
console.log('\n' + '='.repeat(72));
console.log('   FEATURE #6 HARDEST GAUNTLET SUMMARY AUDIT METRICS                    ');
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
  failures.slice(0, 10).forEach(f => {
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
