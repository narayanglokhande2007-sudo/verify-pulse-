// tests/enterprise_gauntlet_450_tenant_calibration.mjs
// ============================================================================
// VERIFYPULSE HARDEST ADVERSARIAL GAUNTLET: FEATURE #9
// Module: Tenant Custom Rules & Policy Decision Calibration Rail
// Target: Tier Gating, Subdomain Whitelists, Keyword Blacklists, Risk Bands
// Total Cases: 450 Extreme Adversarial Scenarios
// ============================================================================

import { performance } from 'perf_hooks';
import { applyTenantCustomRules } from '../lib/tenant_custom_rules.js';
import { calibrateDecision } from '../lib/decision_calibration.js';

console.log('='.repeat(72));
console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #9        ');
console.log('   Module: Tenant Custom Rules & Policy Decision Calibration Rail       ');
console.log('   Target: Tier Gating, Subdomains, Evasion Normalization & Risk Bands  ');
console.log('   Total Cases: 450 Extreme Adversarial Scenarios                       ');
console.log('='.repeat(72));

let totalPassed = 0;
let totalFailed = 0;
const failures = [];
const latencies = [];

function recordTest(id, category, passed, error = null, latencyMs = 0) {
  latencies.push(latencyMs);
  if (passed) {
    totalPassed++;
  } else {
    totalFailed++;
    failures.push({ id, category, error: error?.message || String(error) });
  }
}

// ============================================================================
// CATEGORY 1: Tenant Whitelist Subdomain Shield & Tier Gating (90 Cases)
// Objective: Tier 1/2 never apply custom rules; Tier 3 whitelists apex & subdomains.
// ============================================================================
console.log('\n--- [Category 1/5] Tenant Whitelist Subdomain Shield & Tier Gating (90 Cases) ---');

// 1.1: Tier Gating: Tier 1 (Free) and Tier 2 (Pro) ignore custom rules (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `TIER-GATE-${i + 1}`;
  const t0 = performance.now();
  const tier = (i % 2 === 0) ? 1 : 2;
  const initialVerdict = { verdict: 'SUSPICIOUS', confidence: 80, findings: ['Original AI flag'] };
  const rawInput = 'Official update at https://fraudshield-demo.com/portal';
  const urls = ['https://fraudshield-demo.com/portal'];

  try {
    const result = applyTenantCustomRules('fraudshield', tier, rawInput, urls, initialVerdict);
    // For Tier 1 and 2, the whitelist MUST NOT be applied; verdict remains SUSPICIOUS
    const passed = result.verdict === 'SUSPICIOUS' && result.confidence === 80;
    recordTest(testId, 'Tier Gating Enforcement', passed, passed ? null : new Error(`Tier ${tier} inappropriately received custom rules`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Tier Gating Enforcement', false, err, performance.now() - t0);
  }
}

// 1.2: Apex & Multi-level Subdomain Whitelisting in Tier 3 (30 cases)
const SUBDOMAINS = [
  'hdfcbank.com', 'netbanking.hdfcbank.com', 'loans.hdfcbank.com',
  'auth.secure.hdfcbank.com', 'api.v1.hdfcbank.com', 'corp.portal.hdfcbank.com',
  'fraudshield-demo.com', 'app.fraudshield-demo.com', 'admin.secure.fraudshield-demo.com',
  'gateway.fraudshield-demo.com'
];
for (let i = 0; i < 30; i++) {
  const testId = `WHITELIST-SUBDOMAIN-${i + 1}`;
  const t0 = performance.now();
  const domain = SUBDOMAINS[i % SUBDOMAINS.length];
  const tenantId = domain.includes('hdfc') ? 'hdfc_bank_test' : 'fraudshield';
  const initialVerdict = { verdict: 'SUSPICIOUS', confidence: 90, findings: ['AI suspicion'] };
  const url = `https://${domain}/login`;

  try {
    const result = applyTenantCustomRules(tenantId, 3, `Visit ${url}`, [url], initialVerdict);
    const passed = result.verdict === 'SAFE' &&
                   result.confidence === 100 &&
                   result.evidenceSources.includes('tenant_custom_whitelist');
    recordTest(testId, 'Apex and Subdomain Whitelisting', passed, passed ? null : new Error(`Domain ${domain} was not whitelisted`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Apex and Subdomain Whitelisting', false, err, performance.now() - t0);
  }
}

// 1.3: Whitelist Boundary Defense: Attacker lookalikes must NOT match (30 cases)
const ATTACKER_LOOKALIKES = [
  'phishing-hdfcbank.com', 'hdfcbank.com.attacker-domain.net', 'fakehdfcbank.com',
  'hdfcbank.com.imposter.org', 'hdfcbank.com-verify.in', 'fraudshield-demo.com.fake.ru',
  'secure-fraudshield-demo.com.xyz', 'hdfc.com.loan-scam.co', 'fraudshield-demo.com-portal.cc',
  'myhdfcbank.com'
];
for (let i = 0; i < 30; i++) {
  const testId = `WHITELIST-BOUNDARY-${i + 1}`;
  const t0 = performance.now();
  const domain = ATTACKER_LOOKALIKES[i % ATTACKER_LOOKALIKES.length];
  const tenantId = domain.includes('hdfc') ? 'hdfc_bank_test' : 'fraudshield';
  const initialVerdict = { verdict: 'DANGEROUS', confidence: 95, findings: ['Phishing match'] };
  const url = `https://${domain}/steal`;

  try {
    const result = applyTenantCustomRules(tenantId, 3, `Visit ${url}`, [url], initialVerdict);
    // Boundary defense: lookalikes MUST NOT be converted to SAFE!
    const passed = result.verdict === 'DANGEROUS' && result.confidence === 95 && !result.evidenceSources.includes('tenant_custom_whitelist');
    recordTest(testId, 'Whitelist Boundary Security', passed, passed ? null : new Error(`Attacker lookalike ${domain} bypassed whitelist check!`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Whitelist Boundary Security', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 2: Tenant Blacklist & Zero-Day Keyword Defense (90 Cases)
// Objective: Immediate brand impersonation detection with zero-width resistance.
// ============================================================================
console.log('\n--- [Category 2/5] Tenant Blacklist & Brand Impersonation Rules (90 Cases) ---');

// 2.1: Exact & Substring Keyword Blacklisting (30 cases)
const BLACKLIST_KEYWORDS = [
  'hdfc-reward', 'hdfc-pan-update', 'fraudshield-support', 'fraudshield-kyc', 'fraudshield-update'
];
for (let i = 0; i < 30; i++) {
  const testId = `BLACKLIST-EXACT-${i + 1}`;
  const t0 = performance.now();
  const kw = BLACKLIST_KEYWORDS[i % BLACKLIST_KEYWORDS.length];
  const tenantId = kw.startsWith('hdfc') ? 'hdfc_bank_test' : 'fraudshield';
  const initialVerdict = { verdict: 'NEEDS_VERIFICATION', confidence: 50, findings: [] };
  const text = `Urgent alert: claim your points at http://scam.org/${kw}/claim now!`;

  try {
    const result = applyTenantCustomRules(tenantId, 3, text, [], initialVerdict);
    const passed = result.verdict === 'SUSPICIOUS' &&
                   result.confidence >= 99 &&
                   result.evidenceSources.includes('tenant_custom_blacklist') &&
                   result.scamType.includes('Tenant Blacklist');
    recordTest(testId, 'Exact Blacklist Keyword Match', passed, passed ? null : new Error(`Keyword ${kw} was not caught by blacklist`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Exact Blacklist Keyword Match', false, err, performance.now() - t0);
  }
}

// 2.2: Zero-Width Characters Evasion Normalization (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `BLACKLIST-ZERO-WIDTH-${i + 1}`;
  const t0 = performance.now();
  // Inject zero-width space (\u200B), zero-width non-joiner (\u200C), byte order mark (\uFEFF)
  const evasiveText = `Special offer: claim h\u200Bdfc-\u200Cpan-\uFEFFupdate today!`;
  const initialVerdict = { verdict: 'NEEDS_VERIFICATION', confidence: 40, findings: [] };

  try {
    const result = applyTenantCustomRules('hdfc_bank_test', 3, evasiveText, [], initialVerdict);
    const passed = result.verdict === 'SUSPICIOUS' &&
                   result.confidence >= 99 &&
                   result.evidenceSources.includes('tenant_custom_blacklist');
    recordTest(testId, 'Zero-Width Blacklist Evasion', passed, passed ? null : new Error(`Zero-width evasion bypassed blacklist`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Zero-Width Blacklist Evasion', false, err, performance.now() - t0);
  }
}

// 2.3: Case Insensitivity in Keyword Matching (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `BLACKLIST-CASE-${i + 1}`;
  const t0 = performance.now();
  const mixedCaseKw = (i % 2 === 0) ? 'HDFC-REWARD' : 'FraUdShield-SuPPort';
  const tenantId = (i % 2 === 0) ? 'hdfc_bank_test' : 'fraudshield';
  const text = `Customer notice regarding ${mixedCaseKw} points.`;
  const initialVerdict = { verdict: 'SAFE', confidence: 30, findings: [] };

  try {
    const result = applyTenantCustomRules(tenantId, 3, text, [], initialVerdict);
    const passed = result.verdict === 'SUSPICIOUS' &&
                   result.confidence >= 99 &&
                   result.evidenceSources.includes('tenant_custom_blacklist');
    recordTest(testId, 'Case-Insensitive Blacklist', passed, passed ? null : new Error(`Mixed-case keyword ${mixedCaseKw} missed`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Case-Insensitive Blacklist', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 3: Strict Mode Calibration & Custom Policy Injector (90 Cases)
// Objective: Strict mode confidence inflation (+15 up to 99) and deduplicated advisory.
// ============================================================================
console.log('\n--- [Category 3/5] Strict Mode Calibration & Custom Policy Injector (90 Cases) ---');

// 3.1: Strict Mode Confidence Elevation (+15 capped at 99) (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `STRICT-MODE-BOOST-${i + 1}`;
  const t0 = performance.now();
  // Test starting confidences: 50 -> 65, 75 -> 90, 90 -> 99, 95 -> 99
  const initialConf = 50 + (i % 4) * 15;
  const initialVerdict = { verdict: 'SUSPICIOUS', confidence: initialConf, findings: [] };

  try {
    const result = applyTenantCustomRules('hdfc_bank_test', 3, 'Regular suspicious alert', [], initialVerdict);
    const expectedConf = Math.min(initialConf + 15, 99);
    const passed = result.confidence === expectedConf;
    recordTest(testId, 'Strict Mode Confidence Boost', passed, passed ? null : new Error(`Expected ${expectedConf}, got ${result.confidence}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Strict Mode Confidence Boost', false, err, performance.now() - t0);
  }
}

// 3.2: Non-Suspicious Verdicts Unchanged in Strict Mode (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `STRICT-MODE-NON-SUSP-${i + 1}`;
  const t0 = performance.now();
  const verdict = (i % 2 === 0) ? 'NEEDS_VERIFICATION' : 'DANGEROUS';
  const initialVerdict = { verdict, confidence: 60, findings: [] };

  try {
    const result = applyTenantCustomRules('hdfc_bank_test', 3, 'Generic inquiry', [], initialVerdict);
    // Strict mode only elevates confidence when verdict === 'SUSPICIOUS'
    const passed = result.confidence === 60 && result.verdict === verdict;
    recordTest(testId, 'Strict Mode Non-Suspicious Guard', passed, passed ? null : new Error(`Strict mode mutated non-suspicious confidence`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Strict Mode Non-Suspicious Guard', false, err, performance.now() - t0);
  }
}

// 3.3: Custom Advisory Message Injection and Deduplication (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `CUSTOM-MESSAGE-DEDUP-${i + 1}`;
  const t0 = performance.now();
  const initialVerdict = {
    verdict: 'SUSPICIOUS',
    confidence: 80,
    findings: i >= 15 ? ["HDFC Bank Policy: We never ask for OTP via SMS links."] : []
  };

  try {
    const result = applyTenantCustomRules('hdfc_bank_test', 3, 'Check account', [], initialVerdict);
    const msgCount = result.findings.filter(f => f === "HDFC Bank Policy: We never ask for OTP via SMS links.").length;
    const passed = msgCount === 1;
    recordTest(testId, 'Custom Message Deduplication', passed, passed ? null : new Error(`Message was duplicated or missing: count=${msgCount}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Custom Message Deduplication', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 4: Dynamic Environment Rules Injection (90 Cases)
// Objective: Dynamic JSON parsing, malformed JSON fallback & ID case normalization.
// ============================================================================
console.log('\n--- [Category 4/5] Dynamic Environment Rules Injection (90 Cases) ---');

// 4.1: Dynamic Rules from VERIFYPULSE_TENANT_RULES (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `ENV-RULES-DYNAMIC-${i + 1}`;
  const t0 = performance.now();
  const tenantId = `dynamic_client_${i}`;
  const dynamicRules = {
    [tenantId]: {
      whitelistedDomains: [`client-portal-${i}.com`],
      blacklistedKeywords: [`client-scam-${i}`],
      strictMode: true,
      customMessage: `Dynamic client ${i} policy notice.`
    }
  };

  try {
    process.env.VERIFYPULSE_TENANT_RULES = JSON.stringify(dynamicRules);
    const initialVerdict = { verdict: 'SUSPICIOUS', confidence: 70, findings: [] };
    const url = `https://client-portal-${i}.com/app`;

    const result = applyTenantCustomRules(tenantId, 3, `Visit ${url}`, [url], initialVerdict);
    const passed = result.verdict === 'SAFE' &&
                   result.confidence === 100 &&
                   result.evidenceSources.includes('tenant_custom_whitelist');
    recordTest(testId, 'Dynamic Environment Rules Parsing', passed, passed ? null : new Error(`Dynamic tenant ${tenantId} rule failed`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Dynamic Environment Rules Parsing', false, err, performance.now() - t0);
  }
}

// 4.2: Malformed JSON Fallback Resilience (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `ENV-RULES-MALFORMED-${i + 1}`;
  const t0 = performance.now();
  try {
    process.env.VERIFYPULSE_TENANT_RULES = 'INVALID_JSON_CORRUPTED_{{{[';
    // Should gracefully fall back to seed rules without crashing!
    const initialVerdict = { verdict: 'NEEDS_VERIFICATION', confidence: 50, findings: [] };
    const result = applyTenantCustomRules('hdfc_bank_test', 3, 'Claim hdfc-reward now', [], initialVerdict);

    const passed = result.verdict === 'SUSPICIOUS' &&
                   result.evidenceSources.includes('tenant_custom_blacklist');
    recordTest(testId, 'Malformed Env JSON Fallback', passed, passed ? null : new Error(`Did not fallback to seed rules cleanly`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Malformed Env JSON Fallback', false, err, performance.now() - t0);
  } finally {
    delete process.env.VERIFYPULSE_TENANT_RULES;
  }
}

// 4.3: Tenant ID Case-Insensitivity (30 cases)
const CASINGS = ['HDFC_BANK_TEST', 'Hdfc_Bank_Test', 'hdfc_BANK_test', 'FRAUDSHIELD', 'FraudShield'];
for (let i = 0; i < 30; i++) {
  const testId = `TENANT-CASE-NORM-${i + 1}`;
  const t0 = performance.now();
  const rawId = CASINGS[i % CASINGS.length];
  const isHdfc = rawId.toLowerCase().includes('hdfc');
  const initialVerdict = { verdict: 'SUSPICIOUS', confidence: 80, findings: [] };
  const url = isHdfc ? 'https://hdfcbank.com/secure' : 'https://fraudshield-demo.com/portal';

  try {
    const result = applyTenantCustomRules(rawId, 3, `Visit ${url}`, [url], initialVerdict);
    const passed = result.verdict === 'SAFE' && result.confidence === 100;
    recordTest(testId, 'Tenant ID Case Normalization', passed, passed ? null : new Error(`Case variant ${rawId} was not resolved`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Tenant ID Case Normalization', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 5: Decision Calibration & Risk Band Governance (90 Cases)
// Objective: Calibrate risk bands, evidence-backed sources & safety guarantees.
// ============================================================================
console.log('\n--- [Category 5/5] Decision Calibration & Risk Band Governance (90 Cases) ---');

// 5.1: Critical Risk & High Risk Bands (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `CALIBRATION-RISK-BANDS-${i + 1}`;
  const t0 = performance.now();
  try {
    if (i < 15) {
      // DANGEROUS -> critical-risk
      const cal = calibrateDecision({ verdict: 'DANGEROUS', confidence: 95, evidenceSources: ['Local URL and brand forensics'] });
      const passed = cal.riskBand === 'critical-risk' &&
                     cal.decisionBasis === 'evidence-backed' &&
                     cal.independentVerificationRecommended === true &&
                     cal.safeIsNotAuthentication === false;
      recordTest(testId, 'Dangerous Critical Risk Band', passed, passed ? null : new Error(`Failed dangerous calibration`), performance.now() - t0);
    } else {
      // SUSPICIOUS -> high-risk
      const cal = calibrateDecision({ verdict: 'SUSPICIOUS', confidence: 85, evidenceSources: ['Local social-engineering rules'] });
      const passed = cal.riskBand === 'high-risk' &&
                     cal.decisionBasis === 'evidence-backed' &&
                     cal.independentVerificationRecommended === true;
      recordTest(testId, 'Suspicious High Risk Band', passed, passed ? null : new Error(`Failed suspicious calibration`), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Risk Band Calibration', false, err, performance.now() - t0);
  }
}

// 5.2: Evidence-Backed Basis with Tenant Custom Rules (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `CALIBRATION-TENANT-EVIDENCE-${i + 1}`;
  const t0 = performance.now();
  try {
    const source = (i % 2 === 0) ? 'tenant_custom_whitelist' : 'tenant_custom_blacklist';
    const verdict = (i % 2 === 0) ? 'SAFE' : 'SUSPICIOUS';
    const cal = calibrateDecision({ verdict, confidence: 99, evidenceSources: [source] });

    // Both tenant_custom_whitelist and tenant_custom_blacklist must yield 'evidence-backed'
    const passed = cal.decisionBasis === 'evidence-backed';
    recordTest(testId, 'Tenant Rules Evidence-Backed Basis', passed, passed ? null : new Error(`Source ${source} did not yield evidence-backed basis`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Tenant Rules Evidence-Backed Basis', false, err, performance.now() - t0);
  }
}

// 5.3: Service Status & SAFE Authentication Non-Implication (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `CALIBRATION-SAFE-SERVICE-${i + 1}`;
  const t0 = performance.now();
  try {
    if (i < 15) {
      // Service Degraded: Service health monitor MUST force decisionBasis = 'service-status'
      const cal = calibrateDecision({
        verdict: 'SERVICE_UNAVAILABLE',
        confidence: 0,
        evidenceSources: ['Service health monitor', 'Local URL and brand forensics']
      });
      const passed = cal.riskBand === 'service-unavailable' && cal.decisionBasis === 'service-status';
      recordTest(testId, 'Service Degraded Status Calibration', passed, passed ? null : new Error(`Service health monitor did not yield service-status`), performance.now() - t0);
    } else {
      // SAFE verdict: safeIsNotAuthentication MUST be true!
      const cal = calibrateDecision({
        verdict: 'SAFE',
        confidence: 90,
        evidenceSources: ['Trusted domain registry']
      });
      const passed = cal.riskBand === 'lower-risk' &&
                     cal.safeIsNotAuthentication === true &&
                     cal.independentVerificationRecommended === false;
      recordTest(testId, 'Safe Does Not Imply Authentication', passed, passed ? null : new Error(`Safe verdict contract violated`), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Safe and Service Calibration', false, err, performance.now() - t0);
  }
}

// ============================================================================
// FEATURE #9 HARDEST GAUNTLET SUMMARY AUDIT METRICS
// ============================================================================
console.log('\n' + '='.repeat(72));
console.log('   FEATURE #9 HARDEST GAUNTLET SUMMARY AUDIT METRICS                    ');
console.log('='.repeat(72));
console.log(`Total Cases Tested:      ${totalPassed + totalFailed}`);
console.log(`Total Passed:            ${totalPassed} ${totalFailed === 0 ? '✅' : '⚠️'}`);
console.log(`Total Failed:            ${totalFailed} ${totalFailed === 0 ? '✅' : '❌'}`);
console.log(`Success Rate:            ${((totalPassed / (totalPassed + totalFailed)) * 100).toFixed(2)}%`);

const avgLatency = latencies.reduce((a, b) => a + b, 0) / (latencies.length || 1);
const maxLatency = Math.max(...latencies, 0);
const minLatency = Math.min(...latencies, 0);

console.log('\n--- LATENCY BENCHMARK ---');
console.log(`Min Latency: ${minLatency.toFixed(3)} ms | Avg Latency: ${avgLatency.toFixed(3)} ms | Max Latency: ${maxLatency.toFixed(3)} ms`);

if (failures.length > 0) {
  console.log(`\n❌ FAILURES BREAKDOWN (${failures.length} Failures Exposed):`);
  const catCounts = {};
  for (const f of failures) catCounts[f.category] = (catCounts[f.category] || 0) + 1;
  for (const [cat, cnt] of Object.entries(catCounts)) {
    console.log(`  - ${cat}: ${cnt} failures`);
  }
  console.log('\nSample Failed Cases:');
  for (const f of failures.slice(0, 10)) {
    console.log(`  [${f.id}] (${f.category}): ${f.error}`);
  }
  console.log('='.repeat(72));
  process.exit(1);
} else {
  console.log('\n🎉 ALL 450 HARDEST TEST CASES PASSED!');
  console.log('='.repeat(72));
  process.exit(0);
}
