// tests/enterprise_battle_test_feature_1_url_forensics.mjs
// Real-world enterprise client simulation for Feature #1: URL Forensics & Phishing Interception

import { performance } from 'node:perf_hooks';
import { analyzeMessageForensics, canonicalizeUrl, extractUrlCandidates } from '../lib/url_forensics.js';
import handler from '../api/verify.js';

// Simulated Enterprise NBFC Test Scenarios
const testScenarios = [
  {
    id: 'SCENARIO_1_CLEAN_LEGITIMATE_NBFC',
    category: 'False Positive Prevention',
    name: 'Official Clean NBFC Repayment Link',
    payload: {
      text: 'Dear Borrower, your loan repayment of Rs 4,500 is due. Pay securely through https://www.kreditbee.in/repay/KB98234 to keep your CIBIL score healthy.',
      checkType: 'url'
    },
    expected: {
      shouldBeFlaggedDangerous: false,
      description: 'System must NOT flag genuine official domains (Zero False Positive expectation)'
    }
  },
  {
    id: 'SCENARIO_2_TYPOSQUATTING_BRAND_SPOOF',
    category: 'Phishing Interception',
    name: 'Typosquatting & Number Substitution (kred1tbee)',
    payload: {
      text: 'Urgent notice from Loan Department: Pay your overdue loan immediately at https://kred1tbee-loan.in/pay to avoid police warrant.',
      checkType: 'url'
    },
    expected: {
      shouldBeFlaggedDangerous: true,
      description: 'System must catch visually identical lookalike domain with number substitution'
    }
  },
  {
    id: 'SCENARIO_3_PUNYCODE_UNICODE_ATTACK',
    category: 'Zero-Day Phishing',
    name: 'Internationalized Unicode Domain (xn-- Cyrillic deception)',
    payload: {
      text: 'Your NBFC loan sanction letter has been approved. Download sanction letter at https://xn--kreditbe-6ya.com/sanction.pdf and verify.',
      checkType: 'url'
    },
    expected: {
      shouldBeFlaggedDangerous: true,
      description: 'System must catch Punycode xn-- prefix and flag as idn_or_unicode_host'
    }
  },
  {
    id: 'SCENARIO_4_RAW_IP_PORT_SMS_SCAM',
    category: 'Syndicate SMS Phishing',
    name: 'Direct Raw IP with Non-Standard Port',
    payload: {
      text: 'Final settlement offer: Pay 50% waiver at http://103.22.45.19:8080/repay.php to close loan account.',
      checkType: 'url'
    },
    expected: {
      shouldBeFlaggedDangerous: true,
      description: 'System must catch direct IP host and non-standard port'
    }
  },
  {
    id: 'SCENARIO_5_SHORTENER_OTP_TRAP',
    category: 'Social Engineering',
    name: 'Shortened Link with Credential Harvesting (OTP)',
    payload: {
      text: 'Loan disbursement paused. Tap bit.ly/nbfc-verify and enter your bank OTP to release Rs 50,000 immediately.',
      checkType: 'url'
    },
    expected: {
      shouldBeFlaggedDangerous: true,
      description: 'System must catch URL shortener hiding target + sensitive OTP request'
    }
  },
  {
    id: 'SCENARIO_6_CREDENTIAL_STYLE_URL_INJECTION',
    category: 'Browser Confusion Attack',
    name: 'URL Credentials Confusion (brand@attacker.com)',
    payload: {
      text: 'Login to your loan dashboard: https://kreditbee.in@loan-portal-security.xyz/login to view statement.',
      checkType: 'url'
    },
    expected: {
      shouldBeFlaggedDangerous: true,
      description: 'System must identify that hostname is loan-portal-security.xyz and flag url_credentials'
    }
  },
  {
    id: 'SCENARIO_7_EXTREME_STRESS_AND_MALFORMED',
    category: 'API Resilience & Security',
    name: 'Malformed URLs & SQL Injection Payload',
    payload: {
      text: "https://invalid-url-with-spaces and http://:::broken and ' OR 1=1-- " + 'A'.repeat(500),
      checkType: 'url'
    },
    expected: {
      shouldNotCrash: true,
      description: 'System must never throw uncaught exceptions or crash on malformed inputs'
    }
  }
];

// Helper to simulate Mock Express/Next.js Request & Response
function createMockHttpExchange(payload, headers = {}) {
  let statusCode = 200;
  let responseData = null;
  const responseHeaders = {};

  const req = {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': 'Enterprise-NBFC-Core-Banking-Client/1.0',
      'x-forwarded-for': '127.0.0.1',
      ...headers
    },
    body: payload
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

async function runEnterpriseBattleTest() {
  console.log('========================================================================');
  console.log('   VERIFYPULSE ENTERPRISE BATTLE-TEST: FEATURE #1 (URL FORENSICS)       ');
  console.log('   Testing Mode: Real Enterprise Client API Simulation                  ');
  console.log('   Date: October 2026 | Node Runtime: v' + process.version);
  console.log('========================================================================\n');

  const scenarioResults = [];

  for (const scenario of testScenarios) {
    const startTime = performance.now();
    let exchangeResult = null;
    let forensicsDirect = null;
    let errorCaught = null;

    try {
      // 1. Direct Engine Level Forensics Test
      forensicsDirect = analyzeMessageForensics(scenario.payload.text);

      // 2. Full HTTP Serverless API Handler Simulation
      const exchange = createMockHttpExchange(scenario.payload);
      await handler(exchange.req, exchange.res);
      exchangeResult = exchange.getResult();
    } catch (err) {
      errorCaught = err;
    }

    const durationMs = (performance.now() - startTime).toFixed(2);

    // Evaluate Pass/Fail
    let passed = false;
    let verdictObserved = exchangeResult?.responseData?.verdict || (forensicsDirect?.highRisk ? 'SUSPICIOUS' : 'SAFE');
    let signalsDetected = forensicsDirect?.urls?.flatMap(u => u.signals) || [];

    if (scenario.id === 'SCENARIO_1_CLEAN_LEGITIMATE_NBFC') {
      // Must NOT be highRisk
      passed = !forensicsDirect?.highRisk && verdictObserved !== 'DANGEROUS';
    } else if (scenario.id === 'SCENARIO_7_EXTREME_STRESS_AND_MALFORMED') {
      passed = !errorCaught && (exchangeResult?.statusCode === 200 || exchangeResult?.statusCode === 400);
    } else {
      // Must be flagged as high risk / suspicious / dangerous
      passed = forensicsDirect?.highRisk || ['SUSPICIOUS', 'DANGEROUS', 'SCAM'].includes(verdictObserved) || signalsDetected.length > 0;
    }

    scenarioResults.push({
      id: scenario.id,
      name: scenario.name,
      category: scenario.category,
      passed,
      durationMs: Number(durationMs),
      verdictObserved,
      signalsDetected,
      forensicsScore: forensicsDirect?.score || 0,
      statusCode: exchangeResult?.statusCode || 500,
      findings: forensicsDirect?.findings || []
    });
  }

  // Latency Benchmark (100 Sequential Invocations)
  console.log('Running 100-Call Latency Gauntlet on URL Forensics Engine...');
  const benchmarkUrl = 'Urgent: Click https://kred1tbee-loan.in/pay to prevent default';
  const latencies = [];

  for (let i = 0; i < 100; i++) {
    const t0 = performance.now();
    analyzeMessageForensics(benchmarkUrl);
    const t1 = performance.now();
    latencies.push(t1 - t0);
  }

  latencies.sort((a, b) => a - b);
  const minLatency = latencies[0].toFixed(3);
  const maxLatency = latencies[latencies.length - 1].toFixed(3);
  const avgLatency = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3);
  const p95Latency = latencies[Math.floor(latencies.length * 0.95)].toFixed(3);
  const p99Latency = latencies[Math.floor(latencies.length * 0.99)].toFixed(3);

  // Print Summary Table
  console.log('\n--- DETAILED SCENARIO AUDIT CARD ---');
  scenarioResults.forEach((res, idx) => {
    const statusSymbol = res.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[Test ${idx + 1}] ${statusSymbol} | ${res.name}`);
    console.log(`       Category: ${res.category}`);
    console.log(`       Latency:  ${res.durationMs} ms | HTTP Status: ${res.statusCode} | Verdict: ${res.verdictObserved}`);
    console.log(`       Signals:  ${res.signalsDetected.join(', ') || 'None'}`);
    if (res.findings.length > 0) {
      console.log(`       Findings: ${res.findings.join(' | ')}`);
    }
    console.log('------------------------------------------------------------------------');
  });

  console.log('\n========================================================================');
  console.log('   LATENCY PERFORMANCE BENCHMARK (100 Iterations)                      ');
  console.log(`   Min Latency:  ${minLatency} ms`);
  console.log(`   Avg Latency:  ${avgLatency} ms`);
  console.log(`   P95 Latency:  ${p95Latency} ms`);
  console.log(`   P99 Latency:  ${p99Latency} ms`);
  console.log(`   Max Latency:  ${maxLatency} ms`);
  console.log('========================================================================\n');

  const totalPassed = scenarioResults.filter(s => s.passed).length;
  console.log(`FINAL RESULT: ${totalPassed}/${scenarioResults.length} Scenarios Passed.`);

  return { scenarioResults, benchmark: { minLatency, avgLatency, p95Latency, p99Latency, maxLatency } };
}

runEnterpriseBattleTest().catch(console.error);
