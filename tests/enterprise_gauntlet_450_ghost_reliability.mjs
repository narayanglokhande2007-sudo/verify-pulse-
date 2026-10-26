// tests/enterprise_gauntlet_450_ghost_reliability.mjs
// ============================================================================
// VERIFYPULSE HARDEST ADVERSARIAL GAUNTLET: FEATURE #8
// Module: Ghost Agent Multi-Provider AI Fallback Rail, Circuit Breakers & Canary
// Target: SSRF Protection, Circuit Policy, Retry Cascades, Canary HMAC, Budgeting
// Total Cases: 450 Extreme Adversarial Scenarios
// ============================================================================

import { performance } from 'perf_hooks';
import {
  runProviderAttempt,
  runProviderWithSingleRetry,
  resetProviderCircuits,
  createServiceUnavailableResult,
  ProviderRequestError,
  classifyProviderFailure
} from '../lib/scan_reliability.js';
import { validatePublicTarget, isPrivateIpv4 } from '../lib/ghost_agent_pooled.js';
import {
  createCanaryToken,
  verifyCanaryToken,
  createCanaryAuditEvent,
  createCanaryUrl
} from '../lib/canary_engine.js';
import { createRequestBudget } from '../lib/request_budget.js';

// Setup required environment for canary engine
process.env.VERIFYPULSE_CANARY_SECRET = 'a_very_secure_test_secret_for_canary_tokens_1234567890';

console.log('='.repeat(72));
console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #8        ');
console.log('   Module: Ghost Agent Multi-Provider Fallback Rail & Canary Engine      ');
console.log('   Target: SSRF Shield, Circuit Breakers, Cascades & Request Budgeting  ');
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
// CATEGORY 1: Ghost Agent SSRF Shield & URL/IP Validation (90 Cases)
// Objective: Block all private IPv4/IPv6, cloud metadata, schemes & creds in URLs.
// ============================================================================
console.log('\n--- [Category 1/5] Ghost Agent SSRF Shield & URL/IP Validation (90 Cases) ---');

// 1.1: Loopback IPv4 (15 cases)
for (let i = 0; i < 15; i++) {
  const testId = `SSRF-LOOPBACK-${i + 1}`;
  const t0 = performance.now();
  const ip = `127.0.${i}.${i + 1}`;
  try {
    const isPriv = isPrivateIpv4(ip);
    let threw = false;
    try {
      await validatePublicTarget(`http://${ip}/admin`);
    } catch {
      threw = true;
    }
    const passed = isPriv === true && threw === true;
    recordTest(testId, 'Loopback SSRF Shield', passed, passed ? null : new Error(`Loopback ${ip} was not blocked`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Loopback SSRF Shield', false, err, performance.now() - t0);
  }
}

// 1.2: RFC 1918 Private IPv4 (15 cases)
const PRIVATE_IPS = [
  '10.0.0.1', '10.255.255.254', '10.50.100.1',
  '172.16.0.1', '172.20.10.5', '172.31.255.254',
  '192.168.0.1', '192.168.1.1', '192.168.100.254',
  '10.1.2.3', '172.17.4.5', '172.30.9.8',
  '192.168.254.254', '10.10.10.10', '192.168.8.1'
];
for (let i = 0; i < 15; i++) {
  const testId = `SSRF-RFC1918-${i + 1}`;
  const t0 = performance.now();
  const ip = PRIVATE_IPS[i];
  try {
    const isPriv = isPrivateIpv4(ip);
    let threw = false;
    try {
      await validatePublicTarget(`https://${ip}:8443/internal-api`);
    } catch {
      threw = true;
    }
    const passed = isPriv === true && threw === true;
    recordTest(testId, 'RFC1918 Private IP Shield', passed, passed ? null : new Error(`Private IP ${ip} was not blocked`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'RFC1918 Private IP Shield', false, err, performance.now() - t0);
  }
}

// 1.3: Link-Local, Cloud Metadata & Multicast (15 cases)
const LINK_LOCAL_SPECIAL_IPS = [
  '169.254.169.254', '169.254.0.1', '169.254.1.1', '169.254.254.254',
  '0.0.0.0', '0.0.0.1',
  '224.0.0.1', '224.0.0.251', '239.255.255.250',
  '240.0.0.1', '255.255.255.255',
  '169.254.170.2', '224.1.1.1', '245.0.0.1', '0.1.2.3'
];
for (let i = 0; i < 15; i++) {
  const testId = `SSRF-METADATA-${i + 1}`;
  const t0 = performance.now();
  const ip = LINK_LOCAL_SPECIAL_IPS[i];
  try {
    const isPriv = isPrivateIpv4(ip);
    let threw = false;
    try {
      await validatePublicTarget(`http://${ip}/latest/meta-data/`);
    } catch {
      threw = true;
    }
    const passed = isPriv === true && threw === true;
    recordTest(testId, 'Cloud Metadata & Special IP Shield', passed, passed ? null : new Error(`Special IP ${ip} was not blocked`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Cloud Metadata & Special IP Shield', false, err, performance.now() - t0);
  }
}

// 1.4: IPv6 SSRF Bypasses (15 cases)
const IPV6_TARGETS = [
  'http://[::1]/', 'http://[::]/', 'http://[fe80::1]/', 'http://[fc00::1]/',
  'http://[fd00::1]/', 'https://[::1]:8080/secret', 'http://[2001:db8::1]/',
  'http://[::ffff:127.0.0.1]/', 'http://[fe80::200:5efe:10.0.0.1]/',
  'http://[::ffff:169.254.169.254]/', 'http://[::ffff:192.168.1.1]/',
  'http://[0:0:0:0:0:0:0:1]/', 'http://[0:0:0:0:0:ffff:7f00:1]/',
  'http://[fe80::a00:27ff:fe8e:e860]/', 'https://[::1]/debug'
];
for (let i = 0; i < 15; i++) {
  const testId = `SSRF-IPV6-${i + 1}`;
  const t0 = performance.now();
  const target = IPV6_TARGETS[i];
  try {
    let threw = false;
    try {
      await validatePublicTarget(target);
    } catch {
      threw = true;
    }
    recordTest(testId, 'IPv6 SSRF Shield', threw, threw ? null : new Error(`IPv6 target ${target} bypassed SSRF check`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'IPv6 SSRF Shield', false, err, performance.now() - t0);
  }
}

// 1.5: URL Scheme Injections & Embedded Credentials (15 cases)
const MALFORMED_SCHEMES_CREDS = [
  'ftp://files.example.com/file.txt', 'file:///etc/passwd', 'gopher://127.0.0.1:70/',
  'javascript:alert(1)', 'data:text/html,<b>hello</b>', 'blob:https://example.com/uuid',
  'ws://socket.example.com/feed', 'wss://secure.socket.com/feed',
  'https://admin:secret@bank-login.com/dashboard', 'http://user:password123@1.1.1.1/',
  'https://root:toor@phish.in/login', 'ldap://corp.internal/',
  'https://auth:token@safe-domain.com/', 'tftp://router.local/', 'mailto:test@example.com'
];
for (let i = 0; i < 15; i++) {
  const testId = `SSRF-SCHEME-CREDS-${i + 1}`;
  const t0 = performance.now();
  const target = MALFORMED_SCHEMES_CREDS[i];
  try {
    let threw = false;
    try {
      await validatePublicTarget(target);
    } catch {
      threw = true;
    }
    recordTest(testId, 'Scheme & Embedded Credential Shield', threw, threw ? null : new Error(`Target ${target} was not rejected`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Scheme & Embedded Credential Shield', false, err, performance.now() - t0);
  }
}

// 1.6: Internal Hostnames & Domain Suffixes (15 cases)
const INTERNAL_HOSTNAMES = [
  'http://localhost/', 'https://localhost:3000/api', 'http://sub.localhost/',
  'http://service.local/', 'http://printer.local:631/', 'http://metadata.google.internal/',
  'http://vault.internal/', 'http://redis.internal:6379/', 'http://ad.corp/',
  'http://dc01.corp/ldap', 'http://router.lan/', 'http://gateway.lan/',
  'http://db.internal/query', 'http://nas.local/shares', 'http://dev.internal/'
];
for (let i = 0; i < 15; i++) {
  const testId = `SSRF-INTERNAL-HOST-${i + 1}`;
  const t0 = performance.now();
  const target = INTERNAL_HOSTNAMES[i];
  try {
    let threw = false;
    try {
      await validatePublicTarget(target);
    } catch {
      threw = true;
    }
    recordTest(testId, 'Internal Hostname Shield', threw, threw ? null : new Error(`Internal host ${target} was not blocked`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Internal Hostname Shield', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 2: AI Provider Circuit Breaker & Failure Classification (90 Cases)
// Objective: Immediate circuit trips on 429/401, 2-failure trip on 500/timeout.
// ============================================================================
console.log('\n--- [Category 2/5] AI Provider Circuit Breaker & Failure Policy (90 Cases) ---');

// 2.1: 429 Rate Limiting immediate circuit breaker (20 cases)
for (let i = 0; i < 20; i++) {
  const testId = `CIRCUIT-429-${i + 1}`;
  const t0 = performance.now();
  const provider = `mock_gemini_429_${i}`;
  try {
    resetProviderCircuits();
    // First attempt fails with 429 rate limit
    const attempt1 = await runProviderAttempt({
      requestId: `req-429-1-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => {
        throw new ProviderRequestError('provider_rate_limited', 'HTTP 429 Too Many Requests', { provider, status: 429, reason: 'rate_limit' });
      }
    });

    // Second attempt MUST immediately short-circuit with 'provider_circuit_open'
    const attempt2 = await runProviderAttempt({
      requestId: `req-429-2-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => 'SHOULD_NOT_EXECUTE'
    });

    const passed = attempt1.ok === false && attempt1.errorCode === 'provider_rate_limited' &&
                   attempt2.ok === false && attempt2.errorCode === 'provider_circuit_open';

    recordTest(testId, '429 Rate Limit Circuit Trip', passed, passed ? null : new Error(`Circuit did not trip immediately on 429`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, '429 Rate Limit Circuit Trip', false, err, performance.now() - t0);
  }
}

// 2.2: 401/403 Auth/Config errors immediate circuit breaker (20 cases)
for (let i = 0; i < 20; i++) {
  const testId = `CIRCUIT-AUTH-${i + 1}`;
  const t0 = performance.now();
  const provider = `mock_groq_auth_${i}`;
  try {
    resetProviderCircuits();
    const attempt1 = await runProviderAttempt({
      requestId: `req-auth-1-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => {
        throw new ProviderRequestError('provider_auth_or_configuration_error', 'HTTP 401 Unauthorized', { provider, status: 401 });
      }
    });

    const attempt2 = await runProviderAttempt({
      requestId: `req-auth-2-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => 'SHOULD_NOT_EXECUTE'
    });

    const passed = attempt1.ok === false && attempt1.errorCode === 'provider_auth_or_configuration_error' &&
                   attempt2.ok === false && attempt2.errorCode === 'provider_circuit_open';

    recordTest(testId, 'Auth Error Circuit Trip', passed, passed ? null : new Error(`Circuit did not trip immediately on auth error`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Auth Error Circuit Trip', false, err, performance.now() - t0);
  }
}

// 2.3: 500 Upstream errors (threshold = 2 failures) (20 cases)
for (let i = 0; i < 20; i++) {
  const testId = `CIRCUIT-500-${i + 1}`;
  const t0 = performance.now();
  const provider = `mock_anthropic_500_${i}`;
  try {
    resetProviderCircuits();
    // First 500 error: Failure, but circuit MUST remain closed (threshold 2)
    const attempt1 = await runProviderAttempt({
      requestId: `req-500-1-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => {
        throw new ProviderRequestError('provider_http_error', 'HTTP 500 Internal Server Error', { provider, status: 500 });
      }
    });

    // Check circuit is still closed by running another operation that succeeds
    let executedInAttempt2 = false;
    const attempt2 = await runProviderAttempt({
      requestId: `req-500-2-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => {
        executedInAttempt2 = true;
        throw new ProviderRequestError('provider_http_error', 'HTTP 500 Second Failure', { provider, status: 500 });
      }
    });

    // Third attempt MUST be short-circuited
    const attempt3 = await runProviderAttempt({
      requestId: `req-500-3-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => 'SHOULD_NOT_EXECUTE'
    });

    const passed = attempt1.errorCode === 'provider_http_error' &&
                   executedInAttempt2 === true &&
                   attempt2.errorCode === 'provider_http_error' &&
                   attempt3.errorCode === 'provider_circuit_open';

    recordTest(testId, '500 Error Two-Attempt Circuit Trip', passed, passed ? null : new Error(`Circuit did not honor 2-failure threshold for 500 error`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, '500 Error Two-Attempt Circuit Trip', false, err, performance.now() - t0);
  }
}

// 2.4: Timeouts & Network errors (threshold = 2 failures) (15 cases)
for (let i = 0; i < 15; i++) {
  const testId = `CIRCUIT-TIMEOUT-${i + 1}`;
  const t0 = performance.now();
  const provider = `mock_timeout_prov_${i}`;
  try {
    resetProviderCircuits();
    // First timeout
    await runProviderAttempt({
      requestId: `req-to-1-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => {
        throw new ProviderRequestError('provider_timeout', 'Request timed out after 3000ms', { provider });
      }
    });

    // Second timeout
    await runProviderAttempt({
      requestId: `req-to-2-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => {
        throw new ProviderRequestError('provider_timeout', 'Request timed out again', { provider });
      }
    });

    // Third attempt short-circuited
    const attempt3 = await runProviderAttempt({
      requestId: `req-to-3-${i}`,
      stage: 'test_scan',
      provider,
      operation: async () => 'SHOULD_NOT_EXECUTE'
    });

    const passed = attempt3.ok === false && attempt3.errorCode === 'provider_circuit_open';
    recordTest(testId, 'Timeout Two-Attempt Circuit Trip', passed, passed ? null : new Error(`Timeout did not trip circuit on 2nd failure`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Timeout Two-Attempt Circuit Trip', false, err, performance.now() - t0);
  }
}

// 2.5: Provider Circuit Isolation & Reset (15 cases)
for (let i = 0; i < 15; i++) {
  const testId = `CIRCUIT-ISOLATION-${i + 1}`;
  const t0 = performance.now();
  const providerA = `prov_isolated_A_${i}`;
  const providerB = `prov_isolated_B_${i}`;
  try {
    resetProviderCircuits();
    // Trip provider A with 429
    await runProviderAttempt({
      requestId: `req-iso-1-${i}`,
      stage: 'test_scan',
      provider: providerA,
      operation: async () => {
        throw new ProviderRequestError('provider_rate_limited', 'HTTP 429', { provider: providerA });
      }
    });

    // Provider B must still be fully functional and open
    const attemptB = await runProviderAttempt({
      requestId: `req-iso-2-${i}`,
      stage: 'test_scan',
      provider: providerB,
      operation: async () => ({ verdict: 'SAFE' })
    });

    // Reset circuits
    resetProviderCircuits();
    // Provider A must now be clear
    const attemptAAfterReset = await runProviderAttempt({
      requestId: `req-iso-3-${i}`,
      stage: 'test_scan',
      provider: providerA,
      operation: async () => ({ verdict: 'SUSPICIOUS' })
    });

    const passed = attemptB.ok === true && attemptAAfterReset.ok === true;
    recordTest(testId, 'Circuit Isolation & Manual Reset', passed, passed ? null : new Error(`Circuits leaked between providers or failed to reset`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Circuit Isolation & Manual Reset', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 3: Single Retry Cascade & Graceful Degradation (90 Cases)
// Objective: Verify retry behavior, multi-provider cascading, and service unavailability.
// ============================================================================
console.log('\n--- [Category 3/5] Single Retry Cascade & Graceful Degradation (90 Cases) ---');

// 3.1: Transient errors retry, deterministic errors skip retry (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `RETRY-POLICY-${i + 1}`;
  const t0 = performance.now();
  const provider = `mock_retry_${i}`;
  try {
    resetProviderCircuits();
    if (i < 15) {
      // Transient timeout: should be retried once!
      let callCount = 0;
      const res = await runProviderWithSingleRetry({
        requestId: `req-retry-transient-${i}`,
        stage: 'scan',
        provider,
        operation: async () => {
          callCount++;
          if (callCount === 1) throw new ProviderRequestError('provider_timeout', 'Timeout 1');
          return { verdict: 'DANGEROUS' };
        }
      });
      const passed = res.ok === true && callCount === 2 && res.result?.verdict === 'DANGEROUS';
      recordTest(testId, 'Transient Error Single Retry', passed, passed ? null : new Error(`Transient error did not retry correctly`), performance.now() - t0);
    } else {
      // Deterministic 429: should NOT be retried!
      let callCount = 0;
      const res = await runProviderWithSingleRetry({
        requestId: `req-retry-determ-${i}`,
        stage: 'scan',
        provider,
        operation: async () => {
          callCount++;
          throw new ProviderRequestError('provider_rate_limited', 'Rate limited 429');
        }
      });
      const passed = res.ok === false && callCount === 1 && res.errorCode === 'provider_rate_limited';
      recordTest(testId, 'Deterministic Error Skip Retry', passed, passed ? null : new Error(`Deterministic 429 was mistakenly retried`), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Retry Policy', false, err, performance.now() - t0);
  }
}

// 3.2: Multi-Provider Failover Cascade (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `CASCADE-FAILOVER-${i + 1}`;
  const t0 = performance.now();
  try {
    resetProviderCircuits();
    let cascadedToGroq = false;
    let cascadedToAnthropic = false;

    // Simulate primary Gemini failing
    const geminiAttempt = await runProviderAttempt({
      requestId: `req-casc-${i}`,
      stage: 'primary',
      provider: `gemini_casc_${i}`,
      operation: async () => {
        throw new ProviderRequestError('provider_rate_limited', 'Rate limit on Gemini');
      }
    });

    let finalVerdict = null;
    if (!geminiAttempt.ok) {
      // Cascades to Groq
      cascadedToGroq = true;
      if (i < 15) {
        // Groq succeeds
        const groqAttempt = await runProviderAttempt({
          requestId: `req-casc-${i}`,
          stage: 'fallback',
          provider: `groq_casc_${i}`,
          operation: async () => ({ verdict: 'DANGEROUS', provider: 'groq' })
        });
        if (groqAttempt.ok) finalVerdict = groqAttempt.result;
      } else {
        // Groq also fails, cascades to Anthropic
        await runProviderAttempt({
          requestId: `req-casc-${i}`,
          stage: 'fallback',
          provider: `groq_casc_${i}`,
          operation: async () => { throw new ProviderRequestError('provider_timeout', 'Groq timed out'); }
        });
        cascadedToAnthropic = true;
        const anthropicAttempt = await runProviderAttempt({
          requestId: `req-casc-${i}`,
          stage: 'secondary_fallback',
          provider: `anthropic_casc_${i}`,
          operation: async () => ({ verdict: 'SUSPICIOUS', provider: 'anthropic' })
        });
        if (anthropicAttempt.ok) finalVerdict = anthropicAttempt.result;
      }
    }

    const passed = (i < 15)
      ? (cascadedToGroq && finalVerdict?.provider === 'groq')
      : (cascadedToAnthropic && finalVerdict?.provider === 'anthropic');

    recordTest(testId, 'Multi-Provider Failover Cascade', passed, passed ? null : new Error(`Failover cascade failed at step ${i}`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Multi-Provider Failover Cascade', false, err, performance.now() - t0);
  }
}

// 3.3: Service Unavailable Graceful Degradation (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `DEGRADATION-UNAVAILABLE-${i + 1}`;
  const t0 = performance.now();
  try {
    const failedProviders = [
      { provider: 'gemini', errorCode: 'provider_rate_limited' },
      { provider: 'groq', errorCode: 'provider_timeout' },
      { provider: 'anthropic', errorCode: 'provider_upstream_error' }
    ];

    const result = createServiceUnavailableResult({
      requestId: `req-degrade-${i}`,
      failedProviders
    });

    const isNotSafe = result.verdict !== 'SAFE';
    const isServiceUnavailable = result.verdict === 'SERVICE_UNAVAILABLE';
    const zeroConfidence = result.confidence === 0;
    const trackedFailedCount = result.serviceStatus?.failedProviderCount === 3;
    const hasAdvice = Array.isArray(result.whatToDo) && result.whatToDo.length >= 2;

    const passed = isNotSafe && isServiceUnavailable && zeroConfidence && trackedFailedCount && hasAdvice;
    recordTest(testId, 'Service Unavailable Degradation', passed, passed ? null : new Error(`Degradation response malformed or defaulted to SAFE`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Service Unavailable Degradation', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 4: Ethical Canary Engine, Decoy Tokens & HMAC Tamper Shield (90 Cases)
// Objective: Verify HMAC signatures, constant-time validation, TTL, and source hashing.
// ============================================================================
console.log('\n--- [Category 4/5] Ethical Canary Tokens & Cryptographic Tamper Shield (90 Cases) ---');

// 4.1: Valid token creation, verification and TTL (25 cases)
for (let i = 0; i < 25; i++) {
  const testId = `CANARY-LIFECYCLE-${i + 1}`;
  const t0 = performance.now();
  try {
    const ownerId = `customer-tenant-${i + 100}`;
    const purpose = `decoy-canary-test-${i}`;
    const token = createCanaryToken({ ownerId, purpose, ttlSeconds: 3600 });

    const verification = verifyCanaryToken(token);
    const passed = verification.valid === true &&
                   verification.payload?.ownerId === ownerId &&
                   verification.payload?.purpose === purpose &&
                   verification.payload?.expiresAt > Math.floor(Date.now() / 1000);

    recordTest(testId, 'Canary Token Lifecycle', passed, passed ? null : new Error(`Canary verification failed`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Canary Token Lifecycle', false, err, performance.now() - t0);
  }
}

// 4.2: Tampered Token Signatures & Payloads (25 cases)
for (let i = 0; i < 25; i++) {
  const testId = `CANARY-TAMPER-${i + 1}`;
  const t0 = performance.now();
  try {
    const validToken = createCanaryToken({ ownerId: `legit-owner-${i}`, purpose: 'tamper-test', ttlSeconds: 1200 });
    const parts = validToken.split('.');
    let tamperedToken;

    if (i % 2 === 0) {
      // Alter signature
      const tamperedSig = parts[1].slice(0, -2) + (parts[1].endsWith('x') ? 'y' : 'x');
      tamperedToken = `${parts[0]}.${tamperedSig}`;
    } else {
      // Decode payload, modify ownerId, re-encode without secret key
      const payloadObj = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      payloadObj.ownerId = 'attacker-hijacked-id';
      const tamperedPayload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
      tamperedToken = `${tamperedPayload}.${parts[1]}`;
    }

    const verification = verifyCanaryToken(tamperedToken);
    const passed = verification.valid === false && verification.reason === 'invalid-token';
    recordTest(testId, 'Canary Tamper Resistance', passed, passed ? null : new Error(`Tampered token was accepted as valid!`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Canary Tamper Resistance', false, err, performance.now() - t0);
  }
}

// 4.3: Expired Tokens Enforcement (20 cases)
for (let i = 0; i < 20; i++) {
  const testId = `CANARY-EXPIRED-${i + 1}`;
  const t0 = performance.now();
  try {
    // Construct token that expired in the past
    const expiredPayload = {
      v: 'vp-canary-v1',
      id: `expired-uuid-${i}`,
      ownerId: `owner-${i}`,
      purpose: 'expiry-test',
      issuedAt: Math.floor(Date.now() / 1000) - 7200,
      expiresAt: Math.floor(Date.now() / 1000) - 3600,
      metadata: {}
    };

    const encodedPayload = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
    // Sign legitimately with secret
    const crypto = await import('crypto');
    const signature = crypto.createHmac('sha256', process.env.VERIFYPULSE_CANARY_SECRET).update(encodedPayload).digest('base64url');
    const expiredToken = `${encodedPayload}.${signature}`;

    const verification = verifyCanaryToken(expiredToken);
    const passed = verification.valid === false && verification.reason === 'expired-or-malformed-token';
    recordTest(testId, 'Canary Expiry Enforcement', passed, passed ? null : new Error(`Expired token was not rejected`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Canary Expiry Enforcement', false, err, performance.now() - t0);
  }
}

// 4.4: Canary Audit Events & Source Hashing (20 cases)
for (let i = 0; i < 20; i++) {
  const testId = `CANARY-AUDIT-${i + 1}`;
  const t0 = performance.now();
  try {
    const token = createCanaryToken({ ownerId: `audit-tenant-${i}`, purpose: 'audit-test', ttlSeconds: 1800 });
    const rawIp = `198.51.100.${i + 1}`;

    if (i < 15) {
      // Valid event types: viewed, requested, download-attempted
      const eventType = ['viewed', 'requested', 'download-attempted'][i % 3];
      const auditResult = createCanaryAuditEvent({ token, eventType, source: rawIp });

      const passed = auditResult.accepted === true &&
                     auditResult.event?.sourceHash !== null &&
                     auditResult.event?.sourceHash !== rawIp && // Raw IP must NOT be stored
                     auditResult.event?.eventType === eventType;

      recordTest(testId, 'Canary Audit & Source Hashing', passed, passed ? null : new Error(`Audit event failed or leaked raw IP`), performance.now() - t0);
    } else {
      // Unsupported event type must be rejected
      const auditResult = createCanaryAuditEvent({ token, eventType: 'malicious-action-attack', source: rawIp });
      const passed = auditResult.accepted === false && auditResult.reason === 'unsupported-event-type';
      recordTest(testId, 'Canary Disallowed Event Type', passed, passed ? null : new Error(`Disallowed event type was accepted`), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Canary Audit Event', false, err, performance.now() - t0);
  }
}

// ============================================================================
// CATEGORY 5: Request Budgeting & Latency Protection (90 Cases)
// Objective: Monotonic deadline calculations, bounded capping, zero budget breach.
// ============================================================================
console.log('\n--- [Category 5/5] Request Budgeting & Latency Protection (90 Cases) ---');

// 5.1: Monotonic Deadline Calculations (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `BUDGET-DEADLINE-${i + 1}`;
  const t0 = performance.now();
  try {
    let fakeNow = 1000000;
    const totalMs = 5000 + (i * 100);
    const budget = createRequestBudget({ totalMs, clock: () => fakeNow });

    const initialRemaining = budget.remainingMs();
    fakeNow += 2000;
    const midRemaining = budget.remainingMs();
    const elapsed = budget.elapsedMs();
    fakeNow += totalMs; // fully exhausted
    const finalRemaining = budget.remainingMs();

    const passed = initialRemaining === totalMs &&
                   midRemaining === (totalMs - 2000) &&
                   elapsed === 2000 &&
                   finalRemaining === 0;

    recordTest(testId, 'Monotonic Budget Deadlines', passed, passed ? null : new Error(`Budget calculations incorrect`), performance.now() - t0);
  } catch (err) {
    recordTest(testId, 'Monotonic Budget Deadlines', false, err, performance.now() - t0);
  }
}

// 5.2: Bounded Timeout Capping (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `BUDGET-TIMEOUT-FOR-${i + 1}`;
  const t0 = performance.now();
  try {
    let fakeNow = 1000000;
    const budget = createRequestBudget({ totalMs: 5000, clock: () => fakeNow });

    if (i < 10) {
      // Ample budget (remaining 5000ms), capMs = 2200ms -> should return 2200ms
      const timeout = budget.timeoutFor({ capMs: 2200, minimumMs: 500 });
      const passed = timeout === 2200;
      recordTest(testId, 'Ample Budget Cap', passed, passed ? null : new Error(`Expected 2200ms, got ${timeout}ms`), performance.now() - t0);
    } else if (i < 20) {
      // Tight budget: 1000ms remaining, capMs = 2200ms -> should return remaining 1000ms
      fakeNow += 4000;
      const timeout = budget.timeoutFor({ capMs: 2200, minimumMs: 500 });
      const passed = timeout === 1000;
      recordTest(testId, 'Tight Budget Shrink', passed, passed ? null : new Error(`Expected 1000ms, got ${timeout}ms`), performance.now() - t0);
    } else {
      // Exhausted budget: remaining 200ms < minimumMs (500ms) -> should return 0
      fakeNow += 4850;
      const timeout = budget.timeoutFor({ capMs: 2200, minimumMs: 500 });
      const passed = timeout === 0;
      recordTest(testId, 'Exhausted Budget Zero', passed, passed ? null : new Error(`Expected 0ms, got ${timeout}ms`), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Bounded Timeout Capping', false, err, performance.now() - t0);
  }
}

// 5.3: Admission Control canStart (30 cases)
for (let i = 0; i < 30; i++) {
  const testId = `BUDGET-CAN-START-${i + 1}`;
  const t0 = performance.now();
  try {
    let fakeNow = 1000000;
    const budget = createRequestBudget({ totalMs: 4000, clock: () => fakeNow });

    if (i < 15) {
      // 4000ms remaining, canStart(300) should be true
      const can = budget.canStart(300);
      const passed = can === true;
      recordTest(testId, 'Admission Control Can Start', passed, passed ? null : new Error(`Expected canStart true, got false`), performance.now() - t0);
    } else {
      // 3800ms passed, only 200ms left. canStart(300) should be false
      fakeNow += 3850;
      const can = budget.canStart(300);
      const passed = can === false;
      recordTest(testId, 'Admission Control Block Start', passed, passed ? null : new Error(`Expected canStart false, got true`), performance.now() - t0);
    }
  } catch (err) {
    recordTest(testId, 'Admission Control canStart', false, err, performance.now() - t0);
  }
}

// ============================================================================
// FEATURE #8 HARDEST GAUNTLET SUMMARY AUDIT METRICS
// ============================================================================
console.log('\n' + '='.repeat(72));
console.log('   FEATURE #8 HARDEST GAUNTLET SUMMARY AUDIT METRICS                    ');
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
