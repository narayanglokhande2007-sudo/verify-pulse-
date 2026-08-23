const DEFAULT_PROVIDER_TIMEOUT_MS = 4500;
const providerCircuits = new Map();

function circuitPolicy(errorCode) {
  // A rate limit or credential failure is deterministic enough to protect the
  // provider immediately. Transient failures require two consecutive attempts
  // before a short circuit opens; one timeout must not remove every fallback
  // for subsequent users on the same serverless instance.
  if (errorCode === 'provider_rate_limited') return { failureThreshold: 1, backoffMs: 60_000 };
  if (errorCode === 'provider_auth_or_configuration_error') return { failureThreshold: 1, backoffMs: 5 * 60_000 };
  if (errorCode === 'provider_http_error') return { failureThreshold: 2, backoffMs: 15_000 };
  if (['provider_timeout', 'provider_network_error', 'provider_upstream_error'].includes(errorCode)) {
    return { failureThreshold: 2, backoffMs: 5_000 };
  }
  return { failureThreshold: Number.POSITIVE_INFINITY, backoffMs: 0 };
}

export function resetProviderCircuits() {
  providerCircuits.clear();
}

export class ProviderRequestError extends Error {
  constructor(code, message, { provider = 'unknown', status = null, cause = null } = {}) {
    super(message);
    this.name = 'ProviderRequestError';
    this.code = code;
    this.provider = provider;
    this.status = status;
    this.cause = cause;
  }
}

export function logScanReliabilityEvent({ requestId, stage, provider = null, outcome, errorCode = null, durationMs = null, providerStatus = null }) {
  // Deliberately excludes scan text, URLs, headers, secrets, and user identifiers.
  console.info(JSON.stringify({
    event: 'verifypulse.scan_reliability',
    requestId,
    stage,
    provider,
    outcome,
    errorCode,
    durationMs,
    providerStatus,
  }));
}

export function classifyProviderFailure(error) {
  if (error instanceof ProviderRequestError) return error.code;
  if (error?.name === 'AbortError') return 'provider_timeout';
  const message = String(error?.message || '').toLowerCase();
  if (message.includes('timeout') || message.includes('timed out')) return 'provider_timeout';
  if (message.includes('invalid json') || message.includes('empty') || message.includes('parse')) return 'invalid_provider_response';
  return 'provider_network_error';
}

export async function fetchJsonWithTimeout(url, options, { provider, timeoutMs = DEFAULT_PROVIDER_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    if (!response.ok) {
      let code = 'provider_http_error';
      if (response.status === 401 || response.status === 403) code = 'provider_auth_or_configuration_error';
      else if (response.status === 429) code = 'provider_rate_limited';
      else if (response.status >= 500) code = 'provider_upstream_error';
      throw new ProviderRequestError(code, `${provider} returned HTTP ${response.status}`, { provider, status: response.status });
    }
    try {
      return await response.json();
    } catch (error) {
      throw new ProviderRequestError('invalid_provider_response', `${provider} returned invalid JSON`, { provider, cause: error });
    }
  } catch (error) {
    if (error instanceof ProviderRequestError) throw error;
    if (error?.name === 'AbortError') {
      throw new ProviderRequestError('provider_timeout', `${provider} timed out`, { provider, cause: error });
    }
    throw new ProviderRequestError(classifyProviderFailure(error), `${provider} request failed`, { provider, cause: error });
  } finally {
    clearTimeout(timer);
  }
}

export async function runProviderAttempt({ requestId, stage, provider, operation }) {
  const startedAt = Date.now();
  const circuit = providerCircuits.get(provider);
  if (circuit?.openUntil && circuit.openUntil > startedAt) {
    logScanReliabilityEvent({
      requestId,
      stage,
      provider,
      outcome: 'skipped_circuit_open',
      errorCode: 'provider_circuit_open',
      durationMs: 0,
      providerStatus: circuit.providerStatus ?? null,
    });
    return { ok: false, errorCode: 'provider_circuit_open', providerStatus: circuit.providerStatus ?? null };
  }
  try {
    const result = await operation();
    providerCircuits.delete(provider);
    logScanReliabilityEvent({
      requestId,
      stage,
      provider,
      outcome: 'success',
      durationMs: Date.now() - startedAt,
    });
    return { ok: true, result };
  } catch (error) {
    const errorCode = classifyProviderFailure(error);
    const providerStatus = Number.isInteger(error?.status) ? error.status : null;
    const policy = circuitPolicy(errorCode);
    const previousFailures = circuit?.errorCode === errorCode ? Number(circuit.consecutiveFailures || 0) : 0;
    const consecutiveFailures = previousFailures + 1;
    const shouldOpenCircuit = policy.backoffMs > 0 && consecutiveFailures >= policy.failureThreshold;
    if (policy.backoffMs > 0) {
      providerCircuits.set(provider, {
        openUntil: shouldOpenCircuit ? Date.now() + policy.backoffMs : 0,
        errorCode,
        consecutiveFailures,
        providerStatus,
      });
    }
    logScanReliabilityEvent({
      requestId,
      stage,
      provider,
      outcome: 'failure',
      errorCode,
      durationMs: Date.now() - startedAt,
      providerStatus,
    });
    return { ok: false, errorCode, providerStatus };
  }
}

export async function runProviderWithSingleRetry({ requestId, stage, provider, operation }) {
  const firstAttempt = await runProviderAttempt({ requestId, stage, provider, operation });
  if (firstAttempt.ok || !['provider_timeout', 'provider_network_error', 'provider_upstream_error'].includes(firstAttempt.errorCode)) {
    return firstAttempt;
  }
  // Short bounded pause protects against a transient connection reset without retrying 401/403/429 failures.
  await new Promise((resolve) => setTimeout(resolve, 125));
  return runProviderAttempt({ requestId, stage: `${stage}_retry`, provider, operation });
}

export function createServiceUnavailableResult({ requestId, failedProviders }) {
  return {
    verdict: 'SERVICE_UNAVAILABLE',
    scamType: 'Analysis Service Temporarily Unavailable',
    confidence: 0,
    analysis: 'VerifyPulse could not complete external AI analysis at this time. This is not a SAFE result and does not mean the content is legitimate.',
    findings: ['No external model returned a usable verdict within the protected request window.'],
    whatToDo: [
      'Do not share money, OTPs, passwords, PINs, or personal documents based on this content.',
      'Verify the claim using an official website or helpline you find independently.',
      'Retry later if you still need an automated risk assessment.'
    ],
    evidenceSources: ['Service health monitor'],
    requestId,
    serviceStatus: {
      state: 'temporarily_unavailable',
      failedProviderCount: failedProviders.length,
      failureCodes: [...new Set(failedProviders.map((entry) => entry.errorCode))]
    }
  };
}
