import crypto from 'crypto';

// Best-effort in-memory limiter for a single serverless instance. It provides
// immediate abuse protection but must be replaced or supplemented by a shared
// store (for example, Redis/KV) when the deployment scales across instances.
const rateLimitStore = globalThis.__verifyPulseRateLimitStore || new Map();
globalThis.__verifyPulseRateLimitStore = rateLimitStore;

function getPositiveInteger(value, fallback, maximum) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, maximum);
}

export function getClientIp(req) {
  const vercelForwardedFor = req.headers?.['x-vercel-forwarded-for'];
  const forwardedFor = req.headers?.['x-forwarded-for'];
  const raw = vercelForwardedFor || forwardedFor || req.socket?.remoteAddress || 'unknown';
  return String(Array.isArray(raw) ? raw[0] : raw).split(',')[0].trim().slice(0, 128) || 'unknown';
}

export function enforceRateLimit(req, {
  scope,
  limit = 20,
  windowMs = 60_000,
} = {}) {
  if (!scope) throw new Error('A rate-limit scope is required.');

  const now = Date.now();
  const key = `${scope}:${getClientIp(req)}`;
  const current = rateLimitStore.get(key);
  const activeWindow = current && now < current.resetAt
    ? current
    : { count: 0, resetAt: now + windowMs };

  activeWindow.count += 1;
  rateLimitStore.set(key, activeWindow);

  // Opportunistic cleanup keeps the memory footprint bounded without an extra job.
  if (rateLimitStore.size > 2_000) {
    for (const [entryKey, entry] of rateLimitStore.entries()) {
      if (entry.resetAt <= now) rateLimitStore.delete(entryKey);
    }
  }

  const retryAfterSeconds = Math.max(1, Math.ceil((activeWindow.resetAt - now) / 1000));
  return {
    allowed: activeWindow.count <= limit,
    remaining: Math.max(0, limit - activeWindow.count),
    limit,
    retryAfterSeconds,
    resetAt: activeWindow.resetAt,
  };
}

export function setRateLimitHeaders(res, result) {
  res.setHeader('RateLimit-Limit', String(result.limit));
  res.setHeader('RateLimit-Remaining', String(result.remaining));
  res.setHeader('RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));
  if (!result.allowed) res.setHeader('Retry-After', String(result.retryAfterSeconds));
}

function keyDigest(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function timingSafeHashMatch(candidate, expected) {
  const candidateBuffer = Buffer.from(candidate, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  return candidateBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(candidateBuffer, expectedBuffer);
}

function configuredKeyDigests() {
  return String(process.env.VERIFYPULSE_B2B_API_KEY_HASHES || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter((value) => /^[a-f0-9]{64}$/.test(value));
}

export function validateB2bApiKey(req) {
  const configuredDigests = configuredKeyDigests();
  if (configuredDigests.length === 0) {
    return {
      allowed: false,
      status: 503,
      code: 'B2B_AUTH_NOT_CONFIGURED',
      message: 'B2B API authentication is not configured.',
    };
  }

  const supplied = req.headers?.['x-api-key'] || req.headers?.authorization?.replace(/^Bearer\s+/i, '');
  if (!supplied || Array.isArray(supplied)) {
    return {
      allowed: false,
      status: 401,
      code: 'B2B_API_KEY_REQUIRED',
      message: 'A valid B2B API key is required.',
    };
  }

  const suppliedDigest = keyDigest(String(supplied));
  const matched = configuredDigests.some((expectedDigest) => timingSafeHashMatch(suppliedDigest, expectedDigest));
  if (!matched) {
    return {
      allowed: false,
      status: 401,
      code: 'B2B_API_KEY_INVALID',
      message: 'A valid B2B API key is required.',
    };
  }

  return { allowed: true };
}

export function getConfiguredLimit(environmentVariable, fallback) {
  return getPositiveInteger(process.env[environmentVariable], fallback, 10_000);
}
