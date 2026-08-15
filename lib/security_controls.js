import crypto from 'crypto';

// Best-effort in-memory limiter for a single serverless instance. It provides
// immediate abuse protection but must be replaced or supplemented by a shared
// store (for example, Redis/KV) when the deployment scales across instances.
const rateLimitStore = globalThis.__verifyPulseRateLimitStore || new Map();
globalThis.__verifyPulseRateLimitStore = rateLimitStore;

const B2B_SCAN_SCOPE = 'b2b:scan';

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

function safeIdentifier(value, maximum = 96) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return /^[A-Za-z0-9._:-]{1,96}$/.test(normalized) ? normalized.slice(0, maximum) : null;
}

function normalizeScopes(value) {
  const values = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : [];
  const scopes = [...new Set(values.map((item) => String(item).trim()).filter((item) => /^[a-z0-9:*._-]{1,80}$/i.test(item)))];
  return scopes;
}

function configuredKeyRegistry() {
  const raw = String(process.env.VERIFYPULSE_B2B_KEY_REGISTRY || '').trim();
  if (!raw) return { configured: false, valid: true, entries: [] };
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 500) return { configured: true, valid: false, entries: [] };
    const entries = [];
    const ids = new Set();
    for (const item of parsed) {
      const keyId = safeIdentifier(item?.keyId);
      const tenantId = safeIdentifier(item?.tenantId);
      const keyHash = typeof item?.sha256 === 'string' ? item.sha256.toLowerCase() : '';
      const scopes = normalizeScopes(item?.scopes);
      const expiresAt = Date.parse(String(item?.expiresAt || ''));
      if (!keyId || !tenantId || !/^[a-f0-9]{64}$/.test(keyHash) || scopes.length === 0 || !Number.isFinite(expiresAt) || ids.has(keyId)) {
        return { configured: true, valid: false, entries: [] };
      }
      ids.add(keyId);
      entries.push({
        keyId,
        tenantId,
        sha256: keyHash,
        scopes,
        expiresAt,
        status: item?.status === 'revoked' ? 'revoked' : 'active'
      });
    }
    return { configured: true, valid: true, entries };
  } catch {
    return { configured: true, valid: false, entries: [] };
  }
}

function suppliedApiKey(req) {
  const headerValue = req.headers?.['x-api-key'] || req.headers?.authorization?.replace(/^Bearer\s+/i, '');
  return typeof headerValue === 'string' && headerValue ? headerValue : null;
}

function authFailure(status, code, message) {
  return { allowed: false, status, code, message };
}

export function validateB2bApiKey(req) {
  const supplied = suppliedApiKey(req);
  const registry = configuredKeyRegistry();

  if (registry.configured) {
    if (!registry.valid) {
      return authFailure(503, 'B2B_AUTH_INVALID_CONFIGURATION', 'B2B API authentication is not configured correctly.');
    }
    const requestedKeyId = safeIdentifier(req.headers?.['x-verifypulse-key-id']);
    if (!supplied || !requestedKeyId) {
      return authFailure(401, 'B2B_API_KEY_REQUIRED', 'A valid B2B API key is required.');
    }
    const record = registry.entries.find((entry) => entry.keyId === requestedKeyId);
    const suppliedDigest = keyDigest(supplied);
    const isMatch = Boolean(record && timingSafeHashMatch(suppliedDigest, record.sha256));
    if (!isMatch || record.status !== 'active' || record.expiresAt <= Date.now()) {
      return authFailure(401, 'B2B_API_KEY_INVALID', 'A valid B2B API key is required.');
    }
    return {
      allowed: true,
      identity: {
        scheme: 'scoped-registry',
        keyId: record.keyId,
        tenantId: record.tenantId,
        scopes: record.scopes,
        expiresAt: new Date(record.expiresAt).toISOString()
      }
    };
  }

  const configuredDigests = configuredKeyDigests();
  if (configuredDigests.length === 0) {
    return authFailure(503, 'B2B_AUTH_NOT_CONFIGURED', 'B2B API authentication is not configured.');
  }
  if (!supplied) {
    return authFailure(401, 'B2B_API_KEY_REQUIRED', 'A valid B2B API key is required.');
  }

  const suppliedDigest = keyDigest(supplied);
  const matched = configuredDigests.some((expectedDigest) => timingSafeHashMatch(suppliedDigest, expectedDigest));
  if (!matched) {
    return authFailure(401, 'B2B_API_KEY_INVALID', 'A valid B2B API key is required.');
  }

  return {
    allowed: true,
    identity: {
      scheme: 'legacy-hash-list',
      keyId: 'legacy',
      tenantId: 'legacy',
      scopes: [B2B_SCAN_SCOPE],
      expiresAt: null
    }
  };
}

export function authorizeB2bScope(authentication, requiredScope = B2B_SCAN_SCOPE) {
  if (!authentication?.allowed) return false;
  const scopes = authentication.identity?.scopes || [];
  return scopes.includes('*') || scopes.includes(requiredScope);
}

export function getConfiguredLimit(environmentVariable, fallback) {
  return getPositiveInteger(process.env[environmentVariable], fallback, 10_000);
}
